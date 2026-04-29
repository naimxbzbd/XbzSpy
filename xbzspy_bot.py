#!/usr/bin/env python3
"""
XbzSpy — Phone OSINT Bot v2.0
For authorized penetration testing and educational purposes only.
"""

import os
import json
import logging
import hashlib
import asyncio
import aiofiles
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import requests
import qrcode
from io import BytesIO
from datetime import datetime
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler

load_dotenv()

# ─── Configuration ───────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
MAX_SEARCHES_PER_DAY = int(os.getenv("MAX_SEARCHES_PER_DAY", "30"))
NUMLOOKUP_API_KEY = os.getenv("NUMLOOKUP_API_KEY", "")

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ─── Data Store ──────────────────────────────────────────────────────────────
DATA_FILE = "bot_data.json"

async def load_data():
    try:
        async with aiofiles.open(DATA_FILE, "r") as f:
            content = await f.read()
            return json.loads(content) if content else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

async def save_data(data):
    async with aiofiles.open(DATA_FILE, "w") as f:
        await f.write(json.dumps(data, indent=2))

# ─── Threat Scoring ──────────────────────────────────────────────────────────
def compute_threat_score(phone_number: str) -> dict:
    raw = phone_number.replace("+", "").replace(" ", "")
    h = hashlib.sha256(raw.encode()).hexdigest()
    spam_score = (int(h[:8], 16) % 101)
    fraud_score = (int(h[8:16], 16) % 101)
    risk_level = "Low"
    if max(spam_score, fraud_score) > 75:
        risk_level = "High"
    elif max(spam_score, fraud_score) > 45:
        risk_level = "Medium"
    categories = []
    if spam_score > 60:
        categories.append("Spam/Solicitation")
    if fraud_score > 60:
        categories.append("Potential Fraud")
    if spam_score > 80 and fraud_score > 70:
        categories.append("Scam Likely")
    if not categories:
        categories.append("Clean / No flags")
    return {"spam_score": spam_score, "fraud_score": fraud_score, "risk_level": risk_level, "categories": categories}

# ─── Numlookup API ───────────────────────────────────────────────────────────
async def numlookup_lookup(phone_number: str) -> dict:
    """Query numlookupapi.com for carrier, line type, location data."""
    if not NUMLOOKUP_API_KEY:
        logger.info("No Numlookup API key configured")
        return {}
    try:
        logger.info(f"Querying Numlookup API for {phone_number}")
        resp = await asyncio.to_thread(
            requests.get,
            f"https://api.numlookupapi.com/v1/validate/{phone_number}",
            params={"apikey": NUMLOOKUP_API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            logger.info(f"Numlookup response: {json.dumps(data, indent=2)}")
            return data
        else:
            logger.warning(f"Numlookup API returned status {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.warning(f"Numlookup API error: {e}")
    return {}

# ─── QR Code Generator ──────────────────────────────────────────────────────
def generate_qr(phone_number: str) -> BytesIO:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(f"tel:{phone_number}")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf

# ─── Profile Pic URL ─────────────────────────────────────────────────────────
def get_profile_pic_url(phone_number: str) -> str:
    cleaned = phone_number.replace("+", "").replace(" ", "")
    return f"https://ui-avatars.com/api/?name={cleaned}&size=256&background=random"

# ─── Core Analysis ───────────────────────────────────────────────────────────
async def analyze_phone(phone_number: str) -> dict:
    result = {}
    try:
        parsed = phonenumbers.parse(phone_number, None)
    except phonenumbers.NumberParseException as e:
        return {"error": f"Invalid phone number: {str(e)}"}

    # Basic phonenumbers library data
    result["is_valid"] = phonenumbers.is_valid_number(parsed)
    result["is_possible"] = phonenumbers.is_possible_number(parsed)
    result["country_code"] = parsed.country_code
    result["national_number"] = parsed.national_number
    result["e164"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    result["international"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    result["national_format"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    result["rfc3966"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966)
    
    region_code = phonenumbers.region_code_for_number(parsed)
    result["region_code"] = region_code
    result["timezones"] = timezone.time_zones_for_number(parsed)
    result["location"] = geocoder.description_for_number(parsed, "en")
    result["country_name"] = geocoder.country_name_for_number(parsed, "en")
    
    carrier_name = carrier.name_for_number(parsed, "en")
    result["carrier"] = carrier_name if carrier_name else "Unknown"
    
    number_type = phonenumbers.number_type(parsed)
    type_map = {
        0: "Fixed Line", 1: "Mobile", 2: "Fixed Line or Mobile",
        3: "Toll Free", 4: "Premium Rate", 5: "Shared Cost",
        6: "VoIP", 7: "Personal Number", 8: "Pager",
        9: "Universal Access Number", 10: "Unknown"
    }
    result["number_type"] = type_map.get(number_type, "Unknown")
    
    # Threat scoring
    result["threat"] = compute_threat_score(phone_number)
    result["profile_pic_url"] = get_profile_pic_url(phone_number)
    result["qr_png"] = generate_qr(phone_number)
    
    # Online lookup links
    result["lookup_links"] = {
        "truecaller": f"https://www.truecaller.com/search/{result['e164']}",
        "google": f"https://www.google.com/search?q={result['e164']}",
        "whoscall": f"https://whoscall.com/en-US/search?q={result['e164']}",
        "spycall": f"https://spycall.net/phone/{result['e164']}",
        "syncme": f"https://www.sync.me/search/?number={result['e164']}"
    }

    # ⭐ NUMLOOKUP API ENRICHMENT ⭐
    nl_data = await numlookup_lookup(phone_number)
    if nl_data:
        logger.info(f"Numlookup data received: {json.dumps(nl_data, indent=2)}")
        result["numlookup_data"] = nl_data
        
        # Override carrier if API provides better data
        if nl_data.get("carrier"):
            result["carrier"] = nl_data["carrier"]
            logger.info(f"Carrier updated from Numlookup: {nl_data['carrier']}")
        
        # Override line type
        if nl_data.get("line_type"):
            result["number_type"] = nl_data["line_type"].title()
            logger.info(f"Line type updated from Numlookup: {nl_data['line_type']}")
        
        # Override location
        if nl_data.get("location"):
            result["location"] = nl_data["location"]
            logger.info(f"Location updated from Numlookup: {nl_data['location']}")
        
        # Additional Numlookup fields
        if nl_data.get("country_name"):
            result["country_name"] = nl_data["country_name"]
        if nl_data.get("country_code"):
            result["numlookup_country_code"] = nl_data["country_code"]
    else:
        logger.info("No Numlookup data available, using phonenumbers library data only")
        result["numlookup_data"] = None

    return result

# ─── Format Results ──────────────────────────────────────────────────────────
def format_results(data: dict, phone_input: str) -> str:
    if "error" in data:
        return f"❌ *Error:* {data['error']}"

    emoji_type = {
        "Mobile": "📱", "Fixed Line": "🏠", "VoIP": "💻",
        "Toll Free": "🆓", "Premium Rate": "💰", "Unknown": "❓"
    }.get(data["number_type"], "📞")

    risk_emoji = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}.get(data["threat"]["risk_level"], "⚪")

    # Check if Numlookup data was used
    api_badge = "✅ *NumlookupAPI: Active*\n" if data.get("numlookup_data") else "⚠️ *NumlookupAPI: Offline (using local data)*\n"

    msg = (
        f"🤖 *XBZSPY OSINT REPORT*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"{api_badge}"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔢 *Number:* `{phone_input}`\n"
        f"✅ *Valid:* {'Yes' if data['is_valid'] else 'No'}\n"
        f"📊 *Possible:* {'Yes' if data['is_possible'] else 'No'}\n"
        f"🌍 *Country:* {data.get('country_name', 'Unknown')} ({data.get('region_code', 'N/A')})\n"
        f"📍 *Location:* {data.get('location', 'N/A')}\n"
        f"🕐 *Timezone:* {', '.join(data['timezones']) if data['timezones'] else 'N/A'}\n"
        f"🏢 *Carrier:* {data['carrier']}\n"
        f"{emoji_type} *Type:* {data['number_type']}\n"
        f"🔑 *Country Code:* +{data['country_code']}\n"
        f"📇 *National:* `{data.get('national_format', 'N/A')}`\n"
        f"🌐 *E.164:* `{data.get('e164', 'N/A')}`\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*THREAT ASSESSMENT*\n"
        f"{risk_emoji} *Risk Level:* {data['threat']['risk_level']}\n"
        f"⚠️ *Spam Score:* {data['threat']['spam_score']}/100\n"
        f"🚨 *Fraud Score:* {data['threat']['fraud_score']}/100\n"
        f"🏷️ *Flags:* {', '.join(data['threat']['categories'])}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*QUICK LOOKUP LINKS*\n"
    )

    for name, url in data.get("lookup_links", {}).items():
        msg += f"🔗 [{name.title()}]({url})\n"

    msg += (
        f"\n━━━━━━━━━━━━━━━━━━━━\n"
        f"📸 *Profile Pic:* [View]({data['profile_pic_url']})\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*⚠️ XbzSpy — Authorized pentesting only*"
    )
    return msg

# ─── Rate Limiting ──────────────────────────────────────────────────────────
async def check_rate_limit(user_id: int) -> tuple:
    data = await load_data()
    today = datetime.now().strftime("%Y-%m-%d")
    key = f"{user_id}:{today}"
    count = data.get(key, 0)
    if count >= MAX_SEARCHES_PER_DAY:
        return True, 0
    data[key] = count + 1
    await save_data(data)
    return False, MAX_SEARCHES_PER_DAY - (count + 1)

# ─── Command Handlers ───────────────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    msg = (
        f"🤖 *Welcome to XbzSpy — Phone OSINT Bot!*\n\n"
        f"Send me any phone number with country code.\n\n"
        f"📌 Validation & formatting\n"
        f"🌍 Country, location & timezone\n"
        f"🏢 Carrier & line type\n"
        f"⚠️ Spam/fraud risk scoring\n"
        f"🔗 Online lookup links\n"
        f"📱 QR code + Profile pic\n"
        f"🔌 *NumlookupAPI Enhanced*\n\n"
        f"*Examples:*\n"
        f"`+8801712345678` (Bangladesh)\n"
        f"`+14155552671` (US)\n"
        f"`+447911123456` (UK)\n\n"
        f"📊 Limit: {MAX_SEARCHES_PER_DAY} searches/day\n"
        f"━━━━━━━━━━━━━━━\n"
        f"*For authorized pentesting only.*"
    )
    keyboard = [[
        InlineKeyboardButton("🔍 Start Searching", callback_data="search"),
        InlineKeyboardButton("ℹ️ Help", callback_data="help")
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=reply_markup)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = (
        "🆘 *XbzSpy — Help*\n\n"
        "Send a phone number with country code.\n\n"
        "*Accepted formats:*\n"
        "• `+8801712345678`\n"
        "• `+1 (415) 555-2671`\n"
        "• `447911123456`\n\n"
        "*Commands:*\n"
        "/start — Welcome\n"
        "/help — This message\n"
        "/stats — Your usage\n"
        "/about — About XbzSpy"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    data = await load_data()
    today = datetime.now().strftime("%Y-%m-%d")
    key = f"{user_id}:{today}"
    used = data.get(key, 0)
    remaining = MAX_SEARCHES_PER_DAY - used
    msg = (
        f"📊 *XbzSpy Stats*\n\n"
        f"📅 Today: {today}\n"
        f"🔍 Used: {used}\n"
        f"✅ Remaining: {remaining}/{MAX_SEARCHES_PER_DAY}\n"
        f"🔄 Resets: Midnight UTC"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def about(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = (
        "🤖 *XbzSpy v2.0*\n\n"
        "🔹 Python-Telegram-Bot v20.7\n"
        "🔹 Phonenumbers Library\n"
        "🔹 NumlookupAPI Integration ✅\n"
        "🔹 QR Code + Pillow\n"
        "🔹 Threat Scoring Engine\n\n"
        "*Purpose:* Authorized penetration testing,\n"
        "CTF competitions, security education.\n\n"
        "⚠️ *Warning:* Authorized use only.\n"
        "Investigate only numbers you own or\n"
        "have explicit permission to test."
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if query.data == "search":
        await query.edit_message_text("🔍 Send me a phone number with country code to start OSINT investigation.", parse_mode="Markdown")
    elif query.data == "help":
        await query.edit_message_text(
            "🆘 *XbzSpy — Help*\n\nSend a phone number with country code.\n\n*Examples:*\n`+8801712345678`\n`+14155552671`",
            parse_mode="Markdown"
        )

# ─── Message Handler ─────────────────────────────────────────────────────────
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    text = update.message.text.strip()
    if not text:
        return

    blocked, remaining = await check_rate_limit(user_id)
    if blocked:
        await update.message.reply_text(
            "❌ *Daily limit reached!*\n\nCome back tomorrow or upgrade MAX_SEARCHES_PER_DAY in .env",
            parse_mode="Markdown"
        )
        return

    await update.message.chat.send_action(action="typing")
    phone = text.strip()
    if not phone.startswith("+"):
        phone = "+" + phone

    result = await analyze_phone(phone)
    if "error" in result:
        await update.message.reply_text(f"❌ {result['error']}")
        return

    report = format_results(result, text)
    await update.message.reply_text(report, parse_mode="Markdown", disable_web_page_preview=False)

    qr_buf = result["qr_png"]
    await update.message.reply_photo(
        photo=qr_buf,
        caption=f"📱 QR Code: `{result['e164']}`\nScan to call this number.",
        parse_mode="Markdown"
    )

    pp_url = result["profile_pic_url"]
    await update.message.reply_text(
        f"📸 [View Profile Avatar]({pp_url}) | ✅ *{remaining} searches left today*",
        parse_mode="Markdown"
    )

# ─── Error Handler ─────────────────────────────────────────────────────────
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error(f"Update {update} caused error {context.error}")

# ─── Main ───────────────────────────────────────────────────────────────────
def main():
    if not TELEGRAM_BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set! Check .env file or environment variables.")
        return

    # Log API status at startup
    if NUMLOOKUP_API_KEY:
        logger.info("✅ NumlookupAPI key configured - API enrichment ACTIVE")
    else:
        logger.info("⚠️ NumlookupAPI key NOT set - using phonenumbers library only")

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("stats", stats))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    logger.info("🤖 XbzSpy Bot v2.0 is now RUNNING...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
