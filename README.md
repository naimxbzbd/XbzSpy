# 🤖 XbzSpy — Phone OSINT Bot

Telegram bot for phone number OSINT investigation. Built for authorized penetration testing and security education.

## Features

- ✅ Phone number validation & formatting
- 🌍 Country, location & timezone detection
- 🏢 Carrier & line type identification (NumlookupAPI enhanced)
- ⚠️ Spam/fraud threat scoring
- 🔗 Quick lookup links (TrueCaller, Google, etc.)
- 📱 QR code generation
- 📸 Profile avatar
- 📊 Daily rate limiting
- 🔌 NumlookupAPI Integration

## Deploy on Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | ✅ | From @BotFather |
| `MAX_SEARCHES_PER_DAY` | ❌ | Default: 30 |
| `NUMLOOKUP_API_KEY` | ❌ | From numlookupapi.com |

## Usage

Send any phone number with country code to the bot:

- `+8801712345678` (Bangladesh)
- `+14155552671` (US)
- `+447911123456` (UK)

## Commands

- `/start` — Welcome message
- `/help` — Usage instructions
- `/stats` — Your daily usage
- `/about` — Bot information

## License

For authorized security testing and educational purposes only.
