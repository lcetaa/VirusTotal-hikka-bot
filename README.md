# VirusTotal Hikka Bot
Author: @monkvy  
Version: 2.0.1

## 📥 Installation
```
.dlm https://raw.githubusercontent.com/monkvy/VirusTotal-hikka-bot/refs/heads/main/VirusTotal.py
```
### 🌐 Полезные ссылки
Если вам нужен сам юзербот Hikka для хостинга Heroku, вы можете найти проект оригинального автора здесь:

[Исходный код Hikka для Heroku от coddrago](https://github.com/coddrago/Heroku)

## 💻 Commands
* .vt <file/url/ip> — Scan a file (via reply), URL, or IP address (with intelligent auto-detection).
* .vthash <hash> — Check existing analysis by file hash (supports SHA-256 / MD5).
* .vthistory — Show interactive, multi-page scan history with integrated search.
* .vtclear — Completely clear the scan history from the database.

## ⚙️ Config
* api_keys — VirusTotal API keys. Supports multiple keys separated by a comma for automatic key-rotation and bypassing limits (Required).
* max_wait_time — Maximum polling wait time for large files in seconds (Default: 300).
* poll_interval — Interval between analysis status checks in seconds (Default: 10).
* save_history — Enable or disable saving scan history to the database (Default: True).
* max_history_items — Maximum number of entries kept in history (Default: 10).
* cleanup_interval — Background cleanup interval for cache and old results in seconds (Default: 3600).

## 📊 Understanding Results
* 🚫 Malicious — Dangerous / Threat detected
* ⚠️ Suspicious — Potentially unsafe / Suspicious behavior
* ✅ Harmless — Clean / Safe
* 👁️ Undetected — No engines detected any threats

### Threat Assessment Scale:
* 0–2 detections — Low Risk
* 3–5 detections — Medium Risk
* 6–10 detections — High Risk
* 10+ detections — Critical Risk

## 🔑 Getting an API Key
1. Register a free account at https://www.virustotal.com
2. Navigate to your profile settings and find the API Key section.
3. Copy your personal API key.
4. Open your userbot settings and paste the key into the api_keys field (you can add multiple keys using commas to avoid rate limits).

## 🔄 What’s New in Major Release v2.x
* 🧠 Smart History Lifecycle (v2.0.1): Implemented fully autonomous background history cleanup. The bot runs an automated check hourly and quietly purges records older than 30 days to keep the database performance optimal.
* 🛠️ UI Pagination Bugfix: Resolved a critical interface error (future_dispatcher) that was causing inline navigation buttons to crash or hang during history searches when exactly one match was found (1-1 of 1).
* 🧹 Clean Refactoring: Complete source code cleanup. Removed all deprecated debug logs and non-English code blocks, ensuring significantly faster compilation and minimal RAM consumption (5-15 MB).
* 🔄 Unified Search Command: Merged functionality into an intelligent single `.vt` command hub — the bot automatically recognizes and roots files, URLs, and IP addresses with zero auxiliary inputs required.
* 🌐 Advanced Net Scanning: IP address lookups now instantly display the target country code flag and its official AS owner database assignment data.
* 🔒 Auto-HTTPS: Integrated native network endpoint link-fixing — the bot automatically prefixes raw domains with 'https://' before submission.
* 🌍 Native Localization: Removed the redundant legacy configuration toggles for languages. The client UI now responds instantly to your primary Hikka bot language settings (RU/EN).

## 📞 Support & Feedback
For any questions, bug reports, or feature requests: 
Telegram: @monkvy
