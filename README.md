# 🦠 VirusTotal Hikka Bot

![Author](https://img.shields.io/badge/Author-%40lceta-blue?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.9-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Hikka%20Userbot-purple?style=for-the-badge)

## 📥 Installation

```text
.dlm https://raw.githubusercontent.com/lcetaa/VirusTotal-hikka-bot/refs/heads/main/VirusTotal.py
```

## 💻 Commands

| Command | Description |
| :--- | :--- |
| `.vt <file/url/ip/domain/hash>` | Scan a file (reply), URL, domain (IDN/Unicode supported), SHA-256/MD5/SHA-1, or IP — auto-detected |
| `.vthistory [page/query]` | Paginated scan history with search support |
| `.vtclear` | Clear all scan history |
| `.vtkey` | Show API key status, quota usage, and daily request count |
| `.vtupdate` | Update the module to the latest version |

## ⚙️ Config

| Option | Default |
| :--- | :--- |
| `api_keys` — API key(s), comma-separated *(required)* | — |
| `max_wait_time` — max polling time, sec (60–600) | `300` |
| `poll_interval` — check interval, sec (5–10) | `10` |
| `save_history` — save scan history | `True` |
| `max_history_items` — max history entries (1–10) | `10` |
| `cleanup_interval` — cleanup interval, sec (300–86400) | `3600` |

## 📊 Results

🔴 Malicious · 🟡 Suspicious · 🟢 Harmless · ⚪ Undetected

🟩 0–2 Low · 🟨 3–5 Medium · 🟧 6–10 High · 🟥 10+ Critical

Every scan result also includes a **community comments** panel — read existing comments, post your own review, or delete it later, right from the chat.

## 🔑 API Key

Register at [virustotal.com](https://www.virustotal.com) → Profile → API Key → paste into `.config VirusTotal api_keys`

You can add multiple keys, comma-separated, to increase your combined daily quota. The module automatically rotates between keys and skips ones that hit their rate limit.

## 📞 Support

[@lceta](https://t.me/lceta)
