# 🦠 VirusTotal Hikka Bot

![Author](https://img.shields.io/badge/Author-%40lceta-blue?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.5-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Hikka%20Userbot-purple?style=for-the-badge)

## 📥 Installation

```text
.dlm https://raw.githubusercontent.com/lcetaa/VirusTotal-hikka-bot/refs/heads/main/VirusTotal.py
```

## 💻 Commands

| Command | Description |
| :--- | :--- |
| `.vt <file/url/ip>` | Scan a file (reply), URL, domain, or IP — auto-detected |
| `.vthash <hash>` | Look up by SHA-256 / MD5. Also searches history by partial hash |
| `.vthistory [page/query]` | Paginated scan history with search support |
| `.vtclear` | Clear all scan history |
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

## 🔑 API Key

Register at [virustotal.com](https://www.virustotal.com) → Profile → API Key → paste into `.config VirusTotal api_keys`

## 📞 Support

[@lceta](https://t.me/lceta)
