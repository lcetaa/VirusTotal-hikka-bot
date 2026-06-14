# 🦠 VirusTotal Hikka Bot

![Author](https://img.shields.io/badge/Автор-%40lceta-blue?style=for-the-badge)
![Version](https://img.shields.io/badge/Версия-2.0.7-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Платформа-Hikka%20Userbot-purple?style=for-the-badge)

## 📥 Установка

```text
.dlm https://raw.githubusercontent.com/lcetaa/VirusTotal-hikka-bot/refs/heads/main/VirusTotal.py
```

## 💻 Команды

| Команда | Описание |
| :--- | :--- |
| `.vt <файл/ссылка/ip/хеш>` | Сканировать файл (ответом), URL, SHA-256/MD5/SHA-1 или IP — определяется автоматически |
| `.vthistory [страница/запрос]` | История сканирований с пагинацией и поиском |
| `.vtclear` | Очистить историю |
| `.vtupdate` | Обновить модуль до последней версии |

## ⚙️ Настройки

| Параметр | По умолчанию |
| :--- | :--- |
| `api_keys` — API ключ(и) через запятую *(обязательно)* | — |
| `max_wait_time` — макс. время ожидания, сек (60–600) | `300` |
| `poll_interval` — интервал проверки, сек (5–10) | `10` |
| `save_history` — сохранять историю | `True` |
| `max_history_items` — макс. записей в истории (1–10) | `10` |
| `cleanup_interval` — интервал очистки, сек (300–86400) | `3600` |

## 📊 Результаты

🔴 Malicious · 🟡 Suspicious · 🟢 Harmless · ⚪ Undetected

🟩 0–2 Низкий · 🟨 3–5 Средний · 🟧 6–10 Высокий · 🟥 10+ Критический

## 🔑 API ключ

Регистрация на [virustotal.com](https://www.virustotal.com) → Профиль → API Key → вставить в `.config VirusTotal api_keys`

## 📞 Поддержка

[@lceta](https://t.me/lceta)
