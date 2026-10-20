# Monad Announcement Watcher

Verify new [Monad Foundation announcements](https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements) with **local GnuPG**, then notify **Discord, Telegram, and/or a JSON webhook**. Headless; no inbound ports, website, or validator access.

Want to check announcements manually? **[Web verifier](https://github.com/natsaixyz/monad-announcement-verifier)** · [Live site](https://monad-verify.natsai.xyz).

## Install

Requires Docker and Docker Compose.

```bash
git clone https://github.com/natsaixyz/monad-announcement-watcher.git
cd monad-announcement-watcher
cp .env.example .env
nano .env  # configure at least one destination
chmod 600 .env
docker compose up -d --build
```

Set any combination in `.env`; leave unused destinations empty:

| Destination | Variables |
| --- | --- |
| Discord | `DISCORD_WEBHOOK_URL` |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| JSON webhook | `CUSTOM_WEBHOOK_URL`, optional `CUSTOM_WEBHOOK_SECRET` ([payload](WEBHOOK.md)) |

**Telegram:** Create a bot via [@BotFather](https://t.me/BotFather), message it `/start`, then find the chat ID with:

```bash
docker compose run --rm watcher python watcher.py --telegram-chat-id
```

Set `TELEGRAM_CHAT_ID` in `.env`. For channels, add the bot with posting permission.

## Test & operate

```bash
docker compose run --rm watcher python watcher.py --test all  # configured destinations only; no state changes
docker compose ps
docker compose logs --tail=30 watcher
```

Polls public GitHub every 5 minutes; checks **2 distinct authorized GPG signatures** using [`config.json`](config.json). Independently verify pinned keys against [Monad's official list](https://docs.monad.xyz/node-ops/gpg-keys.json). It alerts on new or changed announcements and verification failures, and retries destinations independently.

First run reports the latest announcement (`START_MODE=latest`). Delivery history persists in a Docker volume; **don't use `docker compose down -v`** unless resetting history is intentional.

**Verification:** GnuPG checks the original files against at least two distinct pinned authorized primary keys. Announcement text is not parsed. Dates, expiry, severity and the message/folder number match are **not checked**; operators must review the signed message before acting. Folder IDs are source locations, not authenticated announcement numbers.

**Scope:** Public GitHub only; restricted email-only CODE RED is not monitored. No commands are executed. Not an official Monad Foundation tool.

Tests (Python 3.11+ and GnuPG): `python3 -m unittest discover -s tests -q`.

MIT · © 2026 Natsai OÜ
