# Monad Announcement Watcher

Automatically verify new [Monad Foundation announcements](https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements) with **local GnuPG**, then notify **Discord, Telegram, and/or a JSON webhook**.

**Want the website instead?** [Monad Announcement Verifier](https://github.com/natsaixyz/monad-announcement-verifier) · [Live verifier](https://monad-verify.natsai.xyz)

## Install (Docker)

Requirements: Docker and Docker Compose. No domain, inbound ports, validator access, or website required.

```bash
git clone https://github.com/natsaixyz/monad-announcement-watcher.git
cd monad-announcement-watcher
cp .env.example .env
nano .env                       # Set at least one destination; see below
chmod 600 .env
docker compose up -d --build
```

**Choose any combination** in `.env`; leave unused values empty:

| Destination | Settings |
| --- | --- |
| Discord | `DISCORD_WEBHOOK_URL` |
| Telegram | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` |
| Any HTTPS endpoint | `CUSTOM_WEBHOOK_URL`; optional `CUSTOM_WEBHOOK_SECRET` |

```bash
# One-time test without GPG checks or changing watcher history
docker compose run --rm watcher python watcher.py --test all

# Status and logs
docker compose ps
docker compose logs --tail=30 watcher
```

`--test all` tests **only configured** destinations. You can instead use `--test discord`, `--test telegram`, or `--test webhook`.

### Telegram setup (Telegram Web is fine)

1. In Telegram, talk to [@BotFather](https://t.me/BotFather), send `/newbot`, and copy your new **bot token** into `.env` as `TELEGRAM_BOT_TOKEN`. Never commit this token.
2. Open your bot's chat and send `/start` (for a group, add the bot and send a message addressing it). Find the chat ID:
   ```bash
   docker compose run --rm watcher python watcher.py --telegram-chat-id
   ```
3. Set `TELEGRAM_CHAT_ID` in `.env`, then run `docker compose up -d --build` and `docker compose run --rm watcher python watcher.py --test telegram`.

For a Telegram channel, add your bot as an administrator with posting permission; `@publicchannelusername` can be used as `TELEGRAM_CHAT_ID`.

### Custom webhook

Set `CUSTOM_WEBHOOK_URL=https://your-domain.example/monad-alerts`. The watcher POSTs a [documented JSON payload](WEBHOOK.md). Optionally set `CUSTOM_WEBHOOK_SECRET` (16+ characters) to add an `X-Monad-Signature: sha256=...` HMAC over the exact request body. No redirects are followed. Test with `--test webhook`.

## Operation

- Polls Monad's **public GitHub** announcements every 5 minutes (`CHECK_INTERVAL_SECONDS=300`). New or edited `mf-N` files are **verified locally** with two distinct, pinned authorized signer keys before reporting success.
- First start (`START_MODE=latest`) reports the latest valid announcement and silently records older valid ones. `START_MODE=silent` skips initial success notifications. **Failed verification is never silently accepted.**
- Stores delivered events in a persistent Docker volume; **each destination has independent retry/deduplication state**. New destinations do not receive historical alerts. A crash between delivery and state save may cause a duplicate; `event_id` lets custom webhook consumers deduplicate.
- Status is **VERIFIED** or **FAILED**. The watcher never executes announcement instructions. GitHub download errors are logged, not misreported as signature failures.
- Stops with `docker compose down` (keeps state). **Do not use `down -v`** unless you want to reset history.

Trusted Monad public-key fingerprints are pinned in [`config.json`](config.json), not blindly accepted from GitHub. Verify them independently against [Monad's official list](https://docs.monad.xyz/node-ops/gpg-keys.json) before relying on the watcher. Key rotation requires deliberate review and a config update.

**Scope:** public GitHub announcements only. Private email-only CODE RED communications are not monitored. This community-maintained project is **not an official Monad Foundation tool** and should complement, not replace, official operator channels.

## Tests

```bash
# Python 3.11+ and gpg required
gpg --version
python3 -m unittest discover -s tests -v
```

All tests run offline with local signed fixtures and mocked notification delivery. No third-party Python packages are required.

MIT · © 2026 Natsai OÜ
