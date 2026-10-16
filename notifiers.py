"""Notification adapters. No dependency on the web application."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Event:
    number: int
    status: str                   # VERIFIED or FAILED
    kind: str                     # NEW, CHANGED, RECOVERED, TEST
    severity: str = "UNCLASSIFIED"
    created: str = ""
    signers: tuple[str, ...] = ()
    reason: str = ""
    digest: str = ""                 # SHA-256 of the signed announcement pair


class DeliveryError(Exception):
    pass


def webhook_url_valid(url: str) -> bool:
    """Accept only standard Discord webhook endpoints (no arbitrary SSRF target)."""
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        return False
    return (
        p.scheme == "https" and p.hostname in {"discord.com", "discordapp.com"}
        and port in {None, 443} and p.username is None and p.password is None
        and not p.query and not p.fragment
        and re.fullmatch(r"/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", p.path) is not None
    )


class DiscordNotifier:
    def __init__(self, url: str):
        if not webhook_url_valid(url):
            raise ValueError("DISCORD_WEBHOOK_URL must be a standard HTTPS Discord webhook URL")
        self._url = url

    @staticmethod
    def payload(event: Event) -> dict:
        if event.status == "VERIFIED":
            color = {"GREEN": 0x2E865F, "ORANGE": 0xE29C39, "RED": 0xCC4444}.get(event.severity, 0x477CB5)
            label = f"GPG VERIFIED · CODE {event.severity}" if event.severity != "UNCLASSIFIED" else "GPG VERIFIED"
            desc = "Two or more authorized Monad Foundation signatures verified locally."
        elif event.status == "TEST":
            color = 0x477CB5
            label = "WATCHER TEST — NOT AN ANNOUNCEMENT"
            desc = "Discord delivery is working. No announcement was verified by this test."
        else:
            color = 0xD14949
            label = "GPG VERIFICATION FAILED"
            desc = "Do not act on this announcement until independently verified."
        fields = [{"name": "Event", "value": event.kind, "inline": True}]
        if event.created:
            fields.append({"name": "Created", "value": event.created[:128], "inline": True})
        if event.signers:
            fields.append({"name": "Authorized signers", "value": f"{len(event.signers)} distinct · " + ", ".join(x[:8] + "…" + x[-8:] for x in event.signers), "inline": False})
        if event.reason:
            fields.append({"name": "Reason", "value": event.reason[:350], "inline": False})
        title = f"MF Announcement #{event.number} · {label}" if event.status != "TEST" else label
        url = f"https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-{event.number}"
        embed = {"title": title, "description": desc, "color": color, "fields": fields, "footer": {"text": "Natsai · local GPG verification · no actions executed"}}
        if event.status != "TEST":
            embed["url"] = url
        return {"username": "Monad Announcement Watcher", "allowed_mentions": {"parse": []}, "embeds": [embed]}

    def send(self, event: Event) -> None:
        body = json.dumps(self.payload(event), separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self._url, data=body, headers={"Content-Type": "application/json", "User-Agent": "Natsai-Monad-Watcher/1.0"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                if response.status not in (200, 204):
                    raise DeliveryError(f"Discord webhook returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            # Do not log URL, exception repr, or response body: webhook token is secret.
            raise DeliveryError(f"Discord webhook returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise DeliveryError("Discord webhook delivery failed or timed out") from None


class TelegramNotifier:
    """Outbound Telegram Bot API adapter; no inbound webhook or bot polling required."""

    TOKEN_RE = re.compile(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,}")
    CHAT_RE = re.compile(r"(?:-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})")

    def __init__(self, token: str, chat_id: str):
        if not self.TOKEN_RE.fullmatch(token):
            raise ValueError("Invalid TELEGRAM_BOT_TOKEN format")
        if not self.CHAT_RE.fullmatch(str(chat_id)):
            raise ValueError("Invalid TELEGRAM_CHAT_ID (expected numeric chat ID or @channelusername)")
        self._token = token
        self._chat_id = str(chat_id)

    @staticmethod
    def message(event: Event) -> str:
        if event.status == "TEST":
            return "MONAD WATCHER TEST — NOT AN ANNOUNCEMENT\nTelegram delivery works. No GPG verification was performed."
        if event.status == "VERIFIED":
            status = "GPG VERIFIED" + (f" · CODE {event.severity}" if event.severity != "UNCLASSIFIED" else "")
            info = f"{len(event.signers)} distinct authorized Monad signers"
        else:
            status = "GPG VERIFICATION FAILED"
            info = "Do not act on this announcement before independent verification."
        parts = [f"MF Announcement #{event.number} — {status}", f"Event: {event.kind}", info]
        if event.created:
            parts.append(f"Created: {event.created[:128]}")
        if event.reason:
            parts.append(f"Reason: {event.reason[:350]}")
        parts.append(f"https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-{event.number}")
        parts.append("Natsai · local GPG · no commands executed")
        return "\n".join(parts)

    @staticmethod
    def _api(token: str, method: str, payload: dict) -> dict:
        # Token is required in Telegram's API URL. Never expose URL in logs/errors.
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/{method}",
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "Natsai-Monad-Watcher/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                if response.status != 200:
                    raise DeliveryError(f"Telegram Bot API returned HTTP {response.status}")
                data = json.load(response)
                if not isinstance(data, dict) or data.get("ok") is not True:
                    raise DeliveryError("Telegram Bot API rejected request")
                return data
        except urllib.error.HTTPError as exc:
            raise DeliveryError(f"Telegram Bot API returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise DeliveryError("Telegram Bot API request failed or timed out") from None

    def send(self, event: Event) -> None:
        self._api(self._token, "sendMessage", {
            "chat_id": self._chat_id,
            "text": self.message(event),
            "link_preview_options": {"is_disabled": True},
        })

    @classmethod
    def recent_chats(cls, token: str) -> list[dict]:
        """For one-time setup only: list IDs of chats that recently messaged the bot."""
        if not cls.TOKEN_RE.fullmatch(token):
            raise ValueError("Invalid TELEGRAM_BOT_TOKEN format")
        result = cls._api(token, "getUpdates", {"limit": 100, "timeout": 0})
        chats = {}
        for update in result.get("result", []):
            if not isinstance(update, dict):
                continue
            for field in ("message", "channel_post", "my_chat_member"):
                data = update.get(field, {})
                if isinstance(data, dict):
                    chat = data.get("chat", {})
                    if isinstance(chat, dict) and isinstance(chat.get("id"), int):
                        chats[chat["id"]] = {"id": chat["id"], "type": chat.get("type", "unknown"), "name": str(chat.get("title") or chat.get("first_name") or "")[:80]}
        return list(chats.values())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def custom_url_valid(url: str) -> bool:
    """Admin-configured HTTPS endpoint. Never follow redirects with secrets."""
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname
        port = p.port
        if not host or p.scheme != "https" or port not in (None, 443):
            return False
        if p.username or p.password or p.fragment or any(c.isspace() for c in url):
            return False
        if len(url) > 2048 or host.lower() in ("localhost",) or host.lower().endswith(".local"):
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return bool(re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) and "." in host)
        return ip.is_global
    except ValueError:
        return False


class CustomWebhookNotifier:
    """Outbound POST with a stable documented JSON schema; optional HMAC authentication."""

    def __init__(self, url: str, secret: str = ""):
        if not custom_url_valid(url):
            raise ValueError("CUSTOM_WEBHOOK_URL must be a valid public HTTPS URL")
        if secret and len(secret) < 16:
            raise ValueError("CUSTOM_WEBHOOK_SECRET must contain at least 16 characters")
        self._url = url
        self._secret = secret.encode("utf-8")

    @staticmethod
    def payload(event: Event) -> dict:
        identifier = hashlib.sha256(
            f"{event.number}|{event.digest}|{event.status}|{event.kind}".encode("utf-8")
        ).hexdigest()
        url = f"https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-{event.number}"
        return {
            "schema_version": 1,
            "event_id": identifier,
            "event_type": ("monad.announcement.test" if event.status == "TEST"
                           else "monad.announcement.verification"),
            "change": event.kind,
            "announcement": {
                "id": f"mf-{event.number}" if event.status != "TEST" else None,
                "number": event.number if event.status != "TEST" else None,
                "url": url if event.status != "TEST" else None,
                "created": event.created or None,
                "severity": event.severity if event.status == "VERIFIED" else None,
                "sha256": event.digest or None,
            },
            "verification": {
                "status": event.status,
                "signers": list(event.signers),
                "error": event.reason or None,
            },
            "emitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def send(self, event: Event) -> None:
        payload = self.payload(event)
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Natsai-Monad-Watcher/1.0",
            "X-Monad-Event-ID": payload["event_id"],
        }
        if self._secret:
            digest = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            headers["X-Monad-Signature"] = f"sha256={digest}"
        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        try:
            # No redirect following: never forward signed payloads to a second URL.
            with urllib.request.build_opener(_NoRedirect).open(request, timeout=12) as response:
                if response.status < 200 or response.status >= 300:
                    raise DeliveryError(f"Custom webhook returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            raise DeliveryError(f"Custom webhook returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise DeliveryError("Custom webhook delivery failed or timed out") from None
