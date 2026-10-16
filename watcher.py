"""Independent Monad announcement watcher: local GPG verification -> notifications.

Standard library + GnuPG. No HTTP-server dependency, wallet, or validator access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import tempfile
import time
import zipfile
import io
from pathlib import Path
from typing import Callable, Mapping

from notifiers import DiscordNotifier, TelegramNotifier, CustomWebhookNotifier, DeliveryError, Event
from verifier import (
    VerificationError, download_archive, load_config,
    verify_announcement, MAX_ANNOUNCEMENT, MAX_SIGNATURE,
)

LOG = logging.getLogger("monad-watcher")
ROOT = Path(__file__).resolve().parent
STATE_VERSION = 1
PREFIX = "mf-nodeops-comms-main/announcements/"
ITEM_RE = re.compile(r"mf-(0|[1-9][0-9]{0,5})/(announcement\.(?:txt|sig))\Z")


def discover(archive_data: bytes) -> dict[int, str]:
    """Return SHA256 of signed bytes, by MF number. Incomplete folders are ignored.

    A new or edited file triggers re-verification; no GitHub commits are executed.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
            if len(archive.infolist()) > 20000:
                raise VerificationError("Repository archive has too many entries")
            names: dict[int, dict[str, str]] = {}
            for info in archive.infolist():
                if not info.filename.startswith(PREFIX):
                    continue
                match = ITEM_RE.fullmatch(info.filename[len(PREFIX):])
                if match and not info.is_dir():
                    number = int(match.group(1))
                    kind = match.group(2)
                    limit = MAX_ANNOUNCEMENT if kind == "announcement.txt" else MAX_SIGNATURE
                    if not (0 < info.file_size <= limit):
                        raise VerificationError(f"MF #{number} contains an invalid {kind} size")
                    names.setdefault(number, {})[kind] = info.filename
            hashes = {}
            for number, files in sorted(names.items()):
                if "announcement.txt" not in files or "announcement.sig" not in files:
                    continue
                h = hashlib.sha256()
                for kind in ("announcement.txt", "announcement.sig"):
                    limit = MAX_ANNOUNCEMENT if kind.endswith(".txt") else MAX_SIGNATURE
                    with archive.open(files[kind]) as f:
                        data = f.read(limit + 1)
                    if len(data) > limit:
                        raise VerificationError(f"MF #{number} exceeds size limit")
                    h.update(len(data).to_bytes(8, "big"))
                    h.update(data)
                hashes[number] = h.hexdigest()
            if not hashes:
                raise VerificationError("No complete MF announcements found")
            return hashes
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise VerificationError("Malformed GitHub archive") from exc


def initial_state() -> dict:
    return {"version": STATE_VERSION, "initialized": False, "seen": {}}


def load_state(path: Path) -> dict:
    if not path.exists():
        return initial_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != STATE_VERSION or type(data.get("initialized")) is not bool:
            raise ValueError("invalid schema/version")
        seen = data.get("seen")
        if not isinstance(seen, dict):
            raise ValueError("missing records")
        for num, record in seen.items():
            if not re.fullmatch(r"(0|[1-9][0-9]{0,5})", num):
                raise ValueError("bad MF number in state")
            if not isinstance(record, dict) or not re.fullmatch(r"[0-9a-f]{64}", record.get("digest", "")) or record.get("status") not in ("VERIFIED", "FAILED"):
                raise ValueError("corrupted state record")
            if "pending" in record:
                if type(record["pending"]) is not bool or record.get("kind") not in ("NEW", "CHANGED", "RECOVERED"):
                    raise ValueError("invalid notification state")
                targets, delivered = record.get("targets"), record.get("delivered")
                if not isinstance(targets, list) or not targets or not isinstance(delivered, list):
                    raise ValueError("invalid notification destinations")
                if any(not isinstance(x, str) or not re.fullmatch(r"[a-z_]{1,30}", x) for x in targets + delivered):
                    raise ValueError("invalid notification destination")
                if len(set(targets)) != len(targets) or len(set(delivered)) != len(delivered) or not set(delivered) <= set(targets):
                    raise ValueError("invalid notification acknowledgments")
        return data
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        # Never silently reset state: would cause unexpected duplicate notifications.
        raise RuntimeError(f"Watcher state could not be read. Resolve or restore {path}: {exc}") from None


def save_state(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def run_cycle(state: dict, archive_bytes: bytes, config: dict,
              send: Callable[[Event], None] | Mapping[str, Callable[[Event], None]],
              persist: Callable[[], None], start_mode: str = "latest") -> int:
    """Poll one snapshot. Ack each destination independently, to avoid cross-channel spam.

    Previous v1 state records have no 'pending' field and are considered complete.
    Newly enabled destinations are not sent historical announcements.
    """
    sinks = {"discord": send} if callable(send) else dict(send)
    if not sinks or any(not re.fullmatch(r"[a-z_]{1,30}", name) or not callable(fn)
                        for name, fn in sinks.items()):
        raise ValueError("At least one named notifier is required")
    announcements = discover(archive_bytes)
    first = not state["initialized"]
    newest = max(announcements)
    processed = 0
    delivery_errors: list[DeliveryError] = []
    for number, digest in sorted(announcements.items()):
        key = str(number)
        previous = state["seen"].get(key)
        # A complete prior event is not resent when adding a new notification channel.
        if previous and previous["digest"] == digest and previous["status"] == "VERIFIED" and not previous.get("pending", False):
            continue
        status = "VERIFIED"
        result = None
        error = ""
        try:
            result = verify_announcement(number, config, archive_bytes=archive_bytes)
        except VerificationError as exc:
            status = "FAILED"
            error = str(exc)
        same = bool(previous and previous["digest"] == digest and previous["status"] == status)
        if same and not previous.get("pending", False):
            continue
        if same:  # Retry only destinations not yet acknowledged for this event.
            kind = previous["kind"]
            targets = [name for name in previous["targets"] if name in sinks]
            delivered = set(previous["delivered"])
        else:
            kind = "NEW" if not previous else ("CHANGED" if previous["digest"] != digest else "RECOVERED")
            targets = list(sinks)
            delivered = set()
        event = Event(number=number, status=status, kind=kind,
                      severity=result["severity"] if result else "UNCLASSIFIED",
                      created=result["created"] if result else "",
                      signers=tuple(result["signers"]) if result else (), reason=error, digest=digest)
        # First deployment should not spam old valid announcements.
        if first and not same and status == "VERIFIED" and (start_mode == "silent" or number != newest):
            delivered.update(targets)
        else:
            for channel in targets:
                if channel in delivered:
                    continue
                try:
                    sinks[channel](event)
                except DeliveryError as exc:
                    delivery_errors.append(DeliveryError(f"{channel}: {exc}"))
                    continue  # Continue to other destinations and later urgent announcements.
                delivered.add(channel)
                # Persist each successful delivery before sending to the next destination.
                state["seen"][key] = {"digest": digest, "status": status, "kind": kind,
                                      "targets": targets, "delivered": sorted(delivered), "pending": True}
                persist()
        finished = set(targets) <= delivered
        if finished:
            # Mark complete only when all enabled destinations were acknowledged.
            state["seen"][key] = {"digest": digest, "status": status, "kind": kind,
                                  "targets": targets, "delivered": sorted(delivered), "pending": False}
            persist()
            processed += 1
            LOG.info("MF #%d %s (%s)", number, status, kind)
    if not state["initialized"] and not delivery_errors:
        state["initialized"] = True
        persist()
    if delivery_errors:
        raise DeliveryError(f"{len(delivery_errors)} notification delivery failure(s); pending retry: " +
                            "; ".join(str(e) for e in delivery_errors[:3]))
    return processed


def get_args():
    p = argparse.ArgumentParser(description="Independent Monad GPG announcement watcher")
    p.add_argument("--once", action="store_true", help="Poll once and exit")
    p.add_argument("--test-webhook", action="store_true", help="Test Discord only, without altering state")
    p.add_argument("--test-telegram", action="store_true", help="Test Telegram only, without altering state")
    p.add_argument("--test", choices=["discord", "telegram", "webhook", "all"], help="Send test alert to selected destination(s); no GPG or state changes")
    p.add_argument("--telegram-chat-id", action="store_true", help="List chat IDs of recent messages to this bot")
    return p.parse_args()


def main() -> int:
    args = get_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    custom_url = os.environ.get("CUSTOM_WEBHOOK_URL", "").strip()
    custom_secret = os.environ.get("CUSTOM_WEBHOOK_SECRET", "").strip()
    if args.telegram_chat_id:
        if not telegram_token:
            LOG.error("Set TELEGRAM_BOT_TOKEN first")
            return 2
        try:
            chats = TelegramNotifier.recent_chats(telegram_token)
            if chats:
                for chat in chats:
                    print(f"CHAT_ID={chat['id']} TYPE={chat['type']} NAME={chat['name']}")
            else:
                print("No chats found. Send /start to your bot in Telegram and retry.")
        except (ValueError, DeliveryError) as exc:
            LOG.error("Could not read recent Telegram chats: %s", exc)
            return 1
        return 0
    sinks = {}
    try:
        if discord_url:
            sinks["discord"] = DiscordNotifier(discord_url).send
        if telegram_token or telegram_chat:
            if not telegram_token or not telegram_chat:
                raise ValueError("Both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")
            sinks["telegram"] = TelegramNotifier(telegram_token, telegram_chat).send
        if custom_url:
            sinks["webhook"] = CustomWebhookNotifier(custom_url, custom_secret).send
        elif custom_secret:
            raise ValueError("CUSTOM_WEBHOOK_SECRET requires CUSTOM_WEBHOOK_URL")
        if not sinks:
            raise ValueError("Configure Discord, Telegram, or custom webhook in .env")
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    if args.test_webhook or args.test_telegram or args.test:
        choice = args.test or ("discord" if args.test_webhook else "telegram")
        names = list(sinks) if choice == "all" else [choice]
        if any(name not in sinks for name in names):
            LOG.error("Requested notifier is not configured: %s", choice)
            return 2
        failures = 0
        for name in names:
            try:
                sinks[name](Event(number=0, status="TEST", kind="TEST"))
            except DeliveryError as exc:
                LOG.error("%s test failed: %s", name, exc)
                failures += 1
            else:
                LOG.info("%s test delivered; no announcement verified", name.capitalize())
        return 1 if failures else 0
    try:
        config = load_config(Path(os.environ.get("VERIFIER_CONFIG", ROOT / "config.json")))
        interval = int(os.environ.get("CHECK_INTERVAL_SECONDS", "300"))
        if not 60 <= interval <= 86400:
            raise ValueError("CHECK_INTERVAL_SECONDS must be 60..86400")
        start_mode = os.environ.get("START_MODE", "latest").lower()
        if start_mode not in ("latest", "silent"):
            raise ValueError("START_MODE must be latest or silent")
        state_path = Path(os.environ.get("WATCHER_STATE", "/state/watcher.json"))
        state = load_state(state_path)
        # Check writable durable storage before sending any alert.
        save_state(state_path, state)
    except (VerificationError, ValueError, RuntimeError) as exc:
        LOG.error("Configuration/state error: %s", exc)
        return 2

    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    LOG.info("Polling public Monad announcements every %ds; GPG verification is local", interval)
    failures = 0
    while not stopped:
        try:
            archive = download_archive()
            count = run_cycle(state, archive, config, sinks, lambda: save_state(state_path, state), start_mode)
            failures = 0
            LOG.info("Poll OK, %d new/changed results processed", count)
        except (VerificationError, DeliveryError, OSError) as exc:
            failures += 1
            LOG.warning("Poll failed (%d consecutive): %s", failures, exc)
            # Keep state unchanged for unsent events. No false GPG failure on network outages.
            if args.once:
                return 1
        if args.once:
            return 0
        # Respond promptly to SIGTERM, no external scheduler or cron required.
        for _ in range(interval):
            if stopped:
                break
            time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
