"""Read-only Monad signed-announcement verification. Python stdlib + GnuPG."""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ARCHIVE_URL = "https://github.com/monad-crypto/mf-nodeops-comms/archive/refs/heads/main.zip"
OFFICIAL_BASE = "https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-"
FINGERPRINT_SOURCE = "https://docs.monad.xyz/node-ops/gpg-keys.json"
MAX_ARCHIVE = 10 * 1024 * 1024
MAX_ANNOUNCEMENT = 128 * 1024
MAX_SIGNATURE = 128 * 1024
MAX_KEY = 128 * 1024
MAX_KEYS = 40
FPR_RE = re.compile(r"[A-F0-9]{40}\Z")
URL_PATH_RE = re.compile(
    r"^/monad-crypto/mf-nodeops-comms/"
    r"(?:tree/main/announcements/mf-|blob/main/announcements/mf-)"
    r"(0|[1-9]\d{0,5})(?:/(?:announcement\.(?:txt|sig))?)?/?$"
)


class VerificationError(Exception):
    """Expected untrusted-input or verification failure."""


def parse_number(value: object) -> int:
    """Accept a GitHub folder/file URL, 'mf-1', or '1'. Never arbitrary URLs."""
    if not isinstance(value, str) or len(value) > 400:
        raise VerificationError("Paste an official Monad GitHub announcement URL or an MF number.")
    value = value.strip()
    match = re.fullmatch(r"(?:mf-)?(0|[1-9]\d{0,5})", value, re.IGNORECASE)
    if match:
        return int(match.group(1))
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(value)
    except ValueError:
        raise VerificationError("Invalid URL.") from None
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or parsed.query or parsed.fragment:
        raise VerificationError("Only official github.com/monad-crypto/mf-nodeops-comms URLs are accepted.")
    match = URL_PATH_RE.fullmatch(parsed.path)
    if not match:
        raise VerificationError("Paste a Monad announcement folder link (announcements/mf-N).")
    return int(match.group(1))


def load_config(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        fps = data["trusted_fingerprints"]
        count = data["required_signatures"]
        if not isinstance(fps, list) or not fps or len(fps) > MAX_KEYS:
            raise ValueError("trusted_fingerprints must be a nonempty list")
        if any(not isinstance(x, str) or FPR_RE.fullmatch(x) is None for x in fps):
            raise ValueError("each fingerprint must be 40 uppercase hex characters")
        if len(set(fps)) != len(fps):
            raise ValueError("duplicate trusted fingerprints")
        if type(count) is not int or count < 2 or count > len(fps):
            raise ValueError("required_signatures must be >= 2 and <= number of trusted fingerprints")
        return {"trusted_fingerprints": frozenset(fps), "required_signatures": count}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise VerificationError(f"Invalid local config.json: {exc}") from exc


def download_archive() -> bytes:
    request = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "Natsai-Monad-Announcement-Verifier/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read(MAX_ARCHIVE + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise VerificationError("Could not download the official Monad GitHub repository. Try again later.") from exc
    if len(data) > MAX_ARCHIVE:
        raise VerificationError("Repository archive exceeds the safety size limit.")
    return data


def latest_announcement_number(archive_bytes: bytes) -> int:
    """Discover the highest public mf-N folder with both announcement files.

    Discovery is NOT signature verification. The normal /api/verify process
    independently authenticates the selected announcement on user request.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            if len(archive.infolist()) > 20000:
                raise VerificationError("Official repository contains too many files.")
            found: dict[int, set[str]] = {}
            for info in archive.infolist():
                match = re.fullmatch(
                    r"mf-nodeops-comms-main/announcements/mf-(0|[1-9]\d{0,5})/"
                    r"(announcement\.(?:txt|sig))",
                    info.filename,
                )
                if match and not info.is_dir() and 0 < info.file_size <= MAX_ANNOUNCEMENT:
                    found.setdefault(int(match.group(1)), set()).add(match.group(2))
            complete = [number for number, files in found.items()
                        if {"announcement.txt", "announcement.sig"} <= files]
            if not complete:
                raise VerificationError("No complete public Monad announcements were found.")
            return max(complete)
    except (zipfile.BadZipFile, EOFError, OSError) as exc:
        raise VerificationError("Malformed or damaged repository archive.") from exc


def _zip_member(archive: zipfile.ZipFile, suffix: str, limit: int) -> bytes:
    name = "mf-nodeops-comms-main/" + suffix
    try:
        info = archive.getinfo(name)
        if info.is_dir() or info.file_size > limit:
            raise VerificationError("Official repository file exceeds the safety limit.")
        with archive.open(info) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise VerificationError("Official repository file exceeds the safety limit.")
        return data
    except KeyError:
        raise VerificationError(f"Missing {suffix} in the official repository.") from None


def repository_files(archive_bytes: bytes, number: int) -> tuple[bytes, bytes, list[bytes]]:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            base = f"announcements/mf-{number}/"
            message = _zip_member(archive, base + "announcement.txt", MAX_ANNOUNCEMENT)
            signature = _zip_member(archive, base + "announcement.sig", MAX_SIGNATURE)
            names = [
                name for name in archive.namelist()
                if re.fullmatch(r"mf-nodeops-comms-main/keys/[a-zA-Z0-9_-]+\.pub\.asc", name)
            ]
            if not names or len(names) > MAX_KEYS:
                raise VerificationError("No usable signing keys (or too many keys) in the repository.")
            key_data = [_zip_member(archive, name.removeprefix("mf-nodeops-comms-main/"), MAX_KEY) for name in names]
    except (zipfile.BadZipFile, EOFError, OSError) as exc:
        raise VerificationError("Malformed or damaged repository archive.") from exc
    return message, signature, key_data


def _gpg(args: list[str], home: Path, timeout: int = 12) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["gpg", "--no-options", "--homedir", str(home), "--batch", "--no-tty", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError("GnuPG unavailable or exceeded its execution timeout.") from exc


def _primary_fingerprints(colon_output: str) -> list[str]:
    """Extract primary pub fingerprints only; never mistake a subkey for a signer."""
    primaries: list[str] = []
    awaiting_primary = False
    for line in colon_output.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            awaiting_primary = True
        elif fields[0] == "sub":
            awaiting_primary = False
        elif fields[0] == "fpr" and awaiting_primary:
            if len(fields) > 9:
                primaries.append(fields[9].upper())
            awaiting_primary = False
    return primaries


def verify_signatures(message: bytes, signature: bytes, keys: list[bytes], config: dict) -> list[str]:
    if not shutil.which("gpg"):
        raise VerificationError("GnuPG is not installed on the server.")
    trusted = config["trusted_fingerprints"]
    with tempfile.TemporaryDirectory(prefix="monad-verify-") as root:
        workspace = Path(root)
        home = workspace / "gnupg"
        home.mkdir(mode=0o700)
        msg_path = workspace / "announcement.txt"
        sig_path = workspace / "announcement.sig"
        msg_path.write_bytes(message)
        sig_path.write_bytes(signature)
        imported: set[str] = set()
        for index, key in enumerate(keys):
            key_path = workspace / f"key-{index}.asc"
            key_path.write_bytes(key)
            inspect = _gpg(["--with-colons", "--fingerprint", "--show-keys", str(key_path)], home)
            if inspect.returncode != 0:
                raise VerificationError("Could not inspect a public key from the official repository.")
            key_fps = _primary_fingerprints(inspect.stdout)
            if len(key_fps) != 1:
                raise VerificationError("Public key files must contain exactly one primary key.")
            primary = key_fps[0]
            if primary not in trusted:
                # Ignore unknown keys: repo content cannot silently update local trust.
                continue
            result = _gpg(["--import", str(key_path)], home)
            if result.returncode != 0:
                raise VerificationError("Could not import a pinned authorized GPG public key.")
            imported.add(primary)
        if len(imported) < config["required_signatures"]:
            raise VerificationError("Not enough locally pinned public keys were found in the repository. Review key rotation manually.")
        result = _gpg(
            ["--no-auto-key-retrieve", "--status-fd", "1", "--verify", str(sig_path), str(msg_path)],
            home, timeout=20,
        )
        records: list[list[str]] = []
        for line in result.stdout.splitlines():
            if line.startswith("[GNUPG:] "):
                records.append(line[len("[GNUPG:] "):].split())
        blocked = {
            "BADSIG", "ERRSIG", "NODATA", "NO_PUBKEY", "EXPSIG", "EXPKEYSIG",
            "REVKEYSIG", "KEYREVOKED", "KEYEXPIRED", "SIGEXPIRED", "FAILURE", "ERROR"
        }
        if result.returncode != 0 or any(fields and fields[0] in blocked for fields in records):
            raise VerificationError("GPG signature verification failed, or a signer key/signature is invalid or expired.")
        valid: set[str] = set()
        for fields in records:
            if fields and fields[0] == "VALIDSIG":
                # GPG status: VALIDSIG signer_fpr date timestamp expiry version reserved algo hash class [primary_fpr]
                primary = fields[10].upper() if len(fields) > 10 else fields[1].upper()
                if primary not in trusted or primary not in imported:
                    raise VerificationError("A signature comes from an unrecognized signer. Do not trust this announcement.")
                valid.add(primary)
        if len(valid) < config["required_signatures"]:
            raise VerificationError("Fewer than two distinct authorized GPG signers verified this announcement.")
        return sorted(valid)


def inspect_announcement(message: bytes, number: int) -> dict:
    """Display envelope only; no announcement-text parsing or acceptance rules.

    The number identifies the repository folder, not an authenticated claim in
    the message. The original bytes are passed to GPG before this function.
    Legacy metadata fields remain empty for API compatibility.
    """
    return {
        "number": number,
        "created": "",
        "expires": None,
        "severity": "UNCLASSIFIED",
        "message": message.decode("utf-8", errors="replace"),
    }


def verify_announcement(number: int, config: dict, archive_bytes: bytes | None = None) -> dict:
    if type(number) is not int or not 0 <= number <= 999999:
        raise VerificationError("Invalid MF announcement number.")
    archive = archive_bytes if archive_bytes is not None else download_archive()
    message, signature, public_keys = repository_files(archive, number)
    # Exact downloaded bytes. GPG + pinned distinct signer checks decide success.
    signers = verify_signatures(message, signature, public_keys, config)
    return {
        **inspect_announcement(message, number),
        "ok": True,
        "signers": signers,
        "verification_scope": "signatures_only",
        "metadata_checked": False,
        "number_source": "repository_folder",
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "github_url": OFFICIAL_BASE + str(number),
        "fingerprint_source": FINGERPRINT_SOURCE,
        "notice": "Signatures only: check the signed message's identity, dates, expiry and instructions yourself. "
                  "The folder number is not authenticated by this check. "
                  "Hosted results require trust in the operator; verify locally before critical actions.",
    }
