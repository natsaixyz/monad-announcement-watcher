# JSON webhook contract (v1)

Set `CUSTOM_WEBHOOK_URL` to your receiver's **public HTTPS** endpoint. The watcher sends a `POST` with `Content-Type: application/json` and `X-Monad-Event-ID` (stable across retries).

Example for a verified announcement:

```json
{
  "schema_version": 1,
  "event_id": "<64 hex chars; stable for same announcement, content, result and change>",
  "event_type": "monad.announcement.verification",
  "change": "NEW",
  "announcement": {
    "id": "mf-2",
    "number": 2,
    "url": "https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-2",
    "created": "2026-10-16 05:45 UTC",
    "severity": "ORANGE",
    "sha256": "<sha256 of length-prefixed announcement.txt and announcement.sig bytes>"
  },
  "verification": {
    "status": "VERIFIED",
    "signers": ["<40-character GPG fingerprint>", "<40-character GPG fingerprint>"],
    "error": null
  },
  "emitted_at": "2026-10-16T11:30:00+00:00"
}
```

Values:

- `event_type`: `monad.announcement.verification` or `monad.announcement.test`.
- `change`: `NEW`, `CHANGED`, `RECOVERED`, or `TEST`.
- `verification.status`: `VERIFIED`, `FAILED`, or `TEST`.
- `announcement.severity`: `GREEN`, `ORANGE`, `RED` **only when VERIFIED**; otherwise `null`.
- `verification.signers`: list of full authorized primary-key fingerprints when VERIFIED; otherwise `[]`.
- `verification.error`: error description when FAILED; otherwise `null`.
- Test deliveries use `null` announcement identifiers and `verification.status=TEST`; **no announcement is verified by a test**.

When `CUSTOM_WEBHOOK_SECRET` is configured (minimum 16 characters), the watcher adds `X-Monad-Signature: sha256=<hex>` where `<hex>` is `HMAC-SHA256(secret, raw_request_body)`. Verify with constant-time comparison on the receiving side. Require the header when you configured a secret; HTTPS alone does not prove who sent a webhook.

Return any `2xx` HTTP status to acknowledge delivery. Non-`2xx`, timeouts and redirects are failures; the watcher retries **that destination only** at its next poll. Delivery is *at least once* across crashes, so deduplicate using `event_id`. Do not execute any commands from webhook contents automatically.

`CUSTOM_WEBHOOK_URL` is controlled by the local operator through `.env`, not by unauthenticated web requests. Public HTTPS URLs are required; private IP literals, localhost, custom ports, and plain HTTP are rejected.
