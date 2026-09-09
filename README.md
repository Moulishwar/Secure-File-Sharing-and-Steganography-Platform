# StegoShare

Secure file and text sharing. Content is encrypted with AES-256-GCM, and a
carrier image is generated that reveals nothing about it.

The design principle: **the carrier is not the payload.** A photo can only hide
a couple of hundred kilobytes before statistical detectors notice, so the image
carries a 104-byte capsule — a locator and a capability token — while the
ciphertext lives in object storage. In a 12 MP cover that is under 0.003% of
capacity, which is why file size stops being a constraint.

## Two modes

| Mode | The image carries | Size limit | Opening it needs |
|---|---|---|---|
| **Reference** | 104-byte locator + capability | none | image + password + an approved grant |
| **Inline** | the encrypted content itself | ~45–220 KB in a phone photo | image + password only, no server |

Reference mode is the platform. Inline mode is a self-contained covert channel.
Both use the same embedding engine.

## Quick start

```bash
uv sync
uv run stegoshare-init                       # writes a gitignored .env
set -a && . ./.env && set +a
uv run flask --app stegoshare init-db
uv run flask --app stegoshare run
```

Then open <http://127.0.0.1:5000>.

```bash
uv run pytest                                # 64 tests
```

## How access control works

`grants.wrapped_dek` is **NULL until the approval threshold is met**. An
unapproved recipient does not hold a permission flag that a route has to
remember to check — they hold no key material at all. Authorization and key
retrieval are the same query (`security.open_share`), so there is no code path
that returns a key without having proved the grant.

Opening a reference share requires all four of:

1. a grant row for this (share, recipient),
2. that grant's `wrapped_dek` being non-NULL,
3. the capability token carried inside the image matching the stored digest,
4. the wrapped key unwrapping under associated data naming this exact share and
   this exact user.

Every failure returns the same 403.

## The embedding engine

Keyed LSB **matching** (±1), not replacement. Replacement drives even values up
and odd values down, and that asymmetry is exactly what RS analysis and
sample-pair analysis detect. Positions come from a ChaCha20 keystream keyed by
the password, so the payload's location is secret even though this source is
public.

Measured on a 1200×900 cover: 434 of 3,240,000 samples changed (0.013%), all by
±1, PSNR 86.9 dB.

Content-adaptive costs (HILL / S-UNIWARD with Syndrome Trellis Codes) are the
planned upgrade. They are not here yet because adaptivity makes a pixel's
eligibility depend on its value, which breaks reproducible position selection
unless the scheme also carries wet-paper codes — that is what STC solves.

## What this does and does not protect

- **Encryption** protects the content. **Hiding** conceals that there is
  anything to protect. They are different properties and the hiding is the
  weaker one.
- **The operator can decrypt reference-mode files.** The server holds the
  key-encryption key. If the promise needs to be "only you can read this", that
  is client-side end-to-end encryption and a different architecture.
- **Any app that recompresses the image destroys the payload.** Send the PNG as
  a file. WhatsApp, Instagram and most email gateways will break it.
- **Never reuse a cover image that exists anywhere else.** If someone can obtain
  the original, they diff the two files and the hiding is over — no analysis
  needed.

## Layout

```
stegoshare/
  config.py      environment-driven config; refuses to start without secrets
  db.py          connection per request
  crypto.py      AES-256-GCM, envelope wrapping, AAD binding
  capsule.py     capsule format + Argon2id/HKDF key schedule
  stego.py       keyed LSB-matching engine
  images.py      cover intake: content sniffing, bomb guard, format policy
  storage.py     object storage abstraction (local now, S3/MinIO later)
  security.py    login_required, the authorization gate, audit
  auth.py        signup / login / logout
  shares.py      create, request, approve, open
  pipeline.py    orchestration + mandatory round-trip verification
schema.sql
tests/           64 tests
```

## Hosting

Local development is the current target and every layer is built for hosting.
What changes when you deploy:

- `STEGOSHARE_ENV=production` forces secure session cookies and adds HSTS.
- Swap `STEGOSHARE_STORAGE` for an S3/MinIO backend implementing the three
  methods in `storage.Storage`.
- Point `STEGOSHARE_RATELIMIT_URI` at Redis; in-memory limits are per-worker.
- Run under gunicorn behind a reverse proxy. Never `flask run`.
- Move from SQLite to Postgres once there is more than one writer.
