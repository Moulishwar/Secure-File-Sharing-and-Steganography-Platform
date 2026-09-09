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
uv run pytest                                # 93 tests
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

Keyed LSB **matching** (±1), never replacement. Replacement drives even values
up and odd values down, and that asymmetry is exactly what RS and sample-pair
analysis detect. Positions come from a ChaCha20 keystream keyed by the password,
so the payload's location is secret even though this source is public.

On top of that, the body is embedded with **HILL costs driving Syndrome Trellis
Codes**. HILL scores where the image is busy enough to absorb a change; STC
searches for the stego vector that satisfies the syndrome at least total cost.
The asymmetry that makes this work: extraction is a parity-check multiply, so
the receiver needs no costs, no cover, and no knowledge of which samples moved.

Measured on a 1200×900 cover with a smooth sky over grainy ground:

| | changes | in the smooth sky | HILL distortion |
|---|---|---|---|
| uniform (v1) | 12,653 | 6,217 | baseline |
| HILL + STC (v2) | 5,347 | **62** | **1%** of v1 |

For a 104-byte reference capsule: 203 of 3,240,000 samples changed (0.006%),
all by ±1, PSNR 90.2 dB, ~0.7 s to generate.

**One known limitation.** The 28-byte header must be readable before its own
version byte is known, so it is embedded uniformly and cannot be cost-steered —
the receiver would need cover costs it does not have. The STC-controlled body
puts ~0 changes in smooth regions; the header scatters ~106 uniformly, which for
a small capsule is over half the total. `tests/test_adaptive.py` pins this down.

Carriers record their engine in the header, so anything issued under v1 keeps
opening after the upgrade.

## Steganalysis gate

`tests/test_steganalysis.py` runs a chi-square attack against our own output and
fails the build if it fires. It is paired with a positive control — deliberate
LSB replacement, which must be detected — because a gate that never fires
measures nothing.

**Read the result narrowly.** Chi-square is an old, weak detector that only
fires at high replacement rates. Passing is a floor, not a guarantee. A modern
CNN steganalyser (SRNet and successors) is far stronger and is not implemented
here. Any claim about this engine should name the detector and the payload rate;
never state undetectability as an absolute.

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
  stego.py       embedding engine: position selection + version dispatch
  costs.py       HILL cost model -- where the image can absorb a change
  stc.py         syndrome trellis codes
  images.py      cover intake: content sniffing, bomb guard, format policy
  storage.py     object storage abstraction (local now, S3/MinIO later)
  security.py    login_required, the authorization gate, audit
  auth.py        signup / login / logout
  shares.py      create, request, approve, open
  pipeline.py    orchestration + mandatory round-trip verification
schema.sql
tests/           93 tests, including a steganalysis gate
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
