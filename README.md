# StegoShare

Secure file and text sharing. Content is encrypted with AES-256-GCM, and a
carrier image is generated that reveals nothing about it.

The design principle: **the carrier is not the payload.** A photo can only hide
a couple of hundred kilobytes before statistical detectors notice, so the image
carries a 152-byte capsule — a locator and a capability token — while the
ciphertext lives in object storage. In a 12 MP cover that is under 0.005% of
capacity, which is why file size stops being a constraint.

## Two modes

| Mode | The image carries | Size limit | Opening it needs |
|---|---|---|---|
| **Reference** | 152-byte locator + capability | none | image + password + an approved grant |
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
uv run pytest                                # 169 tests
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

For a 152-byte reference capsule: 310 of 3,240,000 samples changed (0.010%),
all by ±1, PSNR 88.3 dB, ~1.9 s to generate.

**One known limitation.** The header (28 bytes, 44 once its Reed-Solomon parity
is added) must be readable before its own version byte is known, so it is
embedded uniformly and cannot be cost-steered — the receiver would need cover
costs it does not have. The STC-controlled body puts ~0 changes in smooth
regions; the header scatters uniformly, which for a small capsule is over half
the total. `tests/test_adaptive.py` pins this down.

Carriers record their engine in the header, so anything issued under v1 keeps
opening after the upgrade.

## Corruption tolerance

The capsule carries Reed-Solomon parity on both header and body, sitting *below*
the AEAD so it repairs damage before authentication runs. Damage within reach is
repaired and the tag verifies; damage beyond it fails the tag and returns
nothing. Security is unchanged — parity over ciphertext leaks nothing, and a
mis-correction fails closed rather than yielding chosen plaintext.

Measured on a 1200×900 carrier:

| Damage | without RS | with RS |
|---|---|---|
| 200 random samples flipped | fails | **opens** |
| 16×16 pasted patch | 1/10 | **10/10** |
| 32×32 pasted patch | 0/10 | 2/10 |
| 48×48 pasted patch | 0/10 | 0/10 |

**A scuff survives; an edit does not.** Raising parity buys one patch size for a
much larger capsule and then stops helping — a bigger body occupies more carrier
positions, so it catches more of any given patch. Damage tolerance and
undetectability pull against each other, and this design favours undetectability.
RS does nothing at all against recompression; only the lossless-PNG discipline
protects against that.

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
  ecc.py         Reed-Solomon over header and body
  images.py      cover intake: content sniffing, bomb guard, format policy
  storage.py     object storage: local disk or any S3-compatible service
  security.py    login_required, the authorization gate, audit
  auth.py        signup / login / logout
  shares.py      create, request, approve, open
  pipeline.py    orchestration + mandatory round-trip verification
schema.sql
tests/           169 tests, incl. steganalysis and corruption gates
```

## Hosting

Every layer is config-driven, so deploying is a matter of changing values
rather than code.

**Object storage.** Two backends satisfy the same three-method contract and are
covered by one shared suite of contract tests, so they cannot drift apart:

```bash
uv sync --extra s3

STEGOSHARE_STORAGE=s3
STEGOSHARE_S3_BUCKET=stegoshare-objects
STEGOSHARE_S3_REGION=us-east-1
# MinIO or Cloudflare R2 instead of AWS:
STEGOSHARE_S3_ENDPOINT=http://127.0.0.1:9000
```

The bucket must be private. Credentials are deliberately not app config —
boto3 resolves them from the environment, an instance role, or a profile, so a
deployed instance can use a role and hold no long-lived key at all. A missing
bucket name fails the boot, not the first upload.

**Why there are no presigned URLs.** They are the usual advice for offloading
downloads, and they do not fit this design: the bucket holds ciphertext under a
per-share data key the recipient's browser never sees, so a direct URL would
hand out unreadable bytes. Decryption stays server-side and objects are streamed
from memory. That is a consequence of the server-held-keys trust model, and it
also means an object is held in memory while it is decrypted — bounded by
`MAX_CONTENT_LENGTH`, currently 25 MB.

**Everything else:**

- `STEGOSHARE_ENV=production` forces secure session cookies and adds HSTS.
- Point `STEGOSHARE_RATELIMIT_URI` at Redis; in-memory limits are per-worker.
- Run under gunicorn behind a reverse proxy. Never `flask run`.
- Move from SQLite to Postgres once there is more than one writer.
