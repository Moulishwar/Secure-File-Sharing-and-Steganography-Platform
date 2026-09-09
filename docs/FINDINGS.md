# Code review findings — Secure File Sharing & Steganography Platform

**Purpose of this document:** a from-source code review of this repository as it currently stands (Flask app, `main.py` + `image.py` + `textstenography.py` + `web.py` + `check.py`), written to brief whoever picks this project up next for a rewrite to modern, hostable standards. Every finding below cites the exact file/lines it came from. This is not a hypothetical threat model — every item is something actually present in the committed code.

Read `## 0. Priority order` first, then use the rest as a reference while rewriting.

---

## 0. Priority order

If this is being rewritten rather than patched incrementally, the honest recommendation is: **treat this as a rebuild guided by the app's feature set, not a patch job.** The core problems (plaintext passwords, ECB-mode block cipher, a symmetric-encryption path that doesn't actually round-trip, SQL built by string interpolation, secrets committed to git) are foundational enough that patching around them individually will leave the architecture just as fragile. That said, if a full rebuild isn't the plan, fix in this order:

1. **Plaintext password storage** (§1.1) — this is the single most serious issue; nothing else matters if account credentials are stored and compared in cleartext.
2. **The double encryption layer that doesn't work** (§1.4) — files are not actually recoverable via the ChaCha20 path as committed; this is a correctness bug wearing a security-feature costume.
3. **SQL built by string formatting** (§1.2) and **secrets/runtime data committed to git** (§1.6) — both are quick, mechanical fixes with outsized risk reduction.
4. Everything else in §1, then the modernization checklist in §3.

---

## 1. Security findings

### 1.1 Passwords are stored and compared in plaintext — critical
- `main.py:141-154` (`/sign`, signup): `pswd = request.form["pswd"]` is inserted directly into the `data` table with no hashing.
- `main.py:158-176` (`/login`): authentication is `select * from data where email=? and password=?` — a direct plaintext comparison against the stored value.
- **Fix:** hash on signup with a modern KDF (`werkzeug.security.generate_password_hash` is already available for free since Flask pulls in Werkzeug, or use `passlib` with bcrypt/argon2) and verify with `check_password_hash` on login. Never store or compare the raw password again.

### 1.2 SQL built by Python string interpolation instead of parameters — high
- `main.py:169-170` (`/login`): `"select count(*) from requesttable where otheruserid=%s and status='not'" % (v[0])`.
- `main.py:516-517` (`/notification`): identical pattern.
- `main.py:534-535` (`/approve`): identical pattern.
- In all three cases the interpolated value is a session-derived integer (a user's primary key), not raw user input at that exact call site — so it isn't trivially exploitable today — but it is still the textbook SQL-injection anti-pattern, sitting directly next to correctly parameterized queries elsewhere in the same file (e.g. `main.py:164`, `:384-388`), which shows the parameterized form was already known and just not applied consistently.
- **Fix:** parameterize these three queries the same way the rest of the file does (`con.execute("... where otheruserid=? and status='not'", (v[0],))`). There is no reason to ever build a SQL string with `%` in this codebase.

### 1.3 Hardcoded Flask secret key — high
- `main.py:16`: `app.secret_key = 'any random string'`.
- A static, publicly-visible (it's in the git history) secret key means anyone can forge or tamper with session cookies — including the `session["user"]` tuple that every access-control check in this app relies on.
- **Fix:** load from an environment variable (`app.secret_key = os.environ["FLASK_SECRET_KEY"]`, failing startup if unset), generated with `secrets.token_hex(32)` and never committed.

### 1.4 The ChaCha20 encrypt/decrypt path does not actually work — critical (correctness, not just security)
- Encrypt side, `main.py:364-376` (`storedata()` / `/storeuser`): generates `keys = os.urandom(32)` fresh on every call and never persists it anywhere — not written to the DB, not returned, not logged (deliberately or otherwise).
- Decrypt side, `main.py:582-587` (`decrypt()` / `/decrypt`): generates its **own independent** `key = os.urandom(32)`, unrelated to whatever key encryption used.
- Net effect: **decryption is mathematically guaranteed to fail** — ChaCha20 with the wrong key does not raise an error, it just produces garbage output. Both call sites wrap this in a bare `except: pass` (`main.py:375-376`, `593-594`), so the failure is silent — the app reports success and hands back corrupted data.
- This sits on top of a *separate*, actually-working encryption layer: `sencrypt()`/`sdecrypt()` (`main.py:82-126`) use Blowfish with a key that genuinely is generated once (`generatekey()`) and persisted in `sharingtable.key` (`main.py:384-388`), so files aren't actually unrecoverable end-to-end — but the ChaCha20 layer wrapped around that is dead weight that actively corrupts whatever it touches. This reads as an abandoned attempt to add a second encryption layer that was never finished.
- **Fix:** either remove the ChaCha20 layer entirely (Blowfish-via-`sencrypt`/`sdecrypt` is already the operative encryption), or replace the whole thing with one correct, authenticated scheme — see §1.5 for why Blowfish/ECB shouldn't be the long-term answer either.

### 1.5 Blowfish in ECB-equivalent mode, no authentication, weak padding — high
- `main.py:82-105` (`sencrypt`): encrypts 8-byte blocks independently with `cipher.encrypt_block()` — no chaining mode, no IV. This is ECB in all but name: identical plaintext blocks always produce identical ciphertext blocks, leaking structure (visible as repeating patterns for any file with repeated 8-byte sequences).
- Padding is manual null-byte padding (`block.ljust(bufferSize, b'\0')`) with no length-prefix or unpadding logic that distinguishes real trailing nulls from padding — decrypted files can silently gain or lose trailing null bytes.
- No authentication tag (not AEAD) — a corrupted or tampered ciphertext block decrypts to *something* rather than failing loudly.
- Blowfish's 64-bit block size is also considered legacy for anything beyond small files (birthday-bound collision risk at scale, e.g. SWEET32-class attacks).
- **Fix:** replace with a single AEAD scheme — `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305` or `AESGCM` — using a fresh random 12-byte nonce per encryption (stored alongside the ciphertext, nonces are not secret) and a properly generated/stored key. This single change also resolves §1.4, since there'd only be one encryption layer, one key, one round trip.

### 1.6 Secrets and generated runtime data are committed to git — high
Confirmed via `git ls-files` in this repo: `store.db`, `data.db`, everything under `encrpyt/`, and generated images under `static/col/` and `static/decrypt/` are tracked in version control.
- `store.db` contains the `sharingtable.key` column — i.e., **the plaintext symmetric keys for every encrypted file share are committed to git history**, alongside plaintext user passwords (§1.1) and email addresses.
- Rewriting history to purge this is worth doing before any public hosting, not just gitignoring going forward (removing a file from a future commit does not remove it from git history/clones already taken).
- **Fix:** add `.gitignore` entries for `*.db`, `upload/`, `encrpyt/`, `static/col/`, `static/decrypt/`; ship a schema-creation script or migration instead of a binary DB; if this repo is ever made public, scrub history (`git filter-repo` or equivalent) or start a fresh repository, since the committed keys/passwords should be considered permanently compromised.

### 1.7 No CSRF protection, and state-changing actions are reachable via plain GET — medium/high
- `/approve`, `/requestpermission`, `/decrypt`, `/logout` (main.py:472, 484, 522, 572) are all registered for both `GET` and `POST` and perform state changes or reveal decrypted content on GET — meaning a plain link (or an `<img src>`, or a crawler prefetching a page) can trigger approval of a share, a decryption, or a logout.
- No CSRF token exists anywhere in the templates or forms.
- **Fix:** restrict state-changing routes to `POST` only, and add CSRF protection (Flask-WTF's `CSRFProtect` is the standard choice) on every form.

### 1.8 No authentication decorator — ad hoc `session["user"]` access throughout — medium
- Nearly every protected route (`/uploadfile`, `/uploadtext`, `/textsten`, `/viewshared`, `/decrypt`, `/approve`, `/notification`, `/requestpermission`, `/success`) accesses `session["user"]` directly with no existence check. If accessed while logged out, this raises an uncaught `KeyError` → an unhandled 500 (and with `debug=True`, a full interactive traceback — see §1.9) instead of a clean redirect to login.
- **Fix:** a `@login_required` decorator that checks `"user" in session` and redirects to `/` (or returns 401) otherwise, applied uniformly.

### 1.9 `debug=True` in the app entrypoint — high, if ever exposed beyond localhost
- `main.py:600`: `app.run(debug=True)`.
- Flask's debug mode exposes the Werkzeug interactive debugger — if an unhandled exception occurs on a network-reachable instance, an unauthenticated visitor can get a Python console in the request context, which is remote code execution in practical terms.
- **Fix:** debug mode must be driven by environment/config (`app.run(debug=os.environ.get("FLASK_DEBUG") == "1")`, defaulting to off), and any real hosting should run via a production WSGI server (gunicorn/uwsgi) behind a reverse proxy rather than Flask's development server at all.

### 1.10 Unsanitized, client-controlled filenames on upload — medium
- `main.py:280` (`/uploadtext`), `:319-322` (`/uploadfile`): `f.save("upload/" + f.filename)` uses the browser-supplied filename verbatim, with no `secure_filename()`, no extension allowlist, and no size limit.
- A crafted filename containing path-traversal sequences or a filename engineered to collide with/overwrite another user's file is not defended against; there's also no check that the uploaded "coverimage" is actually an image before it's handed to `cv2.imread`/`PIL.Image.open`.
- **Fix:** `werkzeug.utils.secure_filename()`, an explicit content-type/extension allowlist, `MAX_CONTENT_LENGTH` on the Flask app, and generating server-side filenames (e.g. a UUID) rather than trusting client input, storing the original name only as metadata.

### 1.11 Sensitive values and debug output printed to stdout — low/medium
- `main.py:528`: `print(fileid, createuserid, currentuser)` in `/approve`.
- `main.py:580`: `print(key)` in `/decrypt` — prints the actual `sharingtable` row, including the plaintext encryption key, to the server console/log.
- Numerous other `print()` calls throughout act as ad hoc debugging left in place.
- **Fix:** replace with the standard `logging` module at appropriate levels, and never log key material or credentials, even at debug level.

### 1.12 Broad exception swallowing hides real failures — low/medium
- `main.py:150, 174-176, 281-285, 309-313, 375-376, 379-382, 593-594` — a mix of bare `except:` and `except Exception as e: print(e)` that either silently continue or just print-and-swallow. This is how the broken crypto in §1.4 goes unnoticed, and generally makes the app's actual behavior under failure impossible to reason about or test.
- **Fix:** catch specific exceptions, let unexpected ones propagate (or be logged with a stack trace and turned into a proper error response), and never use a bare `except: pass` around anything security-relevant.

### 1.13 `check.py` unconditionally wipes application data — medium (operational hazard, not a remote vuln)
- `check.py:13-19`: on every run, unconditionally executes `delete from sharing`, `delete from sharingtable`, `delete from requesttable`, then commits. No confirmation, no flag, no dry-run.
- This reads as a developer debugging script that happens to live in the repo root next to the actual app — if run against a real database by mistake, it silently destroys all sharing/request data.
- **Fix:** remove from the shipped app, or move to a clearly separated `scripts/dev-only/` path with a required `--yes-really` flag and a docstring warning.

### 1.14 `web.py` is dead scratch code with a hardcoded user id — low
- `web.py`: connects to `store.db`, runs a query hardcoded to `userid=2`, computes a result it never uses or prints (`working()` builds `vx` and returns nothing). Looks like a debugging script from development, not part of the running application.
- **Fix:** remove, or if it has ongoing debugging value, move it out of the deployable app tree.

### 1.15 No dependency manifest, no `.gitignore` — low (but blocks reproducible builds/hosting)
- No `requirements.txt`, `pyproject.toml`, or `.gitignore` exists anywhere in the repository. Dependencies (`flask`, `blowfish`, `cryptography`, `opencv-python`, `pillow`, `numpy`) are only discoverable by reading imports.
- **Fix:** pin dependencies explicitly (a `requirements.txt` or `pyproject.toml`) and add a `.gitignore` covering the runtime artifacts in §1.6.

---

## 2. Steganography-specific correctness notes

- `encode_image()` / `decode_image()` (`main.py:194-227`, `541-569`; duplicated near-identically in `image.py`) only embeds **1 bit** of the secret image per channel — specifically the secret pixel's own most-significant bit (`(secret_pixel[i] >> 7) & 1`) written into the cover pixel's least-significant bit. The "recovered" secret image on decode is therefore a crude 1-bit-per-channel (effectively black/white per channel) rendition of the original, not a faithful reconstruction — worth knowing before quoting any image-fidelity metric for the *secret* image specifically. A PSNR computed between the **cover** and **stego** image (not the secret and recovered-secret image) would look good, since only the LSB of each channel changes — but no PSNR calculation exists anywhere in this codebase today (confirmed by search), so any such figure would need to be computed and added, not assumed.
- Text steganography (`encode_text`/`decode_text`, `main.py:230-255, 403-419`, and the standalone `textstenography.py`) has a delimiter-based stop condition but no capacity check before encoding — a message longer than the cover image can hold will silently truncate or wrap rather than raising a clear "message too large for this image" error.

---

## 3. Modernization checklist (for a "hostable standard" rewrite)

- **Config/secrets:** move `SECRET_KEY`, DB path, and any crypto material to environment variables (`python-dotenv` locally, real env vars in hosting), with a `.env.example` committed instead of real values.
- **Data layer:** move off ad hoc `sqlite3.connect()` calls scattered per-route to a single connection pattern (Flask `g` + teardown, or SQLAlchemy), and replace the commented-out `CREATE TABLE` statements in `main.py`/`check.py` with real migrations (Alembic/Flask-Migrate) or at least a versioned `schema.sql`.
- **Auth:** hash passwords (§1.1), add a `@login_required` decorator (§1.8), add basic signup validation (email format, password strength, duplicate-email check — none currently exist).
- **Crypto:** collapse to one correct AEAD scheme (§1.5), stop committing keys to the database in plaintext without at minimum encrypting them at rest with a server-held master key, or reconsider the trust model entirely (e.g. envelope encryption).
- **Web hygiene:** CSRF protection, POST-only for state changes, secure cookie flags (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`), `MAX_CONTENT_LENGTH`, `secure_filename()` on all uploads.
- **Deployment:** run behind gunicorn/uwsgi + a reverse proxy, `debug=False` by default, HTTPS termination, structured logging instead of `print()`.
- **Repo hygiene:** `.gitignore` for runtime artifacts and databases, `requirements.txt`/`pyproject.toml` with pinned versions, removal (or clear quarantine) of `check.py`/`web.py`/`base.ipynb` from the deployable tree, and a decision on scrubbing git history before any public hosting given the committed secrets in §1.6.
- **Tests:** there are currently none. Given how much of the above involves behavior that's easy to silently break (crypto round-trips especially), adding tests alongside the rewrite — not after — is the difference between catching a regression here and shipping another silent failure like §1.4.
