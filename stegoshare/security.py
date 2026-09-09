"""Authentication and authorization.

This is the layer the legacy app did not have. Its approval workflow lived
entirely in Jinja conditionals: /decrypt never read the requests table, and
/textdecrypt had no ownership filter at all, so any logged-in user could open
any other user's payload by editing a number in the URL.

The rule here is that **authorization and key retrieval are the same query**.
There is no code path that returns key material without having proved the
grant, because the grant row *is* where the key material lives -- and it stays
NULL until the approval threshold is met.
"""

from __future__ import annotations

import hmac
import sqlite3
from functools import wraps
from typing import Any, Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import abort, current_app, redirect, request, session, url_for

from .capsule import secret_digest
from .crypto import InvalidTag, unwrap_dek
from .db import get_db

__all__ = [
    "MIN_PASSWORD_LENGTH",
    "audit",
    "current_user",
    "current_user_id",
    "hash_password",
    "login_required",
    "needs_rehash",
    "open_share",
    "verify_password",
]

MIN_PASSWORD_LENGTH = 12

# OWASP Password Storage Cheat Sheet, Argon2id minimum configuration:
# m=19456 KiB, t=2, p=1.
_hasher = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)

# Verified against on the user-not-found path so that response latency does not
# reveal which email addresses have accounts.
_DUMMY_HASH = _hasher.hash("timing-equalizer-not-a-real-password")


# --------------------------------------------------------------------------
# passwords
# --------------------------------------------------------------------------


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-ish time regardless of whether the account exists."""
    try:
        _hasher.verify(stored_hash or _DUMMY_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return stored_hash is not None


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------


def current_user_id() -> int | None:
    value = session.get("uid")
    return int(value) if value is not None else None


def current_user() -> sqlite3.Row | None:
    uid = current_user_id()
    if uid is None:
        return None
    return get_db().execute(
        "SELECT id, email, display_name FROM users WHERE id = ?", (uid,)
    ).fetchone()


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    """Redirect to login instead of raising KeyError on session['user'].

    Nine routes in the legacy app read session["user"] with no check, so any
    request while logged out produced an unhandled 500 -- and with debug=True,
    an interactive Werkzeug console.
    """

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if current_user_id() is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# the authorization gate
# --------------------------------------------------------------------------


def open_share(
    share_public_id: str, user_id: int, presented_secret: bytes
) -> tuple[sqlite3.Row, bytes]:
    """Return (share row, data key) for a user entitled to open this share.

    Aborts 403 unless *all* of the following hold:

      1. A grant row exists for this (share, recipient).
      2. That grant's wrapped_dek is not NULL -- i.e. the approval threshold
         was met and the approve handler wrote key material for this user.
      3. The secret carried inside the stego image matches the digest stored
         for the share, proving the caller actually holds the image.
      4. The wrapped key unwraps under associated data naming this exact
         share and this exact user, so a grant row copied from elsewhere fails.

    Every failure returns the same 403. Which of the four conditions failed is
    not disclosed.
    """
    row = get_db().execute(
        """
        SELECT s.id, s.public_id, s.owner_id, s.mode, s.kind, s.display_name,
               s.content_type, s.byte_size, s.object_key, s.secret_digest,
               g.wrapped_dek
        FROM   shares s
        JOIN   grants g ON g.share_id = s.id AND g.recipient_id = ?
        WHERE  s.public_id = ? AND g.wrapped_dek IS NOT NULL
        """,
        (user_id, share_public_id),
    ).fetchone()

    if row is None:
        abort(403)

    if not hmac.compare_digest(
        bytes(row["secret_digest"]), secret_digest(presented_secret)
    ):
        abort(403)

    kek = current_app.config["STEGOSHARE"].FILE_KEK
    try:
        dek = unwrap_dek(bytes(row["wrapped_dek"]), kek, share_public_id, user_id)
    except InvalidTag:
        abort(403)

    return row, dek


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------


def audit(
    action: str, share_id: int | None = None, detail: str | None = None
) -> None:
    """Record who did what. Never called with key material in `detail`."""
    get_db().execute(
        "INSERT INTO audit_log (actor_id, action, share_id, detail, ip) "
        "VALUES (?, ?, ?, ?, ?)",
        (current_user_id(), action, share_id, detail, request.remote_addr),
    )
