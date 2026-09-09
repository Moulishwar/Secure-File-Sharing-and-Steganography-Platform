"""Object storage for ciphertext.

Nothing user-supplied and nothing decrypted is ever written under static/. The
legacy app wrote decrypted plaintext to static/decrypt/ and served it through
Flask's unauthenticated static route, which made every decrypted file public to
anyone who could guess a filename.

Local disk backing today, S3/MinIO later. Both satisfy the same three methods,
so switching is a config change. Object keys are server-generated UUIDs and are
validated on every call -- a key never comes from user input, and this refuses
to act on one that looks like it did.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Protocol

__all__ = ["Storage", "LocalStorage", "ObjectKeyError", "new_object_key"]


class ObjectKeyError(ValueError):
    """An object key is not a well-formed UUID."""


def new_object_key() -> str:
    return uuid.uuid4().hex


def _validate(key: str) -> str:
    """Reject anything that is not a bare UUID hex string.

    This is what makes path traversal structurally impossible rather than
    filtered: a key that is not 32 hex characters never reaches the filesystem.
    """
    try:
        uuid.UUID(hex=key)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ObjectKeyError("Malformed object key.") from exc
    if len(key) != 32 or not key.isalnum():
        raise ObjectKeyError("Malformed object key.")
    return key


class Storage(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...


class LocalStorage:
    """Filesystem backend for local development.

    Files are fanned out one level by key prefix so a directory listing stays
    manageable, and the stored bytes are always ciphertext.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        key = _validate(key)
        return self.root / key[:2] / key

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename so a crash cannot leave a truncated object.
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not path.is_file():
            raise FileNotFoundError(f"No object {key}.")
        return path.read_bytes()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)
