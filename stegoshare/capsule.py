"""The capsule: the only structure the embedding engine ever sees.

Everything above this layer treats a capsule as opaque bytes; everything below
treats it as an incompressible random string. That separation is what lets the
embedding algorithm be swapped later (keyed LSB matching now, STC later)
without touching the cryptography.

    capsule := header || body

    header (28 bytes, not encrypted -- the salt and body length are needed
            before any key can be derived, so they cannot sit behind a key)
        magic    4   b"STGC"
        version  1
        mode     1   0x01 reference | 0x02 inline
        flags    2   reserved, must be zero
        body_len 4   uint32 big-endian, length of the sealed body
        salt    16   random per share, never reused across images

    body (AEAD, key derived from password + salt)
        nonce   12
        payload  n   reference: share_id(16) || share_secret(32) = 48 bytes
                     inline:    the message or file bytes themselves
        tag     16

Reference-mode capsules are 104 bytes total. In a 12 MP cover that is under
0.003% of nominal capacity -- roughly one changed pixel in thirty thousand.

The header is plaintext but not *findable*: its embedding positions come from a
bootstrap key derived from the password and the image dimensions, so an
observer without the password does not know where to look. With the wrong
password, extraction yields bytes that fail the AEAD tag and are
indistinguishable from image noise -- there is no error that separates "wrong
password" from "no payload here", which is what makes deniability real.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import InvalidTag, seal, unseal

__all__ = [
    "BODY_OVERHEAD",
    "CapsuleError",
    "HEADER_LEN",
    "MODE_INLINE",
    "MODE_REFERENCE",
    "REFERENCE_PAYLOAD_LEN",
    "KeySchedule",
    "bootstrap_key",
    "derive_keys",
    "make_header",
    "new_salt",
    "new_share_secret",
    "open_body",
    "parse_header",
    "parse_reference_payload",
    "reference_payload",
    "seal_body",
    "secret_digest",
]

MAGIC = b"STGC"
VERSION = 1
HEADER_LEN = 28
SALT_LEN = 16
MAX_BODY_LEN = 0xFFFFFFFF

MODE_REFERENCE = 0x01
MODE_INLINE = 0x02
_MODES = {MODE_REFERENCE, MODE_INLINE}

SHARE_SECRET_LEN = 32
REFERENCE_PAYLOAD_LEN = 16 + SHARE_SECRET_LEN  # uuid bytes + secret

# What seal() adds to a payload: 12-byte nonce + 16-byte tag.
BODY_OVERHEAD = 28

# OWASP Password Storage Cheat Sheet minimum for Argon2id.
_ARGON2_MEMORY_KIB = 19456
_ARGON2_TIME = 2
_ARGON2_LANES = 1


class CapsuleError(Exception):
    """A capsule is malformed, the wrong version, or fails authentication."""


@dataclass(frozen=True, slots=True)
class KeySchedule:
    """Keys derived from one password and one salt. Never reused across images."""

    embed: bytes    # drives the pseudorandom position permutation
    payload: bytes  # AEAD key over the capsule body


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def new_share_secret() -> bytes:
    """A capability token carried by the image and stored only as a digest."""
    return os.urandom(SHARE_SECRET_LEN)


def secret_digest(secret: bytes) -> bytes:
    """What the server stores. Possession of the image proves the preimage."""
    return hashlib.sha256(b"stegoshare/share-secret/v1" + secret).digest()


# --------------------------------------------------------------------------
# key derivation
# --------------------------------------------------------------------------


def bootstrap_key(password: str, width: int, height: int) -> bytes:
    """Locate the header without knowing the salt.

    Deliberately cheap: this only decides *where* the 24-byte header sits. It
    protects nothing on its own -- the body is behind Argon2id and an AEAD tag.
    Binding it to the image dimensions keeps two different covers from placing
    their headers identically under the same password.
    """
    return hashlib.sha256(
        b"stegoshare/bootstrap/v1|"
        + f"{width}x{height}|".encode()
        + password.encode("utf-8")
    ).digest()


def derive_keys(password: str, salt: bytes) -> KeySchedule:
    """Argon2id to a root secret, then HKDF into two non-overlapping keys."""
    if len(salt) != SALT_LEN:
        raise CapsuleError(f"Salt must be {SALT_LEN} bytes.")
    root = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=_ARGON2_TIME,
        memory_cost=_ARGON2_MEMORY_KIB,
        parallelism=_ARGON2_LANES,
        hash_len=32,
        type=Type.ID,
    )
    return KeySchedule(
        embed=_hkdf(root, b"stegoshare/stego-position-v1"),
        payload=_hkdf(root, b"stegoshare/stego-payload-v1"),
    )


def _hkdf(root: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(root)


# --------------------------------------------------------------------------
# header
# --------------------------------------------------------------------------


def make_header(mode: int, salt: bytes, body_len: int) -> bytes:
    if mode not in _MODES:
        raise CapsuleError(f"Unknown capsule mode {mode:#04x}.")
    if len(salt) != SALT_LEN:
        raise CapsuleError(f"Salt must be {SALT_LEN} bytes.")
    if not 0 <= body_len <= MAX_BODY_LEN:
        raise CapsuleError("Body length out of range.")
    header = (
        MAGIC
        + bytes([VERSION, mode])
        + b"\x00\x00"
        + body_len.to_bytes(4, "big")
        + salt
    )
    assert len(header) == HEADER_LEN, "header length drifted from HEADER_LEN"
    return header


def parse_header(raw: bytes) -> tuple[int, bytes, int]:
    """Return (mode, salt, body_len). Raises CapsuleError on anything unexpected.

    Callers must treat this failing as "no payload found", never as a signal
    that the password was wrong -- the two are intentionally indistinguishable
    from outside.
    """
    if len(raw) != HEADER_LEN:
        raise CapsuleError("Header is the wrong length.")
    if raw[:4] != MAGIC:
        raise CapsuleError("No capsule here.")
    version, mode = raw[4], raw[5]
    if version != VERSION:
        raise CapsuleError(f"Unsupported capsule version {version}.")
    if mode not in _MODES:
        raise CapsuleError(f"Unknown capsule mode {mode:#04x}.")
    if raw[6:8] != b"\x00\x00":
        raise CapsuleError("Reserved flags are not zero.")
    body_len = int.from_bytes(raw[8:12], "big")
    return mode, raw[12:28], body_len


# --------------------------------------------------------------------------
# body
# --------------------------------------------------------------------------


def _body_aad(mode: int, salt: bytes) -> bytes:
    """Bind the body to its own header, so a body cannot be replayed under another."""
    return b"stegoshare/capsule-body/v1|" + bytes([VERSION, mode]) + salt


def seal_body(payload: bytes, keys: KeySchedule, mode: int, salt: bytes) -> bytes:
    return seal(payload, keys.payload, _body_aad(mode, salt))


def open_body(body: bytes, keys: KeySchedule, mode: int, salt: bytes) -> bytes:
    try:
        return unseal(body, keys.payload, _body_aad(mode, salt))
    except InvalidTag as exc:
        raise CapsuleError("Capsule failed authentication.") from exc


# --------------------------------------------------------------------------
# reference-mode payload
# --------------------------------------------------------------------------


def reference_payload(share_public_id: str, secret: bytes) -> bytes:
    """Pack the locator and capability token carried by a reference capsule."""
    if len(secret) != SHARE_SECRET_LEN:
        raise CapsuleError(f"Share secret must be {SHARE_SECRET_LEN} bytes.")
    return uuid.UUID(share_public_id).bytes + secret


def parse_reference_payload(raw: bytes) -> tuple[str, bytes]:
    if len(raw) != REFERENCE_PAYLOAD_LEN:
        raise CapsuleError("Reference payload is the wrong length.")
    return str(uuid.UUID(bytes=raw[:16])), raw[16:]
