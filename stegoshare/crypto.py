"""Envelope encryption. One AEAD, one key per share, no layering.

Replaces the legacy Blowfish path (ECB-equivalent, null-padded, unauthenticated)
and the dead ChaCha20 wrapper that generated a fresh key on both the encrypt and
decrypt side and so could never round-trip.

Two levels:

    content   sealed under a per-share DEK (data encryption key)
    DEK       sealed under the KEK (key encryption key) from the environment

The DEK is wrapped once per recipient, with associated data binding it to that
(share, recipient) pair. A wrapped DEK copied out of one grant row and into
another fails to unwrap -- so a database write vulnerability degrades to a
decryption failure instead of a data breach.

Rotating the KEK means re-wrapping every grants.wrapped_dek. It never requires
touching the content ciphertext, which is the operational point of the design.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "InvalidTag",
    "NONCE_LEN",
    "new_dek",
    "seal",
    "unseal",
    "content_aad",
    "wrap_dek",
    "unwrap_dek",
]

# AES-GCM's standard nonce length. 96 bits is the only size with a security
# proof for the standard construction; do not make this configurable.
NONCE_LEN = 12


def new_dek() -> bytes:
    """A fresh 256-bit data key from the OS CSPRNG.

    The legacy code used random.choice() over an alphanumeric alphabet -- the
    Mersenne Twister, whose internal state is recoverable from its output.
    """
    return AESGCM.generate_key(bit_length=256)


def seal(plaintext: bytes, key: bytes, aad: bytes) -> bytes:
    """Encrypt and authenticate. Returns nonce || ciphertext || tag."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(blob: bytes, key: bytes, aad: bytes) -> bytes:
    """Verify and decrypt a blob produced by seal().

    Raises InvalidTag if the key is wrong, the associated data does not match,
    or a single bit of the ciphertext has been altered. There is no partial
    result and no way to get plaintext out of a failed authentication.
    """
    if len(blob) < NONCE_LEN + 16:
        raise InvalidTag("Ciphertext is too short to be well-formed.")
    return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)


def content_aad(share_public_id: str) -> bytes:
    """Associated data binding a ciphertext to the share it belongs to."""
    return f"stegoshare/content/v1|share:{share_public_id}".encode()


def _dek_aad(share_public_id: str, recipient_id: int) -> bytes:
    """Associated data binding a wrapped DEK to one (share, recipient) pair."""
    return (
        f"stegoshare/dek/v1|share:{share_public_id}|user:{recipient_id}".encode()
    )


def wrap_dek(dek: bytes, kek: bytes, share_public_id: str, recipient_id: int) -> bytes:
    """Wrap a data key for one recipient of one share."""
    return seal(dek, kek, _dek_aad(share_public_id, recipient_id))


def unwrap_dek(
    wrapped: bytes, kek: bytes, share_public_id: str, recipient_id: int
) -> bytes:
    """Recover a data key. Raises InvalidTag if the binding does not match."""
    return unseal(wrapped, kek, _dek_aad(share_public_id, recipient_id))
