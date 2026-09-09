"""Envelope encryption.

The legacy app shipped a ChaCha20 layer that generated a fresh random key on
both the encrypt and the decrypt side, wrapped in `except: pass`. It could
never round-trip, and nothing ever noticed. These are the tests that notice.
"""

import pytest

from stegoshare.crypto import (
    InvalidTag,
    content_aad,
    new_dek,
    seal,
    unseal,
    unwrap_dek,
    wrap_dek,
)

SHARE = "6f1c8a3e-0d2b-4c9a-9f11-2b7e5a4d3c88"
OTHER_SHARE = "11111111-2222-3333-4444-555555555555"


def test_content_round_trips(kek):
    dek = new_dek()
    plaintext = b"the quick brown fox" * 100
    blob = seal(plaintext, dek, content_aad(SHARE))
    assert unseal(blob, dek, content_aad(SHARE)) == plaintext


def test_ciphertext_is_not_the_plaintext():
    dek = new_dek()
    plaintext = b"A" * 64
    assert plaintext not in seal(plaintext, dek, b"aad")


def test_every_dek_is_distinct():
    keys = {new_dek() for _ in range(200)}
    assert len(keys) == 200, "key generation is not drawing from a CSPRNG"


def test_nonce_is_fresh_per_encryption():
    dek = new_dek()
    first = seal(b"same plaintext", dek, b"aad")
    second = seal(b"same plaintext", dek, b"aad")
    assert first != second, "nonce reuse: identical plaintexts produced identical output"


def test_tampering_is_detected():
    dek = new_dek()
    blob = bytearray(seal(b"important", dek, b"aad"))
    blob[-1] ^= 0x01  # flip one bit of the tag
    with pytest.raises(InvalidTag):
        unseal(bytes(blob), dek, b"aad")


def test_flipped_ciphertext_byte_is_detected():
    dek = new_dek()
    blob = bytearray(seal(b"important payload here", dek, b"aad"))
    blob[20] ^= 0x80
    with pytest.raises(InvalidTag):
        unseal(bytes(blob), dek, b"aad")


def test_wrong_key_fails_closed():
    blob = seal(b"secret", new_dek(), b"aad")
    with pytest.raises(InvalidTag):
        unseal(blob, new_dek(), b"aad")


def test_truncated_blob_is_rejected():
    dek = new_dek()
    with pytest.raises(InvalidTag):
        unseal(seal(b"x", dek, b"aad")[:10], dek, b"aad")


def test_wrapped_dek_round_trips(kek):
    dek = new_dek()
    wrapped = wrap_dek(dek, kek, SHARE, recipient_id=42)
    assert unwrap_dek(wrapped, kek, SHARE, recipient_id=42) == dek


def test_wrapped_dek_cannot_be_moved_to_another_recipient(kek):
    """A grant row copied onto a different user must not unwrap."""
    wrapped = wrap_dek(new_dek(), kek, SHARE, recipient_id=42)
    with pytest.raises(InvalidTag):
        unwrap_dek(wrapped, kek, SHARE, recipient_id=43)


def test_wrapped_dek_cannot_be_moved_to_another_share(kek):
    wrapped = wrap_dek(new_dek(), kek, SHARE, recipient_id=42)
    with pytest.raises(InvalidTag):
        unwrap_dek(wrapped, kek, OTHER_SHARE, recipient_id=42)


def test_content_aad_binds_to_its_share():
    dek = new_dek()
    blob = seal(b"payload", dek, content_aad(SHARE))
    with pytest.raises(InvalidTag):
        unseal(blob, dek, content_aad(OTHER_SHARE))
