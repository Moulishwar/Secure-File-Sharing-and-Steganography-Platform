"""Reed-Solomon protection for the capsule.

What this buys, measured rather than assumed: tolerance of *sparse* damage. On
a 1200x900 carrier, random LSB corruption that a v2 capsule survives at ~20
samples is survived by a v3 capsule at ~320 -- a 16x improvement. A pasted
16x16 patch goes from 1-in-10 to 10-in-10.

What it does NOT buy:

  * Surviving recompression. A JPEG round trip randomises roughly half the low
    bits in the image. No error correcting code reaches that far, and it is not
    a matter of adding more parity. The format discipline in images.py
    (lossless in, PNG out) remains the only thing between a payload and a chat
    app.
  * Surviving a visible edit. A 32x32 patch defeats the shipped configuration
    and a 48x48 patch defeats every parity level tested. The reason is
    structural: the body is spread over tens of thousands of carrier positions
    so that STC can steer around expensive ones, and that same spreading means
    a patch covering 0.1% of the image still catches dozens of them. Damage
    tolerance and steganographic undetectability pull against each other here,
    and this design deliberately favours the latter.

So: "a scuff survives, an edit does not."

Why it is needed at all: AEAD is deliberately all-or-nothing. One flipped bit
anywhere in the sealed body and AES-GCM's tag check fails, returning nothing.
That is exactly right for detecting tampering and exactly wrong for tolerating
a scuff. RS sits *below* the AEAD and repairs before verification, so:

    corruption within RS's reach   -> repaired, tag verifies, payload returned
    corruption beyond it           -> tag fails, nothing returned

Security is unchanged by this. The parity bytes are a deterministic function of
ciphertext, which is indistinguishable from random, so they leak nothing. An
attacker cannot steer what RS corrects to, because the AEAD tag still gates the
result -- a mis-correction fails closed rather than yielding chosen plaintext.
The real cost is size: a reference capsule grows from 104 to 152 bytes, which
is a larger footprint in the cover and therefore marginally more to detect.
"""

from __future__ import annotations

import math

from reedsolo import ReedSolomonError, RSCodec

__all__ = [
    "BODY_PARITY",
    "CHUNK",
    "HEADER_PARITY",
    "EccError",
    "body_correctable_per_chunk",
    "header_correctable",
    "protect_body",
    "protect_header",
    "protected_body_len",
    "protected_header_len",
    "recover_body",
    "recover_header",
]

# The header is the single point of failure -- lose it and the body length and
# salt go with it -- so it gets its own code even though it is only 28 bytes.
HEADER_PARITY = 16

# Per chunk of the body.
#
# Measured tolerance for a 104-byte reference capsule in a 1200x900 cover, as a
# solid patch pasted at a random position (10 trials each):
#
#   parity   capsule    16x16    32x32    48x48
#       32      152 B    10/10     2/10     0/10
#       64      184 B    10/10     6/10     0/10
#      128      248 B    10/10    10/10     0/10
#
# 32 is the default: it covers sparse damage at almost no cost in footprint.
# Higher parity buys one patch size for a much larger capsule, and the gain
# self-limits -- a bigger body occupies more carrier positions, so it catches
# more of any given patch. Nothing here reaches a visible edit; see the module
# docstring for what that means in practice.
BODY_PARITY = 32

# Data bytes per chunk. Derived, never hardcoded: a GF(256) block is 255
# symbols total, so the data half shrinks as parity grows. Pinning this to 223
# is correct only while parity is 32, and gets the encoded length silently
# wrong for any other value.
CHUNK = 255 - BODY_PARITY

_header_codec = RSCodec(HEADER_PARITY)
_body_codec = RSCodec(BODY_PARITY)


class EccError(Exception):
    """Damage exceeded what the code can repair."""


def header_correctable() -> int:
    """Byte errors repairable in the header. RS corrects parity/2 symbols."""
    return HEADER_PARITY // 2


def body_correctable_per_chunk() -> int:
    return BODY_PARITY // 2


def protected_header_len(header_len: int) -> int:
    return header_len + HEADER_PARITY


def protected_body_len(body_len: int) -> int:
    """Encoded size: each chunk carries its own parity."""
    if body_len <= 0:
        return 0
    return body_len + BODY_PARITY * math.ceil(body_len / CHUNK)


def protect_header(header: bytes) -> bytes:
    return bytes(_header_codec.encode(header))


def recover_header(block: bytes, header_len: int) -> tuple[bytes, int]:
    """Return (header, bytes repaired). Raises EccError past the limit."""
    return _decode(_header_codec, block, header_len)


def protect_body(body: bytes) -> bytes:
    if not body:
        return b""
    return bytes(_body_codec.encode(body))


def recover_body(block: bytes, body_len: int) -> tuple[bytes, int]:
    """Return (sealed body, bytes repaired). Raises EccError past the limit."""
    if body_len <= 0:
        return b"", 0
    return _decode(_body_codec, block, body_len)


def _decode(codec: RSCodec, block: bytes, expected_len: int) -> tuple[bytes, int]:
    try:
        decoded, _, errata = codec.decode(block)
    except (ReedSolomonError, ZeroDivisionError, IndexError) as exc:
        # reedsolo signals "beyond capacity" as ReedSolomonError, but malformed
        # input can surface as arithmetic or indexing failures deeper in. All of
        # them mean the same thing to us: this did not survive.
        raise EccError("Too much damage to repair.") from exc

    data = bytes(decoded)
    if len(data) != expected_len:
        raise EccError("Recovered block is the wrong length.")
    return data, len(errata)
