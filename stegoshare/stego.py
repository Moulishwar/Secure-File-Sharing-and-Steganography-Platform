"""Keyed LSB-matching embedding engine.

This replaces the legacy encode_image()/encode_text(), which failed three ways:
it was keyless (so the algorithm being public gave the payload away), it used
LSB *replacement* (whose even-up/odd-down asymmetry is exactly what RS analysis
and sample-pair analysis detect), and it embedded sequentially at a fixed rate.

What this does instead:

  * LSB matching (+/-1) rather than bit replacement, so pixel value parity is
    not driven in one direction and the classic parity attacks do not apply.
  * Positions chosen by a keyed CSPRNG, so the payload's *location* is secret
    even though this source file is public. Kerckhoffs, applied properly.
  * Boundary handling at 0 and 255 that keeps values in range without ever
    making a pixel's eligibility depend on its value -- which is what lets
    extraction reproduce the position set exactly.

Two body engines exist, selected by the capsule header's version byte:

  v1  keyed LSB matching at key-selected positions. Uniform: every position
      costs the same, so changes land wherever the keystream points -- including
      in smooth regions that have no noise to hide them.

  v2  HILL costs + syndrome trellis codes (the default). The key still selects
      *which* positions are candidates; STC then decides which of them to
      actually move, steering changes into texture. Costs the sender two carrier
      samples per payload bit and buys a large drop in embedding distortion.

The header itself is always LSB-matched at bootstrap positions, because it has
to be readable before its own version byte is known. It is 224 bits, so how it
is embedded barely matters.

Old carriers keep opening: extraction dispatches on the recorded version.
"""

from __future__ import annotations

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from PIL import Image

from . import capsule as cap
from . import stc
from .costs import hill_costs

__all__ = [
    "StegoError",
    "CapacityError",
    "capacity_bits",
    "required_bits",
    "embed_capsule",
    "extract_capsule",
]

# Leave headroom rather than filling the image. The safe-payload ceiling in the
# literature is ~5% of nominal capacity; we cap lower because inline mode is
# the exception and reference mode uses a rounding error of this budget.
SAFE_PAYLOAD_FRACTION = 0.05

# Carrier samples per payload bit under STC -- the trellis submatrix width.
#
# This is the knob that decides whether cost steering does anything. At width 2
# the code has two candidates per payload bit and can barely avoid an expensive
# sample; at width 32 it has thirty-two and will route changes into texture.
# Distortion falls roughly with width, and time rises linearly with it.
#
# Width is derived from payload size against the capacity budget, so a small
# capsule -- the common case, 104 bytes -- gets the widest, cheapest-per-bit
# code, while a large inline payload falls back toward 2 because the rate
# leaves no room. Both sides compute it identically from the header, so it
# needs no bytes on the wire.
MIN_STC_WIDTH = 2
MAX_STC_WIDTH = 32

# Ceiling on total trellis columns, so a large payload cannot make embedding
# take minutes. Time is roughly (columns x 2**height) elementary operations.
MAX_STC_COLUMNS = 400_000


def stc_width(body_bits: int, budget: int) -> int:
    """Submatrix width for a payload of `body_bits` against a capacity budget.

    A pure function of values both sides already know, so the sender and
    receiver always agree without transmitting it.
    """
    if body_bits <= 0:
        return MIN_STC_WIDTH
    by_capacity = budget // body_bits
    by_time = MAX_STC_COLUMNS // body_bits
    return max(MIN_STC_WIDTH, min(MAX_STC_WIDTH, by_capacity, by_time))


class StegoError(Exception):
    """Embedding or extraction failed."""


class CapacityError(StegoError):
    """The payload does not fit this cover at a safe embedding rate."""


# --------------------------------------------------------------------------
# keyed pseudorandom stream
# --------------------------------------------------------------------------


class _KeyStream:
    """ChaCha20 keystream as a deterministic byte source.

    Same key -> same bytes, on every platform and every run. That is what makes
    position selection reproducible between embed and extract.
    """

    _CHUNK = 1 << 16

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise StegoError("Stream key must be 32 bytes.")
        encryptor = Cipher(
            algorithms.ChaCha20(key, b"\x00" * 16), mode=None
        ).encryptor()
        self._encryptor = encryptor
        self._buf = bytearray()

    def take(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += self._encryptor.update(b"\x00" * self._CHUNK)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def uint64s(self, count: int) -> np.ndarray:
        return np.frombuffer(self.take(count * 8), dtype="<u8")

    def bits(self, count: int) -> np.ndarray:
        """One bit per returned element, as uint8 0/1."""
        nbytes = (count + 7) // 8
        return np.unpackbits(
            np.frombuffer(self.take(nbytes), dtype=np.uint8)
        )[:count]


def _select_positions(
    stream: _KeyStream, total: int, count: int, taken: np.ndarray
) -> np.ndarray:
    """Choose `count` distinct indices in [0, total) using the keystream.

    `taken` is a boolean mask of positions already used; it is updated in place
    so the body never collides with the header. Rejection sampling with an
    explicit modulo-bias guard, so the selection is defined by this function
    rather than by whatever algorithm a library version happens to use.
    """
    if count > total - int(taken.sum()):
        raise CapacityError("Not enough positions in this cover.")

    limit = (1 << 64) // total * total  # discard the biased tail
    chosen = np.empty(count, dtype=np.int64)
    filled = 0

    while filled < count:
        batch = max(count - filled, 1024)
        draws = stream.uint64s(int(batch * 1.4) + 16)
        idx = (draws[draws < limit] % total).astype(np.int64)
        if idx.size == 0:
            continue
        # Keep first occurrences only, and drop anything already used.
        idx = idx[~taken[idx]]
        if idx.size == 0:
            continue
        _, first = np.unique(idx, return_index=True)
        idx = idx[np.sort(first)]
        idx = idx[: count - filled]
        chosen[filled : filled + idx.size] = idx
        taken[idx] = True
        filled += idx.size

    return chosen


# --------------------------------------------------------------------------
# capacity
# --------------------------------------------------------------------------


def capacity_bits(image: Image.Image) -> int:
    """Bits embeddable at the safe rate. Nominal capacity is width*height*3."""
    width, height = image.size
    return int(width * height * 3 * SAFE_PAYLOAD_FRACTION)


def required_bits(payload_len: int) -> int:
    """Size of the capsule itself, in bits. Independent of the engine."""
    return (cap.HEADER_LEN + cap.BODY_OVERHEAD + payload_len) * 8


def carrier_samples(payload_len: int, version: int = cap.CURRENT_VERSION) -> int:
    """Minimum cover samples the engine needs -- what capacity is checked against.

    Under STC the body needs at least MIN_STC_WIDTH samples per bit; the actual
    width is chosen larger when the budget allows. The header is always
    LSB-matched and so needs one sample per bit.
    """
    body_bits = (cap.BODY_OVERHEAD + payload_len) * 8
    width = MIN_STC_WIDTH if version == cap.VERSION_STC else 1
    return cap.HEADER_LEN * 8 + body_bits * width


# --------------------------------------------------------------------------
# bit plumbing
# --------------------------------------------------------------------------


def _to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _from_bits(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def _write_bits(
    flat: np.ndarray, positions: np.ndarray, bits: np.ndarray, stream: _KeyStream
) -> None:
    """LSB matching: nudge each selected value by +/-1 only when parity differs.

    At 0 we must go up and at 255 we must go down; everywhere else the
    direction comes from the keystream, so the modification pattern carries no
    exploitable structure of its own.
    """
    values = flat[positions].astype(np.int16)
    mismatch = (values & 1) != bits
    if not mismatch.any():
        return

    signs = np.where(stream.bits(positions.size) == 1, 1, -1).astype(np.int16)
    signs[values == 0] = 1
    signs[values == 255] = -1

    values[mismatch] += signs[mismatch]
    flat[positions] = values.astype(np.uint8)


def _read_bits(flat: np.ndarray, positions: np.ndarray) -> np.ndarray:
    return (flat[positions] & 1).astype(np.uint8)


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------


def embed_capsule(
    cover: Image.Image,
    mode: int,
    payload: bytes,
    password: str,
    version: int = cap.CURRENT_VERSION,
) -> Image.Image:
    """Embed a capsule into a cover image and return the stego image.

    The caller is responsible for verifying the round trip before handing the
    result to anyone -- see pipeline._verify.
    """
    if cover.mode != "RGB":
        cover = cover.convert("RGB")
    width, height = cover.size

    salt = cap.new_salt()
    keys = cap.derive_keys(password, salt)
    body = cap.seal_body(payload, keys, mode, salt, version)
    header = cap.make_header(mode, salt, len(body), version)

    need = carrier_samples(len(payload), version)
    budget = capacity_bits(cover)
    if need > budget:
        raise CapacityError(
            f"This payload needs {need:,} carrier samples but the cover safely "
            f"holds {budget:,}. Use a larger image "
            f"(at least ~{_min_pixels(need):,} pixels) or a shorter message."
        )

    arr = np.asarray(cover, dtype=np.uint8).copy()
    flat = arr.reshape(-1)
    total = flat.size
    taken = np.zeros(total, dtype=bool)

    # Phase 1: the header, at positions only the password reveals.
    boot = _KeyStream(cap.bootstrap_key(password, width, height))
    header_pos = _select_positions(boot, total, cap.HEADER_LEN * 8, taken)
    _write_bits(flat, header_pos, _to_bits(header), boot)

    # Phase 2: the body, under the salted key schedule.
    body_stream = _KeyStream(keys.embed)
    body_bits = _to_bits(body)

    if version == cap.VERSION_STC:
        code_width = stc_width(len(body_bits), budget - cap.HEADER_LEN * 8)
        positions = _select_positions(
            body_stream, total, len(body_bits) * code_width, taken
        )
        # Costs come from the cover, and only the sender ever needs them.
        costs = hill_costs(arr).reshape(-1)[positions]
        submatrix = stc.make_submatrix(
            _KeyStream(keys.code).take(code_width * 16),
            code_width,
            stc.DEFAULT_HEIGHT,
        )
        target = stc.embed(
            (flat[positions] & 1).astype(np.uint8),
            costs,
            body_bits,
            submatrix,
            stc.DEFAULT_HEIGHT,
        )
        _write_bits(flat, positions, target, body_stream)
    else:
        positions = _select_positions(body_stream, total, len(body_bits), taken)
        _write_bits(flat, positions, body_bits, body_stream)

    return Image.fromarray(arr.reshape(height, width, 3), mode="RGB")


def extract_capsule(stego: Image.Image, password: str) -> tuple[int, bytes]:
    """Recover (mode, payload) from a stego image.

    Raises CapsuleError for every failure mode -- wrong password, no payload,
    truncated data, tampered bits -- with the same message, because
    distinguishing them would destroy the deniability the design exists for.
    """
    if stego.mode != "RGB":
        stego = stego.convert("RGB")
    width, height = stego.size

    arr = np.asarray(stego, dtype=np.uint8)
    flat = arr.reshape(-1)
    total = flat.size
    taken = np.zeros(total, dtype=bool)

    boot = _KeyStream(cap.bootstrap_key(password, width, height))
    header_pos = _select_positions(boot, total, cap.HEADER_LEN * 8, taken)
    header = _from_bits(_read_bits(flat, header_pos))

    version, mode, salt, body_len = cap.parse_header(header)
    body_bits = body_len * 8

    # Recomputed, not transmitted: the sender derived it from the same two
    # numbers we have here.
    if version == cap.VERSION_STC:
        code_width = stc_width(
            body_bits, capacity_bits(stego) - cap.HEADER_LEN * 8
        )
    else:
        code_width = 1

    if body_bits * code_width > total - header_pos.size:
        raise cap.CapsuleError("Capsule failed authentication.")

    keys = cap.derive_keys(password, salt)
    body_stream = _KeyStream(keys.embed)
    positions = _select_positions(body_stream, total, body_bits * code_width, taken)
    carried = _read_bits(flat, positions)

    if version == cap.VERSION_STC:
        # Extraction is a syndrome multiply: no costs, no cover, no knowledge
        # of which samples moved.
        submatrix = stc.make_submatrix(
            _KeyStream(keys.code).take(code_width * 16),
            code_width,
            stc.DEFAULT_HEIGHT,
        )
        try:
            recovered = stc.extract(carried, submatrix, body_bits)
        except stc.StcError as exc:
            raise cap.CapsuleError("Capsule failed authentication.") from exc
    else:
        recovered = carried

    body = _from_bits(recovered)
    return mode, cap.open_body(body, keys, mode, salt, version)


def _min_pixels(need_bits: int) -> int:
    """Smallest pixel count whose safe budget covers `need_bits`."""
    return int(np.ceil(need_bits / (3 * SAFE_PAYLOAD_FRACTION)))
