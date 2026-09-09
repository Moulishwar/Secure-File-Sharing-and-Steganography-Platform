"""Syndrome Trellis Codes (Filler, Judas & Fridrich, 2011).

The problem adaptive embedding poses: we want to change the *cheapest* samples,
but the receiver cannot recompute costs -- it only has the stego image, whose
costs differ from the cover's. Any scheme where the receiver must agree with the
sender about which samples were eligible is therefore broken from the start.

STC resolves this by separating the two directions completely:

    embedding   a Viterbi search for the stego vector y minimising
                sum(rho_i) over the samples where y_i != x_i, subject to Hy = m
    extraction  m = Hy, a parity-check multiply -- no costs, no cover, no
                knowledge of which samples moved

So costs steer the sender only, and extraction stays a pure function of the
stego bits and the key. That asymmetry is the entire reason this module exists.

H is built by tiling a small h x w submatrix down the diagonal. The submatrix
comes from the keystream, so the code itself is keyed: an attacker who knows
this file still does not know the parity checks.

Work is done in independent blocks so memory stays bounded regardless of payload
size -- the trellis for a whole 200 KB payload at once would need hundreds of
megabytes of backtrack state.
"""

from __future__ import annotations

import numpy as np

__all__ = ["DEFAULT_HEIGHT", "StcError", "make_submatrix", "embed", "extract"]

# Trellis constraint height. 2**h states, so this trades quality against time
# and memory. The paper shows returns flattening around 10; 9 keeps the
# backtrack table small enough to stay comfortable on a laptop.
DEFAULT_HEIGHT = 9

# Message bits per independent trellis block.
BLOCK_BITS = 4096

_INF = np.inf


class StcError(Exception):
    """The payload does not fit the trellis parameters given."""


def make_submatrix(random_bytes: bytes, width: int, height: int) -> np.ndarray:
    """Derive the h x w parity submatrix, one integer column per element.

    Each column has its low bit and its top bit set, which is what keeps the
    trellis fully connected -- without the top bit whole state ranges become
    unreachable and the search silently degrades.
    """
    top = 1 << (height - 1)
    # Every valid column, enumerated: the low and top bits are forced, so the
    # freedom is the h-2 bits between them.
    candidates = [top | 1 | (middle << 1) for middle in range(1 << (height - 2))]
    if width > len(candidates):
        raise StcError(
            f"Width {width} exceeds the {len(candidates)} distinct columns "
            f"available at height {height}."
        )
    if len(random_bytes) < width * 4:
        raise StcError("Not enough key material for the submatrix.")

    # Partial Fisher-Yates driven by the key. Selecting by permutation rather
    # than by rejection sampling means distinctness is structural: it cannot
    # fail or loop, even if the caller hands us low-entropy bytes.
    draws = np.frombuffer(random_bytes[: width * 4], dtype="<u4")
    for i in range(width):
        j = i + int(draws[i]) % (len(candidates) - i)
        candidates[i], candidates[j] = candidates[j], candidates[i]

    return np.array(candidates[:width], dtype=np.int64)


def _blocks(total_bits: int) -> list[tuple[int, int]]:
    return [
        (start, min(start + BLOCK_BITS, total_bits))
        for start in range(0, total_bits, BLOCK_BITS)
    ]


def embed(
    cover_bits: np.ndarray,
    costs: np.ndarray,
    message_bits: np.ndarray,
    submatrix: np.ndarray,
    height: int = DEFAULT_HEIGHT,
) -> np.ndarray:
    """Return stego bits y with Hy = m, minimising the cost of the changes.

    cover_bits and costs are parallel arrays over the selected carrier
    positions. len(cover_bits) must be an exact multiple of len(message_bits).
    """
    width = len(submatrix)
    if len(cover_bits) != len(message_bits) * width:
        raise StcError(
            f"Need exactly {width} carrier samples per message bit, "
            f"got {len(cover_bits)} for {len(message_bits)} bits."
        )

    stego = cover_bits.copy()
    for start, stop in _blocks(len(message_bits)):
        lo, hi = start * width, stop * width
        stego[lo:hi] = _embed_block(
            cover_bits[lo:hi], costs[lo:hi], message_bits[start:stop],
            submatrix, height,
        )
    return stego


def _embed_block(
    cover: np.ndarray,
    costs: np.ndarray,
    message: np.ndarray,
    submatrix: np.ndarray,
    height: int,
) -> np.ndarray:
    states = 1 << height
    half = states >> 1
    width = len(submatrix)
    columns = len(cover)

    # k ^ submatrix[j] as a gather index, precomputed once per column position.
    indices = np.arange(states, dtype=np.int64)
    permutations = [indices ^ int(col) for col in submatrix]

    # Backtrack table: one bit per (column, state), packed to keep a long
    # payload from turning into hundreds of megabytes.
    taken = np.zeros((columns, states // 8), dtype=np.uint8)

    weights = np.full(states, _INF, dtype=np.float64)
    weights[0] = 0.0

    position = 0
    for bit_index in range(len(message)):
        for j in range(width):
            bit = cover[position]
            cost = costs[position]
            # Two choices for the stego bit at this position. Cost is paid only
            # when the chosen value differs from the cover -- note this is the
            # chosen *value*, not "did we flip": picking one over a cover bit
            # that is already one is free.
            choose_zero = weights + (cost if bit else 0.0)
            choose_one = weights[permutations[j]] + (0.0 if bit else cost)

            picked_one = choose_one < choose_zero
            taken[position] = np.packbits(picked_one)
            weights = np.where(picked_one, choose_one, choose_zero)
            position += 1

        # The syndrome bit for this message bit is now fixed: keep only the
        # states whose low bit matches it, then shift the register down.
        weights = weights[2 * np.arange(half, dtype=np.int64) + int(message[bit_index])]
        weights = np.concatenate([weights, np.full(half, _INF)])

    # The trailing rows of H are truncated away, so whatever remains in the
    # shift register at the end is unconstrained -- the cheapest surviving
    # state is the terminal one, not necessarily zero.
    terminal = int(np.argmin(weights))
    if not np.isfinite(weights[terminal]):
        raise StcError("No valid trellis path; the cover cannot carry this payload.")

    # Backtrack, undoing the shift at each message bit.
    stego = np.empty_like(cover)
    state = terminal
    position = len(cover) - 1
    for bit_index in range(len(message) - 1, -1, -1):
        state = (state << 1) | int(message[bit_index])
        for j in range(width - 1, -1, -1):
            byte = taken[position, state >> 3]
            # packbits is MSB-first within each byte.
            picked_one = (byte >> (7 - (state & 7))) & 1
            stego[position] = picked_one
            if picked_one:
                state ^= int(submatrix[j])
            position -= 1

    return stego


def extract(
    stego_bits: np.ndarray, submatrix: np.ndarray, message_length: int
) -> np.ndarray:
    """Recover the message: m = H y.

    Vectorised over message bits -- there is no sequential dependency here,
    unlike embedding, because each block of `width` samples contributes its
    XOR-fold independently and the running state is just a shift register.
    """
    width = len(submatrix)
    expected = message_length * width
    if len(stego_bits) < expected:
        raise StcError("Stego vector is shorter than the declared message.")

    bits = stego_bits[:expected].reshape(message_length, width).astype(np.int64)
    # Contribution of each group: XOR of the submatrix columns where y is 1.
    folded = np.zeros(message_length, dtype=np.int64)
    for j in range(width):
        folded ^= np.where(bits[:, j] == 1, int(submatrix[j]), 0)

    # The shift register: state ^= folded_i, emit the low bit, shift down.
    # It restarts at each block boundary, because embedding runs an independent
    # trellis per block to keep backtrack memory bounded -- so the register
    # cannot carry across the seam.
    message = np.empty(message_length, dtype=np.uint8)
    for start, stop in _blocks(message_length):
        state = 0
        for i in range(start, stop):
            state ^= int(folded[i])
            message[i] = state & 1
            state >>= 1
    return message
