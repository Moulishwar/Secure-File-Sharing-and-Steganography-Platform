"""HILL cost model: where an image can absorb a change without showing it.

Changing a pixel in a smooth region -- clear sky, a flat wall -- perturbs local
statistics far more than changing one in foliage or fabric. Uniform embedding
spends the same budget everywhere and so wastes it exactly where there is none
to spend. A cost model says where the noise floor already hides a +/-1.

HILL (Li, Wang, Huang, Li 2014) is:

    rho = 1 / ( |X * K| * L1 * L2 )

    K  = the KB high-pass filter, which responds to local non-smoothness
    L1 = 3x3 averaging, spreading each response to its neighbours
    L2 = 15x15 averaging, so changes clump together in already-busy areas
         rather than scattering one per texture edge

Low rho means cheap to change. HILL is chosen over S-UNIWARD because it costs a
few convolutions rather than a full wavelet decomposition, and the published
detection results are within noise of each other.

Nothing here is needed to *extract* a payload -- costs only steer the embedder's
choice among the positions the key already selected. That asymmetry is what
makes adaptive embedding compatible with reproducible extraction.
"""

from __future__ import annotations

import numpy as np

__all__ = ["WET", "hill_costs"]

# The KB (Ker-Boehme) high-pass kernel.
_KB = np.array(
    [[-1.0, 2.0, -1.0],
     [ 2.0, -4.0, 2.0],
     [-1.0, 2.0, -1.0]]
)

# "Wet" cost: a position the embedder must never flip. Used for the padding at
# the tail of the final STC block, which maps to no real cover sample.
#
# Note that saturated samples are NOT wet here. Under binary LSB matching a 0
# can go to 1 and a 255 to 254 -- only the direction is forced, and both stay in
# range. They are merely expensive, which HILL already reflects, because
# saturated regions are smooth and smooth regions score high.
WET = 1e13

# Floor on the denominator, so a perfectly flat region yields a large finite
# cost rather than a division by zero.
_EPS = 1e-10


def _box_blur(plane: np.ndarray, size: int) -> np.ndarray:
    """Separable box filter via cumulative sums -- O(n) per axis, no scipy."""
    out = plane
    for axis in (0, 1):
        pad = size // 2
        width = [(0, 0), (0, 0)]
        width[axis] = (pad, pad)
        padded = np.pad(out, width, mode="symmetric")

        cumulative = np.cumsum(padded, axis=axis, dtype=np.float64)
        zero_shape = list(cumulative.shape)
        zero_shape[axis] = 1
        cumulative = np.concatenate(
            [np.zeros(zero_shape, dtype=np.float64), cumulative], axis=axis
        )

        length = out.shape[axis]
        upper = np.take(cumulative, np.arange(size, size + length), axis=axis)
        lower = np.take(cumulative, np.arange(0, length), axis=axis)
        out = (upper - lower) / size
    return out


def _high_pass(plane: np.ndarray) -> np.ndarray:
    """Convolve with the 3x3 KB kernel using shifted slices."""
    padded = np.pad(plane, 1, mode="symmetric")
    response = np.zeros_like(plane, dtype=np.float64)
    for dy in range(3):
        for dx in range(3):
            weight = _KB[dy, dx]
            if weight:
                response += weight * padded[
                    dy : dy + plane.shape[0], dx : dx + plane.shape[1]
                ]
    return response


def hill_costs(image: np.ndarray) -> np.ndarray:
    """Per-sample embedding costs for an HxWx3 uint8 image.

    Returns a float64 array of the same shape: low where the image is busy
    enough to hide a change, high where it is smooth.
    """
    if image.ndim != 3 or image.shape[2] != 3:
        raise ValueError("Expected an HxWx3 image.")

    costs = np.empty(image.shape, dtype=np.float64)
    for channel in range(3):
        plane = image[:, :, channel].astype(np.float64)
        residual = np.abs(_high_pass(plane))
        spread = _box_blur(_box_blur(residual, 3), 15)
        costs[:, :, channel] = 1.0 / (spread + _EPS)

    # Keep finite so the trellis arithmetic stays well-behaved.
    np.clip(costs, 0.0, WET / 2, out=costs)
    return costs
