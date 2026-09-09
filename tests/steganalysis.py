"""Steganalysis used as a build gate.

Aletheia is the tool the literature points at, but it is not installable from
PyPI, so this implements the classical attack it would run first. That is
enough to answer the question a CI gate should ask: *does our own output look
embedded to the attacks that broke the technique we replaced?*

The chi-square attack (Westfeld & Pfitzmann, 2000) targets LSB replacement.
Replacement moves a sample between the two members of a "pair of values"
(2i, 2i+1) and never outside it, so as the payload rate rises the two
frequencies converge. Natural images have no reason to show that symmetry, so
convergence is the signal.

The statistic below is chi-square per degree of freedom over those pairs:

    high  -> pair frequencies are far apart, as in an untouched image
    ~0    -> pair frequencies have equalised, the replacement signature

We report the raw ratio rather than a p-value so the gate needs no incomplete
gamma function; discrimination is what matters here, not calibration.
"""

from __future__ import annotations

import numpy as np

__all__ = ["chi_square_ratio", "embed_lsb_replacement"]


def chi_square_ratio(image: np.ndarray, min_expected: float = 8.0) -> float:
    """Chi-square per degree of freedom over pairs of values.

    Near zero means the pair frequencies have equalised -- the LSB-replacement
    signature. Large means they have not.
    """
    counts = np.bincount(np.asarray(image, dtype=np.uint8).reshape(-1), minlength=256)
    even = counts[0::2].astype(np.float64)
    odd = counts[1::2].astype(np.float64)

    expected = (even + odd) / 2.0
    usable = expected >= min_expected
    if usable.sum() < 2:
        raise ValueError("Too few populated pairs of values to test.")

    chi_square = np.sum((even[usable] - expected[usable]) ** 2 / expected[usable])
    return float(chi_square / (usable.sum() - 1))


def embed_lsb_replacement(
    image: np.ndarray, payload_bits: np.ndarray, seed: int = 0
) -> np.ndarray:
    """The technique this project replaced, for use as a positive control.

    Overwrites the low bit of randomly chosen samples. A detector that cannot
    flag this is not measuring anything, so every gate below is paired with a
    run against this.
    """
    out = np.asarray(image, dtype=np.uint8).copy()
    flat = out.reshape(-1)
    rng = np.random.default_rng(seed)
    positions = rng.choice(flat.size, size=payload_bits.size, replace=False)
    flat[positions] = (flat[positions] & 0xFE) | payload_bits.astype(np.uint8)
    return out
