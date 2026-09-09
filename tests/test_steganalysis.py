"""Steganalysis gate.

What this proves: our output does not fall to the classical chi-square attack
that defeats LSB replacement -- the technique this project replaced.

What this does NOT prove: undetectability. The chi-square attack is a weak,
old detector that only fires at high replacement rates, as the positive control
below shows. A modern CNN steganalyser (SRNet and successors) is far stronger
and is not implemented here. Treat a pass as a floor, not a guarantee, and read
any claim about this engine's security as "against this detector, at this
payload rate" -- never as an absolute.

The positive control is the important part. A gate that never fires measures
nothing, so every assertion that our engine looks clean is paired with a run
against deliberate LSB replacement, which must look dirty.
"""

import numpy as np
import pytest
from PIL import Image

from stegoshare import capsule as cap
from stegoshare import stego

from .steganalysis import chi_square_ratio, embed_lsb_replacement

PASSWORD = "correct horse battery staple"

# Chi-square per degree of freedom. Pair frequencies converge toward each other
# under replacement, driving the statistic toward zero.
DETECTED = 5.0
CLEAN = 20.0


@pytest.fixture
def natural_cover():
    """Smooth sky over grainy ground, with a realistic value histogram."""

    def _make(width=800, height=600, seed=11):
        rng = np.random.default_rng(seed)
        yy, xx = np.mgrid[0:height, 0:width]
        sky = yy < height // 2
        img = np.zeros((height, width, 3))
        for channel, (top, bottom) in enumerate([(150, 110), (170, 105), (205, 95)]):
            img[:, :, channel] = np.where(
                sky, top + 20 * (yy / height) + 3 * np.sin(xx / 50), bottom
            )
        img = np.where(
            np.repeat(sky[:, :, None], 3, axis=2),
            img + rng.normal(0, 1.5, img.shape),
            img + rng.normal(0, 14, img.shape),
        )
        return Image.fromarray(np.clip(img, 0, 255).astype(np.uint8), "RGB")

    return _make


# --------------------------------------------------------------------------
# the control: the detector must actually fire on the thing it targets
# --------------------------------------------------------------------------


def test_detector_fires_on_lsb_replacement(natural_cover):
    """Without this passing, every assertion below is vacuous."""
    arr = np.asarray(natural_cover(), dtype=np.uint8)
    rng = np.random.default_rng(0)
    payload = rng.integers(0, 2, int(arr.size * 0.95)).astype(np.uint8)

    ratio = chi_square_ratio(embed_lsb_replacement(arr, payload, seed=1))

    assert ratio < DETECTED, f"detector failed to flag LSB replacement ({ratio:.2f})"


def test_untouched_cover_reads_clean(natural_cover):
    assert chi_square_ratio(np.asarray(natural_cover(), dtype=np.uint8)) > CLEAN


# --------------------------------------------------------------------------
# the gate
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version", [cap.VERSION_LSB, cap.VERSION_STC], ids=["v1-matching", "v2-stc"]
)
def test_our_engines_do_not_trip_the_detector(natural_cover, version):
    cover = natural_cover()
    payload = bytes(range(256)) * 8  # 2 KB

    image = stego.embed_capsule(
        cover, cap.MODE_INLINE, payload, PASSWORD, version=version
    )

    ratio = chi_square_ratio(np.asarray(image, dtype=np.uint8))
    assert ratio > CLEAN, f"engine v{version} tripped the detector ({ratio:.2f})"


def test_reference_capsule_is_statistically_invisible(natural_cover):
    """104 bytes in a real cover should barely move the statistic at all."""
    cover = natural_cover()
    payload = cap.reference_payload(
        "6f1c8a3e-0d2b-4c9a-9f11-2b7e5a4d3c88", cap.new_share_secret()
    )

    before = chi_square_ratio(np.asarray(cover, dtype=np.uint8))
    image = stego.embed_capsule(cover, cap.MODE_REFERENCE, payload, PASSWORD)
    after = chi_square_ratio(np.asarray(image, dtype=np.uint8))

    assert abs(after - before) / before < 0.02


@pytest.mark.parametrize(
    "version", [cap.VERSION_LSB, cap.VERSION_STC], ids=["v1-matching", "v2-stc"]
)
def test_neither_engine_shifts_the_histogram_much(natural_cover, version):
    """Both engines must leave the pair-of-values statistic close to the cover.

    Deliberately NOT asserted here: that STC drifts less than uniform embedding.
    That ordering looks plausible -- STC changes fewer samples -- but it is not
    an invariant, and a test of it fails about half the time. Chi-square drift
    depends on *which* samples moved and how each pair of values shifts, not
    just on how many moved, and at these payload rates both drifts are noise.

    The real distortion claim is measured in HILL cost, where the ordering is
    deterministic: see test_adaptive.test_stc_lowers_total_distortion.
    """
    cover = natural_cover()
    payload = bytes(range(256)) * 8
    baseline = chi_square_ratio(np.asarray(cover, dtype=np.uint8))

    image = stego.embed_capsule(
        cover, cap.MODE_INLINE, payload, PASSWORD, version=version
    )
    drift = abs(chi_square_ratio(np.asarray(image, dtype=np.uint8)) - baseline)

    assert drift / baseline < 0.05
