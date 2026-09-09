"""The M5 engine: HILL costs driving syndrome trellis codes.

Three things have to hold. The code must round-trip (a wrong syndrome silently
corrupts everything downstream). Costs must actually steer -- the whole point is
that changes land where the image can absorb them. And carriers issued under the
old engine must keep opening, because a format that breaks its own past output
is not a format.
"""

import numpy as np
import pytest
from PIL import Image

from stegoshare import capsule as cap
from stegoshare import stc, stego
from stegoshare.costs import hill_costs

PASSWORD = "correct horse battery staple"


@pytest.fixture
def split_cover():
    """Smooth gradient on top, fine grain below.

    An image with uniform sensor noise everywhere would have uniform costs, and
    no cost model could or should prefer one half of it -- so the smooth half
    here is deliberately grain-free.
    """

    def _make(width=800, height=600, seed=5):
        rng = np.random.default_rng(seed)
        yy, _ = np.mgrid[0:height, 0:width]
        sky = yy < height // 2
        img = np.zeros((height, width, 3))
        for channel, (top, bottom) in enumerate([(150, 110), (170, 105), (205, 95)]):
            img[:, :, channel] = np.where(sky, top + 14 * (yy / height), bottom)
        grain = rng.integers(-30, 31, (height, width, 3))
        img = np.where(np.repeat(sky[:, :, None], 3, axis=2), img, img + grain)
        return Image.fromarray(np.clip(img, 0, 255).astype(np.uint8), "RGB")

    return _make


# --------------------------------------------------------------------------
# the code itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "message_bits,width,height",
    [(64, 2, 7), (200, 2, 9), (500, 4, 9), (300, 8, 8), (4200, 2, 9)],
)
def test_stc_round_trips(message_bits, width, height):
    rng = np.random.default_rng(0)
    submatrix = stc.make_submatrix(rng.bytes(width * 16), width, height)
    cover = rng.integers(0, 2, message_bits * width).astype(np.uint8)
    costs = rng.random(cover.size) + 0.01
    message = rng.integers(0, 2, message_bits).astype(np.uint8)

    stego_bits = stc.embed(cover, costs, message, submatrix, height)

    assert np.array_equal(stc.extract(stego_bits, submatrix, message_bits), message)


def test_stc_changes_far_fewer_than_half_the_carriers():
    """Embedding efficiency: a random code would change ~50% of samples."""
    rng = np.random.default_rng(1)
    bits, width = 2000, 4
    submatrix = stc.make_submatrix(rng.bytes(width * 16), width, 9)
    cover = rng.integers(0, 2, bits * width).astype(np.uint8)
    message = rng.integers(0, 2, bits).astype(np.uint8)

    stego_bits = stc.embed(cover, np.ones(cover.size), message, submatrix, 9)

    changed = int((cover != stego_bits).sum())
    assert changed / cover.size < 0.15


def test_stc_prefers_cheap_positions():
    """Given a cost gradient, the trellis must route changes to the cheap end."""
    rng = np.random.default_rng(2)
    bits, width = 1500, 8
    submatrix = stc.make_submatrix(rng.bytes(width * 16), width, 9)
    cover = rng.integers(0, 2, bits * width).astype(np.uint8)
    message = rng.integers(0, 2, bits).astype(np.uint8)

    # Alternate expensive and cheap samples.
    costs = np.where(np.arange(cover.size) % 2 == 0, 1000.0, 1.0)
    stego_bits = stc.embed(cover, costs, message, submatrix, 9)

    changed = cover != stego_bits
    expensive = int(changed[0::2].sum())
    cheap = int(changed[1::2].sum())
    assert cheap > 10 * expensive, f"{cheap} cheap vs {expensive} expensive"


def test_submatrix_columns_are_distinct():
    submatrix = stc.make_submatrix(bytes(range(256)), 16, 9)
    assert len(set(submatrix.tolist())) == 16


def test_submatrix_is_keyed():
    a = stc.make_submatrix(b"\x01" * 256, 8, 9)
    b = stc.make_submatrix(b"\x9f" * 256, 8, 9)
    assert not np.array_equal(a, b)


# --------------------------------------------------------------------------
# the cost model
# --------------------------------------------------------------------------


def test_smooth_regions_cost_far_more_than_textured(split_cover):
    image = np.asarray(split_cover(), dtype=np.uint8)
    costs = hill_costs(image)
    half = image.shape[0] // 2

    smooth = float(np.median(costs[:half]))
    textured = float(np.median(costs[half:]))
    assert smooth > 1000 * textured


def test_costs_are_finite_everywhere(split_cover):
    costs = hill_costs(np.asarray(split_cover(), dtype=np.uint8))
    assert np.isfinite(costs).all()
    assert (costs >= 0).all()


def test_flat_image_does_not_divide_by_zero():
    flat = np.full((64, 64, 3), 128, dtype=np.uint8)
    costs = hill_costs(flat)
    assert np.isfinite(costs).all()


# --------------------------------------------------------------------------
# adaptivity, end to end
# --------------------------------------------------------------------------


def _changes(before: Image.Image, after: Image.Image):
    a = np.asarray(before, dtype=np.int16)
    b = np.asarray(after, dtype=np.int16)
    return a != b


def test_stc_keeps_changes_out_of_smooth_regions(split_cover):
    """The headline property. v1 scatters uniformly; v2 must not."""
    cover = split_cover()
    payload = bytes(range(256)) * 8  # 2 KB
    half = np.asarray(cover).shape[0] // 2

    v1 = stego.embed_capsule(
        cover, cap.MODE_INLINE, payload, PASSWORD, version=cap.VERSION_LSB
    )
    v2 = stego.embed_capsule(
        cover, cap.MODE_INLINE, payload, PASSWORD, version=cap.VERSION_STC
    )

    smooth_v1 = int(_changes(cover, v1)[:half].sum())
    smooth_v2 = int(_changes(cover, v2)[:half].sum())

    assert smooth_v1 > 500, "v1 should be scattering changes into the smooth half"
    assert smooth_v2 < smooth_v1 / 20, (
        f"STC left {smooth_v2} changes in smooth regions vs {smooth_v1} for v1"
    )


def test_the_header_is_the_only_uniformly_embedded_part(split_cover):
    """A known and accepted limitation, pinned down so it cannot drift.

    The 28-byte header must be readable before its own version byte is known,
    so it is LSB-matched at bootstrap positions and cannot be cost-steered:
    the receiver would need cover costs it does not have. Its ~106 changed
    samples scatter uniformly.

    The body, which is everything that scales with payload size, is fully
    steered. For a 104-byte reference capsule the header therefore dominates
    the change count -- which is fine at 192 changes in 3.24 million samples,
    but is worth knowing before quoting a steering figure for small capsules.
    """
    cover = split_cover(1200, 900)
    payload = cap.reference_payload(
        "6f1c8a3e-0d2b-4c9a-9f11-2b7e5a4d3c88", cap.new_share_secret()
    )
    image = stego.embed_capsule(cover, cap.MODE_REFERENCE, payload, PASSWORD)

    changed = _changes(cover, image).reshape(-1)
    total = changed.size

    # Recover the header's positions exactly as extraction does.
    boot = stego._KeyStream(cap.bootstrap_key(PASSWORD, *cover.size))
    header_positions = stego._select_positions(
        boot, total, cap.HEADER_LEN * 8, np.zeros(total, dtype=bool)
    )
    is_header = np.zeros(total, dtype=bool)
    is_header[header_positions] = True

    smooth = np.zeros(np.asarray(cover).shape, dtype=bool)
    smooth[: np.asarray(cover).shape[0] // 2] = True
    smooth = smooth.reshape(-1)

    body_changes = changed & ~is_header
    body_in_smooth = int((body_changes & smooth).sum())

    assert int(body_changes.sum()) > 20, "expected the body to change something"
    assert body_in_smooth == 0, (
        f"STC put {body_in_smooth} body changes in the smooth half; "
        "cost steering has regressed"
    )


def test_stc_lowers_total_distortion(split_cover):
    cover = split_cover()
    payload = bytes(range(256)) * 8
    costs = hill_costs(np.asarray(cover, dtype=np.uint8))

    v1 = stego.embed_capsule(
        cover, cap.MODE_INLINE, payload, PASSWORD, version=cap.VERSION_LSB
    )
    v2 = stego.embed_capsule(
        cover, cap.MODE_INLINE, payload, PASSWORD, version=cap.VERSION_STC
    )

    assert costs[_changes(cover, v2)].sum() < costs[_changes(cover, v1)].sum() / 10


def test_stc_still_only_moves_values_by_one(split_cover):
    cover = split_cover()
    image = stego.embed_capsule(
        cover, cap.MODE_INLINE, b"payload" * 100, PASSWORD
    )
    delta = np.asarray(image, dtype=np.int16) - np.asarray(cover, dtype=np.int16)
    assert np.abs(delta).max() <= 1


# --------------------------------------------------------------------------
# width negotiation and version handling
# --------------------------------------------------------------------------


def test_width_is_a_pure_function_of_known_values():
    """Sender and receiver derive it independently; it is never transmitted."""
    for body_bits in (224, 832, 24_672, 500_000):
        for budget in (100_000, 1_800_000):
            first = stego.stc_width(body_bits, budget)
            second = stego.stc_width(body_bits, budget)
            assert first == second
            assert stego.MIN_STC_WIDTH <= first <= stego.MAX_STC_WIDTH


def test_small_capsules_get_the_widest_code():
    """The common case -- a 104-byte reference capsule in a real photo."""
    budget = int(3024 * 4032 * 3 * stego.SAFE_PAYLOAD_FRACTION)
    body_bits = (cap.BODY_OVERHEAD + cap.REFERENCE_PAYLOAD_LEN) * 8
    assert stego.stc_width(body_bits, budget) == stego.MAX_STC_WIDTH


def test_large_payloads_fall_back_toward_the_minimum():
    budget = int(3024 * 4032 * 3 * stego.SAFE_PAYLOAD_FRACTION)
    assert stego.stc_width(800_000, budget) == stego.MIN_STC_WIDTH


def test_v1_carriers_still_open_after_v2_became_the_default(cover):
    """A format that breaks its own past output is not a format."""
    payload = cap.reference_payload(
        "6f1c8a3e-0d2b-4c9a-9f11-2b7e5a4d3c88", cap.new_share_secret()
    )
    legacy = stego.embed_capsule(
        cover(256, 256), cap.MODE_REFERENCE, payload, PASSWORD,
        version=cap.VERSION_LSB,
    )

    mode, recovered = stego.extract_capsule(legacy, PASSWORD)
    assert mode == cap.MODE_REFERENCE
    assert recovered == payload


def test_default_engine_is_stc(cover):
    payload = b"which engine ran?"
    image = stego.embed_capsule(cover(512, 512), cap.MODE_INLINE, payload, PASSWORD)

    # Read the header back the way extraction does, and check the version byte.
    arr = np.asarray(image, dtype=np.uint8).reshape(-1)
    boot = stego._KeyStream(cap.bootstrap_key(PASSWORD, 512, 512))
    taken = np.zeros(arr.size, dtype=bool)
    positions = stego._select_positions(boot, arr.size, cap.HEADER_LEN * 8, taken)
    header = stego._from_bits((arr[positions] & 1).astype(np.uint8))

    version, _, _, _ = cap.parse_header(header)
    assert version == cap.VERSION_STC


def test_version_is_bound_into_the_body_authentication():
    """A body cannot be re-presented under a header claiming the other engine."""
    salt = cap.new_salt()
    keys = cap.derive_keys(PASSWORD, salt)
    body = cap.seal_body(b"payload", keys, cap.MODE_INLINE, salt, cap.VERSION_STC)

    with pytest.raises(cap.CapsuleError):
        cap.open_body(body, keys, cap.MODE_INLINE, salt, cap.VERSION_LSB)


def test_unknown_version_is_rejected():
    with pytest.raises(cap.CapsuleError):
        cap.make_header(cap.MODE_INLINE, cap.new_salt(), 100, version=7)
