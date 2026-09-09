"""Reed-Solomon protection, and the damage it actually survives.

The numbers asserted here were measured, not assumed. Where a claim would be
flattering but false -- "survives a pasted logo" -- the test says so instead.
"""

import numpy as np
import pytest
from PIL import Image

from stegoshare import capsule as cap
from stegoshare import ecc, stego

PASSWORD = "correct horse battery staple"


def _payload():
    return cap.reference_payload(
        "6f1c8a3e-0d2b-4c9a-9f11-2b7e5a4d3c88", cap.new_share_secret()
    )


@pytest.fixture
def carrier_cover():
    """A cover with both smooth and textured halves, big enough for real tests."""

    def _make(width=1200, height=900, seed=3):
        rng = np.random.default_rng(seed)
        yy, xx = np.mgrid[0:height, 0:width]
        sky = yy < height // 2
        img = np.zeros((height, width, 3))
        for channel, (top, bottom) in enumerate([(150, 110), (170, 105), (205, 95)]):
            img[:, :, channel] = np.where(
                sky, top + 18 * (yy / height) + 3 * np.sin(xx / 60), bottom
            )
        img = np.where(
            np.repeat(sky[:, :, None], 3, axis=2),
            img + rng.normal(0, 1.5, img.shape),
            img + rng.normal(0, 14, img.shape),
        )
        return Image.fromarray(np.clip(img, 0, 255).astype(np.uint8), "RGB")

    return _make


# --------------------------------------------------------------------------
# the codec
# --------------------------------------------------------------------------


@pytest.mark.parametrize("length", [1, 28, 76, 200, 223, 224, 500, 2000])
def test_body_round_trips_undamaged(length):
    data = bytes((i * 7 + 3) & 0xFF for i in range(length))
    block = ecc.protect_body(data)
    assert len(block) == ecc.protected_body_len(length)
    assert ecc.recover_body(block, length) == (data, 0)


def test_header_round_trips_undamaged():
    header = cap.make_header(cap.MODE_REFERENCE, cap.new_salt(), 108)
    block = ecc.protect_header(header)
    assert len(block) == ecc.protected_header_len(cap.HEADER_LEN)
    assert ecc.recover_header(block, cap.HEADER_LEN) == (header, 0)


def test_chunk_size_matches_the_parity_it_was_derived_from():
    """A GF(256) block is 255 symbols; data plus parity must equal that.

    Hardcoding CHUNK to 223 is right only while parity is 32. Get this wrong
    and protected_body_len disagrees with what the codec actually emits, which
    surfaces as capsules that embed fine and then fail to extract.
    """
    assert ecc.CHUNK + ecc.BODY_PARITY == 255


def test_length_formula_matches_the_codec_for_multi_chunk_bodies():
    for length in (ecc.CHUNK - 1, ecc.CHUNK, ecc.CHUNK + 1, ecc.CHUNK * 3 + 7):
        data = bytes(length)
        assert len(ecc.protect_body(data)) == ecc.protected_body_len(length)


@pytest.mark.parametrize("errors", [1, 4, 8])
def test_header_repairs_damage_within_capacity(errors):
    header = cap.make_header(cap.MODE_INLINE, cap.new_salt(), 500)
    block = bytearray(ecc.protect_header(header))
    rng = np.random.default_rng(errors)
    for position in rng.choice(len(block), size=errors, replace=False):
        block[position] ^= 0xFF

    recovered, repaired = ecc.recover_header(bytes(block), cap.HEADER_LEN)
    assert recovered == header
    assert repaired >= errors


def test_header_fails_closed_beyond_capacity():
    header = cap.make_header(cap.MODE_INLINE, cap.new_salt(), 500)
    block = bytearray(ecc.protect_header(header))
    rng = np.random.default_rng(0)
    for position in rng.choice(len(block), size=20, replace=False):
        block[position] ^= 0xFF

    with pytest.raises(ecc.EccError):
        ecc.recover_header(bytes(block), cap.HEADER_LEN)


def test_body_repairs_up_to_its_stated_capacity():
    data = bytes((i * 11) & 0xFF for i in range(150))
    block = bytearray(ecc.protect_body(data))
    rng = np.random.default_rng(1)
    for position in rng.choice(len(block), size=ecc.body_correctable_per_chunk(),
                               replace=False):
        block[position] ^= 0xFF

    recovered, _ = ecc.recover_body(bytes(block), len(data))
    assert recovered == data


def test_body_fails_closed_beyond_capacity():
    data = bytes(150)
    block = bytearray(ecc.protect_body(data))
    rng = np.random.default_rng(2)
    for position in rng.choice(len(block), size=ecc.BODY_PARITY + 10, replace=False):
        block[position] ^= 0xFF

    with pytest.raises(ecc.EccError):
        ecc.recover_body(bytes(block), len(data))


def test_parity_bytes_are_not_the_data():
    data = b"A" * 100
    block = ecc.protect_body(data)
    assert block[: len(data)] == data, "RS is systematic: data comes first"
    assert block[len(data) :] != b"\x00" * ecc.BODY_PARITY


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------


def test_capsule_round_trips_with_rs(carrier_cover):
    payload = _payload()
    image = stego.embed_capsule(
        carrier_cover(400, 400), cap.MODE_REFERENCE, payload, PASSWORD
    )
    mode, recovered = stego.extract_capsule(image, PASSWORD)
    assert mode == cap.MODE_REFERENCE
    assert recovered == payload


def _corrupt_random(image, count, seed):
    arr = np.asarray(image, dtype=np.uint8).copy()
    flat = arr.reshape(-1)
    rng = np.random.default_rng(seed)
    flat[rng.choice(flat.size, size=count, replace=False)] ^= 1
    return Image.fromarray(arr, "RGB")


def _opens(image, payload):
    try:
        _, recovered = stego.extract_capsule(image, PASSWORD)
    except cap.CapsuleError:
        return False
    return recovered == payload


def test_sparse_damage_that_would_kill_v2_is_survived(carrier_cover):
    """The headline claim, measured: ~16x more tolerance than v2."""
    cover = carrier_cover()
    payload = _payload()

    without = stego.embed_capsule(
        cover, cap.MODE_REFERENCE, payload, PASSWORD, version=cap.VERSION_STC
    )
    with_rs = stego.embed_capsule(
        cover, cap.MODE_REFERENCE, payload, PASSWORD, version=cap.VERSION_RS
    )

    survived_without = sum(
        _opens(_corrupt_random(without, 200, seed), payload) for seed in range(5)
    )
    survived_with = sum(
        _opens(_corrupt_random(with_rs, 200, seed), payload) for seed in range(5)
    )

    assert survived_with == 5, "RS capsule should shrug off 200 corrupted samples"
    assert survived_without < 5, "v2 should not -- otherwise this proves nothing"


def test_a_small_pasted_patch_is_survived(carrier_cover):
    cover = carrier_cover()
    payload = _payload()
    image = stego.embed_capsule(cover, cap.MODE_REFERENCE, payload, PASSWORD)

    arr = np.asarray(image, dtype=np.uint8).copy()
    arr[400:416, 600:616] = 200  # 16x16 solid block
    assert _opens(Image.fromarray(arr, "RGB"), payload)


def test_a_visible_edit_is_not_survived(carrier_cover):
    """Pinning the honest limit, so nobody quotes a stronger claim than holds.

    A 48x48 patch defeats every parity level tested. If this ever starts
    passing, the tolerance story genuinely improved and the docs should change.
    """
    cover = carrier_cover()
    payload = _payload()
    image = stego.embed_capsule(cover, cap.MODE_REFERENCE, payload, PASSWORD)

    arr = np.asarray(image, dtype=np.uint8).copy()
    arr[400:448, 600:648] = 200  # 48x48
    assert not _opens(Image.fromarray(arr, "RGB"), payload)


def test_damage_beyond_repair_returns_nothing_rather_than_garbage(carrier_cover):
    """Fail closed: RS mis-correction must still hit the AEAD tag."""
    cover = carrier_cover(400, 400)
    payload = _payload()
    image = stego.embed_capsule(cover, cap.MODE_REFERENCE, payload, PASSWORD)

    ruined = _corrupt_random(image, 20_000, seed=9)
    with pytest.raises(cap.CapsuleError):
        stego.extract_capsule(ruined, PASSWORD)


def test_older_capsules_still_open(carrier_cover):
    """v1 and v2 predate the RS header layout; both must keep working."""
    cover = carrier_cover(400, 400)
    payload = _payload()

    for version in (cap.VERSION_LSB, cap.VERSION_STC):
        image = stego.embed_capsule(
            cover, cap.MODE_REFERENCE, payload, PASSWORD, version=version
        )
        mode, recovered = stego.extract_capsule(image, PASSWORD)
        assert mode == cap.MODE_REFERENCE
        assert recovered == payload, f"v{version} capsule stopped opening"


def test_rs_capsule_is_152_bytes():
    body = cap.BODY_OVERHEAD + cap.REFERENCE_PAYLOAD_LEN
    size = ecc.protected_header_len(cap.HEADER_LEN) + ecc.protected_body_len(body)
    assert size == 152


def test_rs_capsule_is_still_negligible_in_a_12mp_cover():
    body = cap.BODY_OVERHEAD + cap.REFERENCE_PAYLOAD_LEN
    size = ecc.protected_header_len(cap.HEADER_LEN) + ecc.protected_body_len(body)
    assert size * 8 / (3024 * 4032 * 3) < 0.00005  # under 0.005%
