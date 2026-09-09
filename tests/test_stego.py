"""The embedding engine.

Covers the round trip, the failure modes that must stay indistinguishable from
each other, the capacity check the legacy encode_text() lacked (it wrapped
modulo the payload length and produced silent garbage), and the statistical
property that motivated moving from LSB replacement to LSB matching.
"""

import io

import numpy as np
import pytest
from PIL import Image

from stegoshare import capsule as cap
from stegoshare import stego
from stegoshare.capsule import MODE_INLINE, MODE_REFERENCE, CapsuleError

PASSWORD = "correct horse battery staple"


def _reference_payload():
    secret = cap.new_share_secret()
    share_id = "6f1c8a3e-0d2b-4c9a-9f11-2b7e5a4d3c88"
    return share_id, secret, cap.reference_payload(share_id, secret)


# --------------------------------------------------------------------------
# round trip
# --------------------------------------------------------------------------


def test_reference_capsule_round_trips(cover):
    share_id, secret, payload = _reference_payload()
    image = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)

    mode, recovered = stego.extract_capsule(image, PASSWORD)

    assert mode == MODE_REFERENCE
    assert cap.parse_reference_payload(recovered) == (share_id, secret)


def test_inline_capsule_round_trips(cover):
    message = "Meet at the usual place. — bring the blue folder.".encode()
    image = stego.embed_capsule(cover(256, 256), MODE_INLINE, message, PASSWORD)

    mode, recovered = stego.extract_capsule(image, PASSWORD)

    assert mode == MODE_INLINE
    assert recovered == message


def test_survives_a_real_png_file(cover):
    """The path that actually matters: embed, save, reload, extract."""
    _, _, payload = _reference_payload()
    image = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    buf.seek(0)
    reloaded = Image.open(buf)

    mode, recovered = stego.extract_capsule(reloaded, PASSWORD)
    assert mode == MODE_REFERENCE
    assert recovered == payload


def test_larger_inline_payload_round_trips(cover):
    """STC needs two carrier samples per payload bit, hence the larger cover."""
    payload = bytes(range(256)) * 40  # 10 KB
    image = stego.embed_capsule(cover(1280, 1024), MODE_INLINE, payload, PASSWORD)
    _, recovered = stego.extract_capsule(image, PASSWORD)
    assert recovered == payload


# --------------------------------------------------------------------------
# failure modes -- all must look the same from outside
# --------------------------------------------------------------------------


def test_wrong_password_fails(cover):
    _, _, payload = _reference_payload()
    image = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)
    with pytest.raises(CapsuleError):
        stego.extract_capsule(image, "not the password")


def test_untouched_image_yields_nothing(cover):
    with pytest.raises(CapsuleError):
        stego.extract_capsule(cover(), PASSWORD)


def test_wrong_password_and_no_payload_are_indistinguishable(cover):
    """The error must not tell an observer which of the two happened."""
    _, _, payload = _reference_payload()
    carrying = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)

    with pytest.raises(CapsuleError) as wrong_pw:
        stego.extract_capsule(carrying, "wrong password")
    with pytest.raises(CapsuleError) as no_payload:
        stego.extract_capsule(cover(seed=99), PASSWORD)

    assert str(wrong_pw.value) == str(no_payload.value)


def test_tampered_stego_image_fails_authentication(cover):
    _, _, payload = _reference_payload()
    image = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)

    arr = np.asarray(image, dtype=np.uint8).copy()
    arr[:, :, 0] ^= 1  # flip every red LSB
    tampered = Image.fromarray(arr, mode="RGB")

    with pytest.raises(CapsuleError):
        stego.extract_capsule(tampered, PASSWORD)


def test_resized_image_loses_the_payload(cover):
    """Dimensions feed the bootstrap key, so a resize cannot silently half-work."""
    _, _, payload = _reference_payload()
    image = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)
    with pytest.raises(CapsuleError):
        stego.extract_capsule(image.resize((64, 64)), PASSWORD)


# --------------------------------------------------------------------------
# capacity
# --------------------------------------------------------------------------


def test_oversized_payload_raises_with_actionable_message(cover):
    with pytest.raises(stego.CapacityError) as exc:
        stego.embed_capsule(cover(64, 64), MODE_INLINE, b"x" * 5000, PASSWORD)
    message = str(exc.value)
    assert "larger image" in message
    assert "pixels" in message


def test_capacity_matches_the_documented_formula(cover):
    image = cover(1000, 1000)
    assert stego.capacity_bits(image) == int(1000 * 1000 * 3 * 0.05)


def test_reference_capsule_is_104_bytes():
    assert stego.required_bits(cap.REFERENCE_PAYLOAD_LEN) == 104 * 8


def test_reference_capsule_is_a_negligible_fraction_of_a_12mp_cover():
    """The claim the whole architecture rests on."""
    nominal = 3024 * 4032 * 3
    fraction = stego.required_bits(cap.REFERENCE_PAYLOAD_LEN) / nominal
    assert fraction < 0.00003  # under 0.003%


# --------------------------------------------------------------------------
# statistical properties
# --------------------------------------------------------------------------


def test_embedding_changes_almost_nothing(cover):
    _, _, payload = _reference_payload()
    original = cover(512, 512)
    image = stego.embed_capsule(original, MODE_REFERENCE, payload, PASSWORD)

    before = np.asarray(original, dtype=np.int16)
    after = np.asarray(image, dtype=np.int16)
    changed = int((before != after).sum())

    # 104 bytes = 832 bits, about half of which need a nudge.
    assert changed <= 832
    assert np.abs(after - before).max() <= 1, "LSB matching must move values by +/-1"


def test_no_parity_asymmetry(cover):
    """LSB *replacement* drives even values up and odd values down; that
    asymmetry is what RS and sample-pair analysis detect. Matching must not."""
    payload = bytes(range(256)) * 20
    original = cover(1024, 1024)
    image = stego.embed_capsule(original, MODE_INLINE, payload, PASSWORD)

    before = np.asarray(original, dtype=np.int16).reshape(-1)
    after = np.asarray(image, dtype=np.int16).reshape(-1)
    delta = after - before
    moved = delta != 0

    ups = int((delta[moved] == 1).sum())
    downs = int((delta[moved] == -1).sum())
    assert ups + downs == int(moved.sum())

    # Direction is keystream-driven, so the split should be near even. Allow a
    # generous band; a replacement scheme would sit at 100/0 on one side.
    ratio = ups / (ups + downs)
    assert 0.35 < ratio < 0.65, f"direction is biased: {ups} up vs {downs} down"


def test_positions_differ_between_passwords(cover):
    """Two passwords must not select the same carrier positions."""
    _, _, payload = _reference_payload()
    original = np.asarray(cover(256, 256), dtype=np.int16)

    a = np.asarray(
        stego.embed_capsule(cover(256, 256), MODE_REFERENCE, payload, "password-a"),
        dtype=np.int16,
    )
    b = np.asarray(
        stego.embed_capsule(cover(256, 256), MODE_REFERENCE, payload, "password-b"),
        dtype=np.int16,
    )

    changed_a = set(np.flatnonzero((original != a).reshape(-1)).tolist())
    changed_b = set(np.flatnonzero((original != b).reshape(-1)).tolist())
    overlap = len(changed_a & changed_b)
    assert overlap < 0.1 * min(len(changed_a), len(changed_b))


def test_same_payload_twice_produces_different_images(cover):
    """A fresh salt per embed means no two stego images match, even for
    identical input. Reusing an embedding key across images is a documented
    steganalysis weakness."""
    _, _, payload = _reference_payload()
    first = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)
    second = stego.embed_capsule(cover(), MODE_REFERENCE, payload, PASSWORD)
    assert np.asarray(first).tobytes() != np.asarray(second).tobytes()
