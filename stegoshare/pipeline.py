"""Share creation and opening: where the layers are wired together.

The one rule enforced here that the legacy app had no equivalent of: a stego
image is round-trip verified before it is ever handed to a user. If what we
just embedded does not come back out byte-identical, the request fails. A user
must never receive an image that does not decode -- that is data loss wearing a
success message, which is exactly how the legacy dead-ChaCha20 path went
unnoticed for the life of the project.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from PIL import Image

from . import capsule as cap
from . import stego
from .crypto import InvalidTag, content_aad, new_dek, seal, unseal, wrap_dek
from .images import to_png_bytes

__all__ = ["ShareDraft", "VerificationError", "build_inline", "build_reference",
           "open_inline", "read_reference_capsule"]


class VerificationError(RuntimeError):
    """The stego image we produced did not survive its own round trip."""


@dataclass(slots=True)
class ShareDraft:
    """Everything the caller needs to persist and deliver a new share."""

    public_id: str
    png: bytes
    sealed_content: bytes | None   # reference mode only -- goes to object storage
    wrapped_dek_for_owner: bytes | None
    secret_digest: bytes | None
    byte_size: int


def _verify(png: bytes, password: str, mode: int, expected: bytes) -> None:
    """Extract from the finished PNG, in the same form the recipient will."""
    import io

    try:
        got_mode, got_payload = stego.extract_capsule(
            Image.open(io.BytesIO(png)), password
        )
    except Exception as exc:  # noqa: BLE001 - any failure here is fatal
        raise VerificationError(
            "The stego image failed its round-trip check and was not delivered."
        ) from exc

    if got_mode != mode or got_payload != expected:
        raise VerificationError(
            "The stego image failed its round-trip check and was not delivered."
        )


def build_reference(
    cover: Image.Image,
    password: str,
    content: bytes,
    kek: bytes,
    owner_id: int,
) -> ShareDraft:
    """Encrypt content for server storage; embed only a locator + capability.

    The image carries 104 bytes regardless of how big the file is, which is why
    reference mode has no practical size limit.
    """
    public_id = str(uuid.uuid4())
    dek = new_dek()
    sealed = seal(content, dek, content_aad(public_id))

    secret = cap.new_share_secret()
    payload = cap.reference_payload(public_id, secret)

    image = stego.embed_capsule(cover, cap.MODE_REFERENCE, payload, password)
    png = to_png_bytes(image)
    _verify(png, password, cap.MODE_REFERENCE, payload)

    return ShareDraft(
        public_id=public_id,
        png=png,
        sealed_content=sealed,
        wrapped_dek_for_owner=wrap_dek(dek, kek, public_id, owner_id),
        secret_digest=cap.secret_digest(secret),
        byte_size=len(content),
    )


def build_inline(cover: Image.Image, password: str, content: bytes) -> ShareDraft:
    """Embed the content itself. Self-contained: opening it needs no server.

    Subject to the capacity ceiling -- roughly 45-220 KB for a phone photo at a
    safe embedding rate. stego.embed_capsule raises CapacityError with an
    actionable message when the payload does not fit.
    """
    public_id = str(uuid.uuid4())

    image = stego.embed_capsule(cover, cap.MODE_INLINE, content, password)
    png = to_png_bytes(image)
    _verify(png, password, cap.MODE_INLINE, content)

    return ShareDraft(
        public_id=public_id,
        png=png,
        sealed_content=None,
        wrapped_dek_for_owner=None,
        secret_digest=None,
        byte_size=len(content),
    )


def read_reference_capsule(image: Image.Image, password: str) -> tuple[str, bytes]:
    """Pull (share id, capability secret) out of an uploaded stego image."""
    mode, payload = stego.extract_capsule(image, password)
    if mode != cap.MODE_REFERENCE:
        raise cap.CapsuleError("Capsule failed authentication.")
    return cap.parse_reference_payload(payload)


def open_inline(image: Image.Image, password: str) -> bytes:
    """Recover a self-contained payload. No database, no authorization."""
    mode, payload = stego.extract_capsule(image, password)
    if mode != cap.MODE_INLINE:
        raise cap.CapsuleError("Capsule failed authentication.")
    return payload


def open_reference_content(sealed: bytes, dek: bytes, public_id: str) -> bytes:
    """Decrypt stored ciphertext. Raises InvalidTag if storage was tampered with."""
    try:
        return unseal(sealed, dek, content_aad(public_id))
    except InvalidTag:
        raise VerificationError(
            "Stored ciphertext failed authentication; it may have been altered."
        ) from None
