"""Cover image intake.

The legacy app did `f.save("upload/" + f.filename)` with the browser-supplied
name and handed the bytes straight to cv2.imread -- no size limit, no type
check, no path safety. Three separate problems, all closed here.

Type is decided by content, never by extension or by the Content-Type header
the browser claims. `filetype` sniffs magic bytes and has no libmagic system
dependency; `imghdr` is not an option because it was removed in Python 3.13.
"""

from __future__ import annotations

import io

import filetype
from PIL import Image, UnidentifiedImageError

__all__ = ["CoverError", "MAX_PIXELS", "load_cover", "to_png_bytes"]

# Formats we will decode. Input may be lossy (phone photos are JPEG); the
# output is always PNG, because spatial embedding does not survive
# re-encoding and handing back a JPEG would destroy the payload we just wrote.
ACCEPTED_MIMES = {"image/png", "image/jpeg", "image/webp", "image/bmp"}

# Decompression-bomb guard. A 40 MP ceiling comfortably covers real cameras
# while refusing the 60000x60000 PNG that expands to gigabytes in memory.
MAX_PIXELS = 40_000_000


class CoverError(ValueError):
    """The uploaded file is not a usable cover image."""


def load_cover(stream: io.BufferedIOBase) -> Image.Image:
    """Validate and decode an uploaded cover. Returns an RGB image.

    Raises CoverError with a message safe to show the user.
    """
    head = stream.read(8192)
    stream.seek(0)
    if not head:
        raise CoverError("That file is empty.")

    kind = filetype.guess(head)
    if kind is None or kind.mime not in ACCEPTED_MIMES:
        raise CoverError(
            "Cover must be a PNG, JPEG, WebP or BMP image. "
            "The file you uploaded is not one of those."
        )

    previous_limit = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        # verify() checks structure but consumes the file object, so the image
        # has to be opened a second time to actually get pixels.
        Image.open(stream).verify()
        stream.seek(0)
        image = Image.open(stream)
        image.load()
    except Image.DecompressionBombError as exc:
        raise CoverError(
            f"That image is too large to process safely "
            f"(limit {MAX_PIXELS // 1_000_000} megapixels)."
        ) from exc
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise CoverError("That image could not be read. It may be corrupted.") from exc
    finally:
        Image.MAX_IMAGE_PIXELS = previous_limit

    if image.width * image.height > MAX_PIXELS:
        raise CoverError(
            f"That image is too large to process safely "
            f"(limit {MAX_PIXELS // 1_000_000} megapixels)."
        )

    return image.convert("RGB")


def to_png_bytes(image: Image.Image) -> bytes:
    """Serialise losslessly. Any re-encoding would destroy the payload."""
    buf = io.BytesIO()
    image.save(buf, format="PNG", optimize=False)
    return buf.getvalue()
