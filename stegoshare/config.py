"""Environment-driven configuration.

Everything that differs between "running on my laptop" and "running on the
internet" is a value here, so hosting later is a config change rather than a
code change. Secrets are always read from the environment and the app refuses
to start without them -- there is deliberately no default fallback, because a
default secret is how a demo becomes a breach.

Generate a local .env with:  uv run stegoshare-init
"""

from __future__ import annotations

import base64
import os
from datetime import timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class ConfigError(RuntimeError):
    """Raised at startup when required configuration is missing or malformed."""


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(
            f"{name} is not set. Run `uv run stegoshare-init` to generate a local "
            f".env, or set {name} in the environment before starting the app."
        )
    return value


def _required_key(name: str) -> bytes:
    """Read a base64-encoded 32-byte key, failing loudly if it is the wrong size."""
    raw = _required(name)
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:  # noqa: BLE001 - surfaced as a startup error
        raise ConfigError(f"{name} must be valid base64.") from exc
    if len(key) != 32:
        raise ConfigError(
            f"{name} must decode to exactly 32 bytes, got {len(key)}."
        )
    return key


class Config:
    """Base configuration. Instantiated once, at app creation."""

    def __init__(self) -> None:
        self.ENV = os.environ.get("STEGOSHARE_ENV", "development").lower()
        self.IS_PRODUCTION = self.ENV == "production"

        # --- secrets -----------------------------------------------------
        self.SECRET_KEY = _required("STEGOSHARE_SECRET_KEY")
        self.FILE_KEK = _required_key("STEGOSHARE_FILE_KEK")

        # --- data --------------------------------------------------------
        self.DB_PATH = Path(
            os.environ.get("STEGOSHARE_DB_PATH", REPO_ROOT / "var" / "stegoshare.db")
        )
        self.STORAGE_BACKEND = os.environ.get("STEGOSHARE_STORAGE", "local").lower()
        self.STORAGE_PATH = Path(
            os.environ.get("STEGOSHARE_STORAGE_PATH", REPO_ROOT / "var" / "objects")
        )

        # --- s3 backend ---------------------------------------------------
        # Credentials are deliberately absent: boto3's own chain resolves them
        # from the environment, an instance role, or a profile. A hosted
        # instance should use a role and hold no long-lived key at all.
        self.S3_BUCKET = os.environ.get("STEGOSHARE_S3_BUCKET", "")
        self.S3_PREFIX = os.environ.get("STEGOSHARE_S3_PREFIX", "objects")
        # Set for MinIO or R2; leave unset for AWS.
        self.S3_ENDPOINT = os.environ.get("STEGOSHARE_S3_ENDPOINT", "")
        self.S3_REGION = os.environ.get("STEGOSHARE_S3_REGION", "")
        # Defence in depth only: objects are already AEAD-encrypted before they
        # reach the bucket, so this protects against the storage provider's
        # own disks, not against anyone who can call GetObject.
        self.S3_SSE = os.environ.get("STEGOSHARE_S3_SSE", "")

        if self.STORAGE_BACKEND == "s3" and not self.S3_BUCKET:
            raise ConfigError(
                "STEGOSHARE_STORAGE is 's3' but STEGOSHARE_S3_BUCKET is not set."
            )

        # --- uploads -----------------------------------------------------
        # 25 MB request ceiling. Payload limits for inline mode are far
        # tighter and enforced by the embedding engine's capacity check.
        self.MAX_CONTENT_LENGTH = int(
            os.environ.get("STEGOSHARE_MAX_UPLOAD_BYTES", 25 * 1024 * 1024)
        )

        # --- sessions ----------------------------------------------------
        # Secure cookies require HTTPS. Off for local http:// development,
        # forced on in production regardless of what the environment says.
        self.SESSION_COOKIE_SECURE = self.IS_PRODUCTION
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.PERMANENT_SESSION_LIFETIME = timedelta(hours=12)

        # --- rate limiting -----------------------------------------------
        # In-memory is fine for a single local process. Point this at Redis
        # when there is more than one worker, or the limits are per-worker.
        self.RATELIMIT_STORAGE_URI = os.environ.get(
            "STEGOSHARE_RATELIMIT_URI", "memory://"
        )

        self.DEBUG = os.environ.get("STEGOSHARE_DEBUG") == "1" and not self.IS_PRODUCTION

    def as_flask_mapping(self) -> dict[str, object]:
        """The subset Flask itself reads."""
        return {
            "SECRET_KEY": self.SECRET_KEY,
            "MAX_CONTENT_LENGTH": self.MAX_CONTENT_LENGTH,
            "SESSION_COOKIE_SECURE": self.SESSION_COOKIE_SECURE,
            "SESSION_COOKIE_HTTPONLY": self.SESSION_COOKIE_HTTPONLY,
            "SESSION_COOKIE_SAMESITE": self.SESSION_COOKIE_SAMESITE,
            "PERMANENT_SESSION_LIFETIME": self.PERMANENT_SESSION_LIFETIME,
            "DEBUG": self.DEBUG,
        }
