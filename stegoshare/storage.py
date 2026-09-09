"""Object storage for ciphertext.

Nothing user-supplied and nothing decrypted is ever written under static/. The
legacy app wrote decrypted plaintext to static/decrypt/ and served it through
Flask's unauthenticated static route, which made every decrypted file public to
anyone who could guess a filename.

Two backends satisfy the same three methods, so moving from a laptop to a host
is a config change rather than a code change:

    local   filesystem, for development
    s3      any S3-compatible service -- AWS, MinIO, Cloudflare R2 -- selected
            by pointing STEGOSHARE_S3_ENDPOINT at it

Object keys are server-generated UUIDs and are validated on every call. A key
never comes from user input, and this refuses to act on one that looks like it
did, so path traversal is structurally impossible rather than filtered.

A note on presigned URLs, since they are the usual advice for this shape of
problem: they do not fit here. What sits in the bucket is ciphertext under a
per-share data key that the recipient's browser never sees, so handing out a
direct download URL would hand out bytes nobody can read. Decryption has to
happen server-side, which means objects are fetched by the app and streamed
from memory. That is a deliberate consequence of the server-held-keys trust
model; presigned URLs only become useful if decryption moves into the client.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Protocol

__all__ = [
    "LocalStorage",
    "ObjectKeyError",
    "S3Storage",
    "Storage",
    "StorageConfigError",
    "create_storage",
    "new_object_key",
]


class ObjectKeyError(ValueError):
    """An object key is not a well-formed UUID."""


class StorageConfigError(RuntimeError):
    """The storage backend is misconfigured. Raised at startup, never per request."""


def new_object_key() -> str:
    return uuid.uuid4().hex


def _validate(key: str) -> str:
    """Reject anything that is not a bare UUID hex string.

    This is what makes path traversal structurally impossible rather than
    filtered: a key that is not 32 hex characters never reaches the filesystem.
    """
    try:
        uuid.UUID(hex=key)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ObjectKeyError("Malformed object key.") from exc
    if len(key) != 32 or not key.isalnum():
        raise ObjectKeyError("Malformed object key.")
    return key


class Storage(Protocol):
    """The contract every backend must honour.

    put     overwrites if the key exists; must not leave a partial object
            behind if it fails midway
    get     raises FileNotFoundError for a key that is not there -- backends
            translate their own not-found error into this one, so callers
            never have to know which backend they are talking to
    delete  idempotent; deleting an absent key is not an error

    All three raise ObjectKeyError for a malformed key.
    """

    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...


class LocalStorage:
    """Filesystem backend for local development.

    Files are fanned out one level by key prefix so a directory listing stays
    manageable, and the stored bytes are always ciphertext.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        key = _validate(key)
        return self.root / key[:2] / key

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename so a crash cannot leave a truncated object. The
        # temp name is unique per call rather than derived from the key, so two
        # writers racing on the same key cannot clobber each other's partial
        # file and rename the result into place.
        tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            tmp.write_bytes(data)
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not path.is_file():
            raise FileNotFoundError(f"No object {key}.")
        return path.read_bytes()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


class S3Storage:
    """Any S3-compatible object store: AWS S3, MinIO, Cloudflare R2.

    Credentials are never passed in from our config. boto3's own resolution
    chain handles them -- environment variables, an instance role, a profile --
    so a deployed instance can use a role and never hold a long-lived key at
    all. That is why there is no access-key parameter here.

    The bucket must be private. Nothing in this class makes an object public,
    and nothing should: the ciphertext is safe at rest but the fact of a
    share's existence is not something to publish.
    """

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "objects",
        endpoint_url: str | None = None,
        region: str | None = None,
        server_side_encryption: str | None = None,
        client=None,  # injected in tests
    ) -> None:
        if not bucket:
            raise StorageConfigError("STEGOSHARE_S3_BUCKET must be set.")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.server_side_encryption = server_side_encryption
        self._client = client if client is not None else _build_client(
            endpoint_url, region
        )

    def _object_key(self, key: str) -> str:
        key = _validate(key)
        # Same two-character fan-out as the local backend, so an operator
        # migrating between them sees a familiar layout.
        parts = [p for p in (self.prefix, key[:2], key) if p]
        return "/".join(parts)

    def put(self, key: str, data: bytes) -> None:
        extra = {}
        if self.server_side_encryption:
            extra["ServerSideEncryption"] = self.server_side_encryption
        # A single PutObject is atomic: readers see the old object or the new
        # one, never a partial write, so there is no temp-and-rename dance.
        self._client.put_object(
            Bucket=self.bucket,
            Key=self._object_key(key),
            Body=data,
            **extra,
        )

    def get(self, key: str) -> bytes:
        object_key = self._object_key(key)
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=object_key)
        except Exception as exc:  # noqa: BLE001 - narrowed immediately below
            if _is_not_found(exc):
                raise FileNotFoundError(f"No object {key}.") from exc
            raise
        return response["Body"].read()

    def delete(self, key: str) -> None:
        # S3 DeleteObject already succeeds for a key that is not there.
        self._client.delete_object(Bucket=self.bucket, Key=self._object_key(key))


def _build_client(endpoint_url: str | None, region: str | None):
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise StorageConfigError(
            "The s3 backend needs boto3. Install it with: uv sync --extra s3"
        ) from exc

    return boto3.client(
        "s3",
        endpoint_url=endpoint_url or None,
        region_name=region or None,
    )


def _is_not_found(exc: Exception) -> bool:
    """True for the several shapes 'missing object' arrives in.

    boto3 raises NoSuchKey for a missing key but 404/NoSuchBucket-ish codes
    turn up too depending on the service and permissions, and MinIO and R2 are
    not perfectly consistent with AWS here.
    """
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error", {})
    code = str(error.get("Code", ""))
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return code in {"NoSuchKey", "NoSuchBucket", "404", "NotFound"} or status == 404


def create_storage(config) -> Storage:
    """Build the backend named by config. Fails at startup, not mid-request."""
    backend = (config.STORAGE_BACKEND or "local").lower()

    if backend == "local":
        return LocalStorage(config.STORAGE_PATH)

    if backend == "s3":
        return S3Storage(
            config.S3_BUCKET,
            prefix=config.S3_PREFIX,
            endpoint_url=config.S3_ENDPOINT,
            region=config.S3_REGION,
            server_side_encryption=config.S3_SSE,
        )

    raise StorageConfigError(
        f"Unknown storage backend {backend!r}. Use 'local' or 's3'."
    )
