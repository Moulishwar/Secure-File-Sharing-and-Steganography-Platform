"""Storage backends.

The contract tests run against every backend from one body of assertions. That
is the point: `local` and `s3` are meant to be interchangeable, and the way
that stops being true is when one of them quietly grows a different behaviour
for a missing key or a repeated delete.

S3 is exercised through moto, so the real S3Storage code path runs -- boto3
calls, error shapes, key layout -- rather than a hand-written stand-in that
would agree with my assumptions by construction.
"""

import os
import uuid

import pytest

from stegoshare.storage import (
    LocalStorage,
    ObjectKeyError,
    S3Storage,
    StorageConfigError,
    create_storage,
    new_object_key,
)

BUCKET = "stegoshare-test"


@pytest.fixture
def local_backend(tmp_path):
    return LocalStorage(tmp_path / "objects")


@pytest.fixture
def s3_backend():
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")

    with moto.mock_aws():
        # moto refuses to run without credentials in the environment.
        os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
        os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield S3Storage(BUCKET, client=client)


@pytest.fixture(params=["local", "s3"])
def backend(request):
    return request.getfixturevalue(f"{request.param}_backend")


# --------------------------------------------------------------------------
# the shared contract
# --------------------------------------------------------------------------


def test_round_trips(backend):
    key = new_object_key()
    backend.put(key, b"ciphertext bytes")
    assert backend.get(key) == b"ciphertext bytes"


def test_round_trips_binary_with_nulls(backend):
    key = new_object_key()
    blob = bytes(range(256)) * 40
    backend.put(key, blob)
    assert backend.get(key) == blob


def test_empty_object_round_trips(backend):
    key = new_object_key()
    backend.put(key, b"")
    assert backend.get(key) == b""


def test_missing_key_raises_file_not_found(backend):
    """Both backends translate their own not-found into one exception."""
    with pytest.raises(FileNotFoundError):
        backend.get(new_object_key())


def test_put_overwrites(backend):
    key = new_object_key()
    backend.put(key, b"first")
    backend.put(key, b"second")
    assert backend.get(key) == b"second"


def test_delete_removes(backend):
    key = new_object_key()
    backend.put(key, b"data")
    backend.delete(key)
    with pytest.raises(FileNotFoundError):
        backend.get(key)


def test_delete_is_idempotent(backend):
    backend.delete(new_object_key())  # must not raise
    key = new_object_key()
    backend.put(key, b"data")
    backend.delete(key)
    backend.delete(key)


def test_keys_are_independent(backend):
    first, second = new_object_key(), new_object_key()
    backend.put(first, b"one")
    backend.put(second, b"two")
    assert backend.get(first) == b"one"
    assert backend.get(second) == b"two"


@pytest.mark.parametrize(
    "bad_key",
    [
        "../../../etc/passwd",
        "..",
        "/absolute",
        "not-a-uuid",
        "",
        "a" * 31,
        "a" * 33,
        "../" + uuid.uuid4().hex,
        uuid.uuid4().hex + "/../../escape",
    ],
)
def test_malformed_keys_are_refused(backend, bad_key):
    """Traversal is structurally impossible: a bad key never reaches the store."""
    with pytest.raises(ObjectKeyError):
        backend.put(bad_key, b"data")
    with pytest.raises(ObjectKeyError):
        backend.get(bad_key)
    with pytest.raises(ObjectKeyError):
        backend.delete(bad_key)


def test_generated_keys_are_accepted(backend):
    for _ in range(20):
        backend.put(new_object_key(), b"x")


# --------------------------------------------------------------------------
# s3 specifics
# --------------------------------------------------------------------------


def test_s3_lays_objects_out_under_the_prefix(s3_backend):
    key = new_object_key()
    s3_backend.put(key, b"data")

    listing = s3_backend._client.list_objects_v2(Bucket=BUCKET)
    stored = [item["Key"] for item in listing["Contents"]]
    assert stored == [f"objects/{key[:2]}/{key}"]


def test_s3_prefix_is_configurable(s3_backend):
    s3_backend.prefix = "shares"
    key = new_object_key()
    s3_backend.put(key, b"data")
    assert s3_backend.get(key) == b"data"

    listing = s3_backend._client.list_objects_v2(Bucket=BUCKET, Prefix="shares/")
    assert listing["KeyCount"] == 1


def test_s3_stores_ciphertext_verbatim(s3_backend):
    """No transformation on the way in or out; the app owns the encryption."""
    key = new_object_key()
    blob = os.urandom(4096)
    s3_backend.put(key, blob)

    raw = s3_backend._client.get_object(
        Bucket=BUCKET, Key=f"objects/{key[:2]}/{key}"
    )["Body"].read()
    assert raw == blob


def test_s3_requires_a_bucket():
    with pytest.raises(StorageConfigError):
        S3Storage("", client=object())


# --------------------------------------------------------------------------
# the factory
# --------------------------------------------------------------------------


class FakeConfig:
    STORAGE_BACKEND = "local"
    STORAGE_PATH = "/tmp/stegoshare-factory-test"
    S3_BUCKET = ""
    S3_PREFIX = "objects"
    S3_ENDPOINT = ""
    S3_REGION = ""
    S3_SSE = ""


def test_factory_builds_local():
    assert isinstance(create_storage(FakeConfig()), LocalStorage)


def test_factory_rejects_an_unknown_backend():
    config = FakeConfig()
    config.STORAGE_BACKEND = "dropbox"
    with pytest.raises(StorageConfigError, match="Unknown storage backend"):
        create_storage(config)


def test_config_refuses_s3_without_a_bucket(monkeypatch):
    """Caught at startup, not on the first upload."""
    from stegoshare.config import Config, ConfigError

    monkeypatch.setenv("STEGOSHARE_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("STEGOSHARE_FILE_KEK", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    monkeypatch.setenv("STEGOSHARE_STORAGE", "s3")
    monkeypatch.delenv("STEGOSHARE_S3_BUCKET", raising=False)

    with pytest.raises(ConfigError, match="STEGOSHARE_S3_BUCKET"):
        Config()


def test_local_put_leaves_no_temp_files_behind(tmp_path):
    """A stray .tmp would be an unencrypted-looking artefact in the store."""
    backend = LocalStorage(tmp_path / "objects")
    key = new_object_key()
    backend.put(key, b"data")

    leftovers = [p.name for p in (tmp_path / "objects").rglob("*.tmp")]
    assert leftovers == []


def test_local_concurrent_puts_do_not_corrupt(tmp_path):
    """Two writers on one key must yield one of the two values, never a splice."""
    import threading

    backend = LocalStorage(tmp_path / "objects")
    key = new_object_key()
    first, second = b"A" * 200_000, b"B" * 200_000

    threads = [
        threading.Thread(target=backend.put, args=(key, blob))
        for blob in (first, second)
        for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert backend.get(key) in (first, second)


# --------------------------------------------------------------------------
# the whole app, on S3
# --------------------------------------------------------------------------


@pytest.fixture
def s3_app(tmp_path, monkeypatch):
    """The real application, configured for S3 instead of local disk."""
    import base64

    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")

    with moto.mock_aws():
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
        monkeypatch.setenv("STEGOSHARE_ENV", "development")
        monkeypatch.setenv("STEGOSHARE_SECRET_KEY", "test-signing-key")
        monkeypatch.setenv(
            "STEGOSHARE_FILE_KEK", base64.b64encode(os.urandom(32)).decode()
        )
        monkeypatch.setenv("STEGOSHARE_DB_PATH", str(tmp_path / "s3app.db"))
        monkeypatch.setenv("STEGOSHARE_STORAGE", "s3")
        monkeypatch.setenv("STEGOSHARE_S3_BUCKET", BUCKET)

        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)

        from stegoshare import create_app, limiter
        from stegoshare.db import init_db

        app = create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        limiter.enabled = False
        with app.app_context():
            init_db()
        yield app


def test_app_uses_the_s3_backend_when_configured(s3_app):
    assert isinstance(s3_app.extensions["storage"], S3Storage)


def test_full_share_flow_works_on_s3(s3_app, cover_png):
    """Create, approve and open a share with nothing on local disk."""
    import io

    secret = b"ciphertext should live in the bucket, plaintext nowhere"

    owner = s3_app.test_client()
    owner.post("/signup", data={"email": "owner@x.test", "display_name": "Ora",
                                "password": "a-long-test-password"})
    bob = s3_app.test_client()
    bob.post("/signup", data={"email": "bob@x.test", "display_name": "Bob",
                              "password": "a-long-test-password"})

    created = owner.post(
        "/share",
        data={
            "kind": "text", "mode": "reference", "title": "note.txt",
            "message": secret.decode(), "password": "share-password",
            "approvals": "1", "recipients": ["2"],
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )
    assert created.status_code == 200
    carrier = created.data

    with s3_app.app_context():
        from stegoshare.db import get_db

        public_id = get_db().execute(
            "SELECT public_id FROM shares ORDER BY id DESC LIMIT 1"
        ).fetchone()["public_id"]

    def open_it(client):
        return client.post(
            "/open",
            data={"carrier": (io.BytesIO(carrier), "c.png"),
                  "password": "share-password"},
            content_type="multipart/form-data",
        )

    assert open_it(bob).status_code == 403          # not approved yet
    bob.post(f"/share/{public_id}/request")
    owner.post(f"/share/{public_id}/approve", data={"requester_id": 2})

    opened = open_it(bob)
    assert opened.status_code == 200
    assert opened.data == secret


def test_only_ciphertext_reaches_the_bucket(s3_app, cover_png):
    import io

    secret = b"this plaintext must never appear in object storage"
    owner = s3_app.test_client()
    owner.post("/signup", data={"email": "owner@x.test", "display_name": "Ora",
                                "password": "a-long-test-password"})
    owner.post(
        "/share",
        data={
            "kind": "text", "mode": "reference", "title": "note.txt",
            "message": secret.decode(), "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )

    client = s3_app.extensions["storage"]._client
    listing = client.list_objects_v2(Bucket=BUCKET)
    assert listing["KeyCount"] == 1

    stored = client.get_object(
        Bucket=BUCKET, Key=listing["Contents"][0]["Key"]
    )["Body"].read()
    assert secret not in stored


def test_nothing_is_written_to_local_disk_on_s3(s3_app, cover_png, tmp_path):
    import io

    owner = s3_app.test_client()
    owner.post("/signup", data={"email": "owner@x.test", "display_name": "Ora",
                                "password": "a-long-test-password"})
    owner.post(
        "/share",
        data={
            "kind": "text", "mode": "reference", "title": "n.txt",
            "message": "hello", "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )

    # Only the SQLite database should exist; no object directory at all.
    files = {p.name for p in tmp_path.rglob("*") if p.is_file()}
    assert not any(name.endswith(".tmp") for name in files)
    assert not (tmp_path / "objects").exists()
