import base64
import io
import os

import numpy as np
import pytest
from PIL import Image


@pytest.fixture
def cover():
    """A deterministic noisy RGB cover.

    Noise rather than flat colour so the tests exercise a realistic spread of
    pixel values, including some at the 0/255 boundaries where LSB matching has
    to pick its direction rather than take it from the keystream.
    """

    def _make(width: int = 128, height: int = 128, seed: int = 7) -> Image.Image:
        rng = np.random.default_rng(seed)
        arr = rng.integers(0, 256, size=(height, width, 3), dtype=np.uint8)
        return Image.fromarray(arr, mode="RGB")

    return _make


@pytest.fixture
def cover_png(cover):
    def _make(width: int = 256, height: int = 256, seed: int = 7) -> bytes:
        buf = io.BytesIO()
        cover(width, height, seed).save(buf, format="PNG")
        return buf.getvalue()

    return _make


@pytest.fixture
def kek():
    return bytes(range(32))


# --------------------------------------------------------------------------
# application
# --------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("STEGOSHARE_ENV", "development")
    monkeypatch.setenv("STEGOSHARE_SECRET_KEY", "test-signing-key-not-for-real-use")
    monkeypatch.setenv(
        "STEGOSHARE_FILE_KEK", base64.b64encode(os.urandom(32)).decode()
    )
    monkeypatch.setenv("STEGOSHARE_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("STEGOSHARE_STORAGE_PATH", str(tmp_path / "objects"))

    from stegoshare import create_app, limiter
    from stegoshare.db import init_db

    application = create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    # Rate limits would otherwise fire partway through a test run.
    limiter.enabled = False

    with application.app_context():
        init_db()

    yield application


@pytest.fixture
def client(app):
    return app.test_client()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class Actor:
    """A logged-in user with its own test client."""

    def __init__(self, app, email, name, password="a-long-test-password"):
        self.app = app
        self.email = email
        self.name = name
        self.password = password
        self.client = app.test_client()
        response = self.client.post(
            "/signup",
            data={"email": email, "display_name": name, "password": password},
            follow_redirects=False,
        )
        assert response.status_code == 302, response.data
        with app.app_context():
            from stegoshare.db import get_db

            self.id = get_db().execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()["id"]

    def login(self):
        self.client.post(
            "/login", data={"email": self.email, "password": self.password}
        )
        return self

    def logout(self):
        self.client.post("/logout")
        return self


@pytest.fixture
def actor(app):
    def _make(email, name, password="a-long-test-password"):
        return Actor(app, email, name, password)

    return _make


@pytest.fixture
def make_share(cover_png):
    """Create a reference-mode share; returns (public_id, carrier_png)."""

    def _make(owner, recipients=(), approvals=1, content=b"top secret contents",
              password="share-password", size=(256, 256)):
        response = owner.client.post(
            "/share",
            data={
                "kind": "text",
                "mode": "reference",
                "title": "Test share",
                "message": content.decode(),
                "password": password,
                "approvals": str(approvals),
                "recipients": [str(r.id) for r in recipients],
                "cover": (io.BytesIO(cover_png(*size)), "cover.png"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 200, response.data[:500]
        assert response.mimetype == "image/png"

        with owner.app.app_context():
            from stegoshare.db import get_db

            public_id = get_db().execute(
                "SELECT public_id FROM shares ORDER BY id DESC LIMIT 1"
            ).fetchone()["public_id"]

        return public_id, response.data

    return _make
