"""Where bytes actually end up.

The legacy app wrote decrypted plaintext into static/decrypt/ and served it
through Flask's unauthenticated static route, stored passwords in clear, and
committed the whole database to git. These tests assert the opposite of each.
"""

import io
from pathlib import Path

SECRET = b"the-quick-brown-fox-jumps-over-the-lazy-dog"


def _all_bytes_under(root: Path) -> bytes:
    if not root.exists():
        return b""
    return b"".join(
        p.read_bytes() for p in root.rglob("*") if p.is_file()
    )


def test_storage_holds_ciphertext_not_plaintext(app, actor, make_share, tmp_path):
    owner = actor("owner@example.test", "Owner")
    make_share(owner, content=SECRET)

    stored = _all_bytes_under(tmp_path / "objects")
    assert stored, "nothing was written to object storage"
    assert SECRET not in stored, "plaintext reached the object store"


def test_database_never_contains_the_plaintext(app, actor, make_share, tmp_path):
    owner = actor("owner@example.test", "Owner")
    make_share(owner, content=SECRET)

    assert SECRET not in (tmp_path / "test.db").read_bytes()


def test_carrier_image_does_not_contain_the_plaintext(actor, make_share):
    """Reference mode embeds a locator, never the content."""
    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner, content=SECRET)
    assert SECRET not in carrier


def test_password_is_not_stored_in_clear(app, actor, tmp_path):
    actor("owner@example.test", "Owner", password="a-very-secret-passphrase")

    blob = (tmp_path / "test.db").read_bytes()
    assert b"a-very-secret-passphrase" not in blob
    assert b"$argon2id$" in blob


def test_nothing_is_written_into_the_static_directory(app, actor, make_share):
    """Decrypted content is streamed from memory and never touches disk."""
    import stegoshare

    static_root = Path(stegoshare.__file__).parent / "static"
    before = {p: p.stat().st_mtime_ns for p in static_root.rglob("*") if p.is_file()}

    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner, content=SECRET)
    owner.client.post(
        "/open",
        data={"carrier": (io.BytesIO(carrier), "c.png"), "password": "share-password"},
        content_type="multipart/form-data",
    )

    after = {p: p.stat().st_mtime_ns for p in static_root.rglob("*") if p.is_file()}
    assert before == after


def test_decrypted_responses_are_not_cacheable(actor, make_share):
    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner, content=SECRET)

    response = owner.client.post(
        "/open",
        data={"carrier": (io.BytesIO(carrier), "c.png"), "password": "share-password"},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert "no-store" in response.headers.get("Cache-Control", "")


def test_audit_log_records_who_opened_what(app, actor, make_share):
    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner, content=SECRET)
    owner.client.post(
        "/open",
        data={"carrier": (io.BytesIO(carrier), "c.png"), "password": "share-password"},
        content_type="multipart/form-data",
    )

    with app.app_context():
        from stegoshare.db import get_db

        actions = [
            r["action"]
            for r in get_db().execute("SELECT action FROM audit_log").fetchall()
        ]
    assert "share.create" in actions
    assert "share.open" in actions


def test_audit_log_never_records_key_material(app, actor, make_share):
    owner = actor("owner@example.test", "Owner")
    make_share(owner, content=SECRET, password="share-password")

    with app.app_context():
        from stegoshare.db import get_db

        details = " ".join(
            str(r["detail"] or "")
            for r in get_db().execute("SELECT detail FROM audit_log").fetchall()
        )
    assert "share-password" not in details


# --------------------------------------------------------------------------
# inline mode: self-contained, no server authorization involved
# --------------------------------------------------------------------------


def test_inline_share_round_trips_through_the_web_layer(actor, cover_png):
    owner = actor("owner@example.test", "Owner")

    response = owner.client.post(
        "/share",
        data={
            "kind": "text",
            "mode": "inline",
            "title": "Offline note",
            "message": "meet at the usual place",
            "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    carrier = response.data

    opened = owner.client.post(
        "/open",
        data={"carrier": (io.BytesIO(carrier), "c.png"), "password": "share-password"},
        content_type="multipart/form-data",
    )
    assert opened.status_code == 200
    assert opened.data == b"meet at the usual place"


def test_inline_share_opens_for_a_different_user(actor, cover_png):
    """Inline mode is deliberately server-independent: the image IS the share."""
    owner = actor("owner@example.test", "Owner")
    other = actor("other@example.test", "Other")

    carrier = owner.client.post(
        "/share",
        data={
            "kind": "text", "mode": "inline", "title": "Note",
            "message": "no server needed", "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    ).data

    opened = other.client.post(
        "/open",
        data={"carrier": (io.BytesIO(carrier), "c.png"), "password": "share-password"},
        content_type="multipart/form-data",
    )
    assert opened.status_code == 200
    assert opened.data == b"no server needed"


def test_inline_share_stores_no_object_and_no_grants(app, actor, cover_png):
    owner = actor("owner@example.test", "Owner")
    owner.client.post(
        "/share",
        data={
            "kind": "text", "mode": "inline", "title": "Note",
            "message": "self contained", "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )

    with app.app_context():
        from stegoshare.db import get_db

        share = get_db().execute(
            "SELECT object_key, secret_digest FROM shares WHERE mode = 'inline'"
        ).fetchone()
        grants = get_db().execute("SELECT COUNT(*) AS c FROM grants").fetchone()["c"]

    assert share["object_key"] is None
    assert share["secret_digest"] is None
    assert grants == 0


# --------------------------------------------------------------------------
# upload hardening
# --------------------------------------------------------------------------


def test_non_image_cover_is_rejected(actor):
    owner = actor("owner@example.test", "Owner")
    response = owner.client.post(
        "/share",
        data={
            "kind": "text", "mode": "inline", "message": "hi",
            "password": "share-password",
            "cover": (io.BytesIO(b"#!/bin/sh\nrm -rf /\n"), "evil.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"PNG, JPEG, WebP or BMP" in response.data


def test_oversized_payload_reports_capacity_not_a_crash(actor, cover_png):
    owner = actor("owner@example.test", "Owner")
    response = owner.client.post(
        "/share",
        data={
            "kind": "text", "mode": "inline",
            "message": "x" * 20000, "password": "share-password",
            "cover": (io.BytesIO(cover_png(64, 64)), "cover.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"larger image" in response.data


def test_client_filename_never_becomes_a_path(app, actor, cover_png, tmp_path):
    """The legacy app did f.save('upload/' + f.filename) verbatim."""
    owner = actor("owner@example.test", "Owner")
    owner.client.post(
        "/share",
        data={
            "kind": "file", "mode": "reference",
            "payload": (io.BytesIO(b"payload bytes"), "../../../etc/passwd"),
            "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )

    # Object keys are server-generated UUIDs; nothing escaped the store root.
    written = [p for p in (tmp_path / "objects").rglob("*") if p.is_file()]
    assert len(written) == 1
    assert written[0].name.isalnum() and len(written[0].name) == 32
    assert not Path("/etc/passwd.tmp").exists()


# --------------------------------------------------------------------------
# download naming
# --------------------------------------------------------------------------


def test_text_share_downloads_with_a_txt_extension(actor, make_share):
    """A title like "Imp" must not arrive as an extensionless file."""
    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner, content=b"the message body")

    response = owner.client.post(
        "/open",
        data={"carrier": (io.BytesIO(carrier), "c.png"), "password": "share-password"},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert ".txt" in response.headers["Content-Disposition"]


def test_a_title_that_already_ends_in_txt_is_not_doubled(app, actor, cover_png):
    owner = actor("owner@example.test", "Owner")
    owner.client.post(
        "/share",
        data={
            "kind": "text", "mode": "reference", "title": "notes.txt",
            "message": "hello", "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )

    with app.app_context():
        from stegoshare.db import get_db

        name = get_db().execute(
            "SELECT display_name FROM shares ORDER BY id DESC LIMIT 1"
        ).fetchone()["display_name"]
    assert name == "notes.txt"


def test_file_shares_keep_their_own_extension(app, actor, cover_png):
    owner = actor("owner@example.test", "Owner")
    owner.client.post(
        "/share",
        data={
            "kind": "file", "mode": "reference",
            "payload": (io.BytesIO(b"%PDF-1.4 fake"), "report.pdf"),
            "password": "share-password",
            "cover": (io.BytesIO(cover_png(256, 256)), "cover.png"),
        },
        content_type="multipart/form-data",
    )

    with app.app_context():
        from stegoshare.db import get_db

        name = get_db().execute(
            "SELECT display_name FROM shares ORDER BY id DESC LIMIT 1"
        ).fetchone()["display_name"]
    assert name == "report.pdf"


def test_text_download_has_a_single_charset(actor, make_share):
    """Werkzeug adds the charset for text/*; storing it too duplicated it."""
    owner = actor("owner@example.test", "Owner")
    _, carrier = make_share(owner, content=b"body")

    response = owner.client.post(
        "/open",
        data={"carrier": (io.BytesIO(carrier), "c.png"), "password": "share-password"},
        content_type="multipart/form-data",
    )
    assert response.headers["Content-Type"].count("charset") == 1
