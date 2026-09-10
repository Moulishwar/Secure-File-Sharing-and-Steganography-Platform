"""Creating, requesting, approving and opening shares.

Every state change is POST-only and CSRF-protected. Every route that takes an
identifier from the request re-derives the caller's entitlement server-side --
the template never decides what is permitted, it only decides what is drawn.
"""

from __future__ import annotations

import io

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from . import capsule as cap
from . import pipeline, stego
from .db import get_db
from .images import CoverError, load_cover
from .security import audit, current_user_id, login_required, open_share

bp = Blueprint("shares", __name__)

# One message for every extraction failure. Distinguishing "wrong password"
# from "no payload in this image" would hand an observer exactly the signal the
# design exists to deny them.
OPEN_FAILED = "No payload found in that image, or the password is wrong."


def _kek() -> bytes:
    return current_app.config["STEGOSHARE"].FILE_KEK


def _storage():
    return current_app.extensions["storage"]


# --------------------------------------------------------------------------
# dashboard
# --------------------------------------------------------------------------


@bp.get("/dashboard")
@login_required
def dashboard():
    uid = current_user_id()
    db = get_db()

    mine = db.execute(
        "SELECT public_id, mode, kind, display_name, byte_size, created_at "
        "FROM shares WHERE owner_id = ? ORDER BY created_at DESC",
        (uid,),
    ).fetchall()

    # Shares I am a recipient of, with whether I hold key material yet.
    shared = db.execute(
        """
        SELECT s.public_id, s.mode, s.kind, s.display_name, s.approvals_required,
               u.display_name AS owner_name,
               (g.wrapped_dek IS NOT NULL) AS unlocked,
               (SELECT COUNT(*) FROM access_requests r
                 WHERE r.share_id = s.id AND r.requester_id = ?) AS requested,
               (SELECT COUNT(*) FROM access_requests r
                 WHERE r.share_id = s.id AND r.requester_id = ?
                   AND r.status = 'approved') AS approvals
        FROM   grants g
        JOIN   shares s ON s.id = g.share_id
        JOIN   users  u ON u.id = s.owner_id
        WHERE  g.recipient_id = ? AND s.owner_id != ?
        ORDER BY s.created_at DESC
        """,
        (uid, uid, uid, uid),
    ).fetchall()

    pending = db.execute(
        "SELECT COUNT(*) AS c FROM access_requests "
        "WHERE approver_id = ? AND status = 'pending'",
        (uid,),
    ).fetchone()["c"]

    return render_template(
        "dashboard.html", mine=mine, shared=shared, pending=pending
    )


# --------------------------------------------------------------------------
# creating a share
# --------------------------------------------------------------------------


@bp.get("/share/new")
@login_required
def new_share():
    people = get_db().execute(
        "SELECT id, display_name, email FROM users WHERE id != ? ORDER BY display_name",
        (current_user_id(),),
    ).fetchall()
    return render_template("new_share.html", people=people)


@bp.post("/share")
@login_required
def create_share():
    uid = current_user_id()
    db = get_db()

    mode = request.form.get("mode", "reference")
    if mode not in {"reference", "inline"}:
        abort(400)
    kind = request.form.get("kind", "text")
    if kind not in {"file", "text"}:
        abort(400)
    password = request.form.get("password") or ""
    if len(password) < 8:
        flash("Use a share password of at least 8 characters.")
        return redirect(url_for("shares.new_share"))

    # --- the payload -------------------------------------------------
    if kind == "text":
        message = (request.form.get("message") or "").strip()
        if not message:
            flash("Enter a message to hide.")
            return redirect(url_for("shares.new_share"))
        content = message.encode("utf-8")
        title = (request.form.get("title") or "Message").strip()[:116]
        # A title like "Imp" would otherwise download as an extensionless file
        # the browser and desktop have no idea how to open.
        display_name = title if title.lower().endswith(".txt") else f"{title}.txt"
        # Bare type only: Werkzeug appends the charset for text/*, and storing
        # it here too produces "text/plain; charset=utf-8; charset=utf-8".
        content_type = "text/plain"
    else:
        upload = request.files.get("payload")
        if upload is None or not upload.filename:
            flash("Choose a file to hide.")
            return redirect(url_for("shares.new_share"))
        content = upload.read()
        if not content:
            flash("That file is empty.")
            return redirect(url_for("shares.new_share"))
        # The client filename is metadata only. It never touches a path.
        display_name = upload.filename[:120]
        content_type = upload.mimetype or "application/octet-stream"

    # --- the cover ---------------------------------------------------
    cover_file = request.files.get("cover")
    if cover_file is None or not cover_file.filename:
        flash("Choose a cover image.")
        return redirect(url_for("shares.new_share"))
    try:
        cover = load_cover(cover_file.stream)
    except CoverError as exc:
        flash(str(exc))
        return redirect(url_for("shares.new_share"))

    # --- build -------------------------------------------------------
    try:
        if mode == "inline":
            draft = pipeline.build_inline(cover, password, content)
        else:
            draft = pipeline.build_reference(cover, password, content, _kek(), uid)
    except stego.CapacityError as exc:
        flash(str(exc))
        return redirect(url_for("shares.new_share"))
    except pipeline.VerificationError as exc:
        flash(str(exc))
        return redirect(url_for("shares.new_share"))

    # --- persist -----------------------------------------------------
    if mode == "inline":
        # Self-contained: nothing to store, nobody to grant. Recorded only so
        # the owner can see what they made.
        db.execute(
            "INSERT INTO shares (public_id, owner_id, mode, kind, display_name, "
            "content_type, byte_size, approvals_required) "
            "VALUES (?, ?, 'inline', ?, ?, ?, ?, 0)",
            (draft.public_id, uid, kind, display_name, content_type, draft.byte_size),
        )
    else:
        object_key = _persist_object(draft)
        recipients = _selected_recipients(uid)
        approvals_required = max(
            0, min(request.form.get("approvals", type=int) or 1, max(len(recipients), 1))
        )

        cursor = db.execute(
            "INSERT INTO shares (public_id, owner_id, mode, kind, display_name, "
            "content_type, byte_size, object_key, secret_digest, approvals_required) "
            "VALUES (?, ?, 'reference', ?, ?, ?, ?, ?, ?, ?)",
            (draft.public_id, uid, kind, display_name, content_type,
             draft.byte_size, object_key, draft.secret_digest, approvals_required),
        )
        share_id = int(cursor.lastrowid)

        # The owner holds key material immediately; recipients hold none until
        # the approval threshold writes it.
        db.execute(
            "INSERT INTO grants (share_id, recipient_id, wrapped_dek, granted_at) "
            "VALUES (?, ?, ?, datetime('now'))",
            (share_id, uid, draft.wrapped_dek_for_owner),
        )
        db.executemany(
            "INSERT OR IGNORE INTO grants (share_id, recipient_id) VALUES (?, ?)",
            [(share_id, rid) for rid in recipients],
        )

    audit("share.create", detail=f"mode={mode} kind={kind}")
    db.commit()

    return send_file(
        io.BytesIO(draft.png),
        mimetype="image/png",
        as_attachment=True,
        download_name=f"{display_name.rsplit('.', 1)[0] or 'share'}-carrier.png",
    )


def _persist_object(draft: pipeline.ShareDraft) -> str:
    from .storage import new_object_key

    key = new_object_key()
    _storage().put(key, draft.sealed_content)
    return key


def _selected_recipients(owner_id: int) -> list[int]:
    """Recipient ids from the form, filtered to users that actually exist."""
    raw = request.form.getlist("recipients")
    wanted = {int(v) for v in raw if v.isdigit()} - {owner_id}
    if not wanted:
        return []
    placeholders = ",".join("?" * len(wanted))
    rows = get_db().execute(
        f"SELECT id FROM users WHERE id IN ({placeholders})", tuple(wanted)
    ).fetchall()
    return [int(r["id"]) for r in rows]


# --------------------------------------------------------------------------
# opening a share
# --------------------------------------------------------------------------


@bp.get("/open")
@login_required
def open_form():
    return render_template("open.html")


@bp.post("/open")
@login_required
def open_submit():
    uid = current_user_id()
    password = request.form.get("password") or ""

    upload = request.files.get("carrier")
    if upload is None or not upload.filename:
        flash("Choose the image that carries the payload.")
        return render_template("open.html"), 400

    try:
        image = load_cover(upload.stream)
    except CoverError as exc:
        flash(str(exc))
        return render_template("open.html"), 400

    try:
        mode, payload = stego.extract_capsule(image, password)
    except cap.CapsuleError:
        flash(OPEN_FAILED)
        return render_template("open.html"), 400

    if mode == cap.MODE_INLINE:
        audit("share.open", detail="inline")
        get_db().commit()
        return _deliver(payload, "message.txt", "application/octet-stream")

    # Reference mode: possession of the image is necessary but not sufficient.
    share_public_id, secret = cap.parse_reference_payload(payload)
    row, dek = open_share(share_public_id, uid, secret)  # aborts 403 unless approved

    sealed = _storage().get(row["object_key"])
    content = pipeline.open_reference_content(sealed, dek, share_public_id)

    audit("share.open", share_id=int(row["id"]))
    get_db().commit()
    return _deliver(content, row["display_name"], row["content_type"])


def _deliver(content: bytes, name: str, content_type: str):
    """Stream from memory. Nothing decrypted is ever written to disk."""
    response = send_file(
        io.BytesIO(content),
        mimetype=content_type,
        as_attachment=True,
        download_name=name or "payload",
    )
    # send_file sets `no-cache`, which still permits a proxy or the browser to
    # store the body. Decrypted content must not be stored at all.
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers.pop("Expires", None)
    return response


# --------------------------------------------------------------------------
# access requests and approvals
# --------------------------------------------------------------------------


@bp.post("/share/<public_id>/request")
@login_required
def request_access(public_id: str):
    uid = current_user_id()
    db = get_db()

    # The requester must already be a listed recipient. The legacy route took
    # any fileid from the query string and inserted rows for it unconditionally.
    share = db.execute(
        """
        SELECT s.id FROM shares s
        JOIN   grants g ON g.share_id = s.id AND g.recipient_id = ?
        WHERE  s.public_id = ? AND s.mode = 'reference'
        """,
        (uid, public_id),
    ).fetchone()
    if share is None:
        abort(403)

    approvers = db.execute(
        "SELECT recipient_id FROM grants "
        "WHERE share_id = ? AND recipient_id != ? AND wrapped_dek IS NOT NULL",
        (share["id"], uid),
    ).fetchall()

    # INSERT OR IGNORE against the UNIQUE constraint is what stops the
    # duplicate-request spam the legacy route allowed.
    db.executemany(
        "INSERT OR IGNORE INTO access_requests (share_id, requester_id, approver_id) "
        "VALUES (?, ?, ?)",
        [(share["id"], uid, int(a["recipient_id"])) for a in approvers],
    )
    audit("access.request", share_id=int(share["id"]))
    db.commit()

    flash("Access requested.")
    return redirect(url_for("shares.dashboard"))


@bp.get("/requests")
@login_required
def requests_inbox():
    rows = get_db().execute(
        """
        SELECT r.id, r.share_id, r.requester_id, r.created_at,
               s.public_id, s.display_name, u.display_name AS requester_name
        FROM   access_requests r
        JOIN   shares s ON s.id = r.share_id
        JOIN   users  u ON u.id = r.requester_id
        WHERE  r.approver_id = ? AND r.status = 'pending'
        ORDER BY r.created_at
        """,
        (current_user_id(),),
    ).fetchall()
    return render_template("requests.html", rows=rows)


@bp.post("/share/<public_id>/approve")
@login_required
def approve(public_id: str):
    uid = current_user_id()
    requester_id = request.form.get("requester_id", type=int)
    if requester_id is None:
        abort(400)

    db = get_db()
    share = db.execute(
        "SELECT id, approvals_required FROM shares WHERE public_id = ?",
        (public_id,),
    ).fetchone()
    if share is None:
        abort(404)

    # Only a pending request addressed to this approver can be approved, and
    # only once. rowcount is the authorization check.
    approved = db.execute(
        "UPDATE access_requests SET status = 'approved', decided_at = datetime('now') "
        "WHERE share_id = ? AND requester_id = ? AND approver_id = ? "
        "AND status = 'pending'",
        (share["id"], requester_id, uid),
    ).rowcount
    if not approved:
        abort(403)

    _grant_if_threshold_met(share["id"], public_id, requester_id, share["approvals_required"])

    audit("access.approve", share_id=int(share["id"]), detail=f"requester={requester_id}")
    db.commit()

    flash("Approved.")
    return redirect(url_for("shares.requests_inbox"))


def _grant_if_threshold_met(
    share_id: int, public_id: str, requester_id: int, required: int
) -> None:
    """Write the requester's wrapped key -- the only place that ever happens.

    Until this runs, the requester's grant row has wrapped_dek NULL, so
    open_share() finds nothing to unwrap. The approval threshold is not a flag
    consulted at read time; it is the precondition for the key existing.
    """
    from .crypto import unwrap_dek, wrap_dek

    db = get_db()
    got = db.execute(
        "SELECT COUNT(*) AS c FROM access_requests "
        "WHERE share_id = ? AND requester_id = ? AND status = 'approved'",
        (share_id, requester_id),
    ).fetchone()["c"]
    if got < required:
        return

    approver_id = current_user_id()
    grant = db.execute(
        "SELECT wrapped_dek FROM grants "
        "WHERE share_id = ? AND recipient_id = ? AND wrapped_dek IS NOT NULL",
        (share_id, approver_id),
    ).fetchone()
    if grant is None:
        abort(403)  # an approver with no key material cannot confer one

    kek = _kek()
    dek = unwrap_dek(bytes(grant["wrapped_dek"]), kek, public_id, approver_id)
    db.execute(
        "UPDATE grants SET wrapped_dek = ?, granted_at = datetime('now') "
        "WHERE share_id = ? AND recipient_id = ? AND wrapped_dek IS NULL",
        (wrap_dek(dek, kek, public_id, requester_id), share_id, requester_id),
    )
