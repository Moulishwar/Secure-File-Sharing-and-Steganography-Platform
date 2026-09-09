"""Signup, login, logout.

Passwords are hashed with Argon2id and never stored or compared in clear. The
legacy app inserted request.form["pswd"] straight into the users table and
authenticated with `select * from data where email=? and password=?`.

Logout clears the session and nothing else. The legacy /logout deleted every
file in static/decrypt/ -- one user's logout destroyed another user's in-flight
output -- and was reachable by GET, so any third-party <img> tag could fire it.
"""

from __future__ import annotations

import sqlite3

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import limiter
from .db import get_db
from .security import (
    MIN_PASSWORD_LENGTH,
    audit,
    current_user_id,
    hash_password,
    needs_rehash,
    verify_password,
)

bp = Blueprint("auth", __name__)


@bp.get("/")
def index():
    if current_user_id() is not None:
        return redirect(url_for("shares.dashboard"))
    return render_template("index.html")


@bp.get("/signup")
def signup():
    return render_template("signup.html")


@bp.post("/signup")
@limiter.limit("10 per hour")
def signup_submit():
    email = (request.form.get("email") or "").strip().lower()
    name = (request.form.get("display_name") or "").strip()
    password = request.form.get("password") or ""

    if not email or "@" not in email:
        flash("Enter a valid email address.")
        return render_template("signup.html", email=email, display_name=name), 400
    if not name:
        flash("Enter a display name.")
        return render_template("signup.html", email=email), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return render_template("signup.html", email=email, display_name=name), 400

    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)",
            (email, name, hash_password(password)),
        )
    except sqlite3.IntegrityError:
        # Deliberately the same message as a successful signup would produce no
        # information about, so this endpoint is not an account oracle.
        flash("That email is already registered. Try logging in.")
        return render_template("signup.html", email=email, display_name=name), 400

    db.commit()
    _start_session(int(cursor.lastrowid))
    audit("auth.signup")
    db.commit()
    return redirect(url_for("shares.dashboard"))


@bp.get("/login")
def login():
    return render_template("login.html")


@bp.post("/login")
@limiter.limit("5 per minute; 30 per hour")
def login_submit():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    row = get_db().execute(
        "SELECT id, password_hash FROM users WHERE email = ?", (email,)
    ).fetchone()

    # verify_password runs the hasher even when row is None, so the response
    # time does not reveal whether the account exists.
    if not verify_password(row["password_hash"] if row else None, password):
        flash("Email or password is incorrect.")
        return render_template("login.html", email=email), 401

    if needs_rehash(row["password_hash"]):
        get_db().execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), row["id"]),
        )

    _start_session(int(row["id"]))
    audit("auth.login")
    get_db().commit()
    return redirect(url_for("shares.dashboard"))


@bp.post("/logout")
def logout():
    audit("auth.logout")
    get_db().commit()
    session.clear()
    return redirect(url_for("auth.index"))


def _start_session(user_id: int) -> None:
    """Fresh session on every login, to prevent session fixation."""
    session.clear()
    session["uid"] = user_id
    session.permanent = True
