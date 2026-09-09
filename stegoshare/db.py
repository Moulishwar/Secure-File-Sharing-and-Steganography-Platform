"""One connection per request, closed on teardown.

The legacy app opened a module-level connection at import time and shared it
across threads, plus a fresh sqlite3.connect() in every route that was never
closed. Both are replaced by the Flask `g` pattern below.

SQLite is the local development store. The access layer is deliberately thin
so that moving to Postgres later is a driver swap rather than a rewrite -- the
only SQLite-specific things here are the PRAGMAs and datetime('now') defaults
in schema.sql.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import click
from flask import Flask, current_app, g

__all__ = ["get_db", "init_app", "init_db"]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path: Path = current_app.config["STEGOSHARE"].DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        # Off by default in SQLite; without it every REFERENCES clause in
        # schema.sql is decorative.
        conn.execute("PRAGMA foreign_keys = ON")
        # Concurrent readers alongside a writer, rather than a global lock.
        conn.execute("PRAGMA journal_mode = WAL")
        g.db = conn
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    """Apply schema.sql. Safe to run repeatedly -- every statement is IF NOT EXISTS."""
    schema = Path(current_app.root_path).parent / "schema.sql"
    get_db().executescript(schema.read_text(encoding="utf-8"))
    get_db().commit()


@click.command("init-db")
def init_db_command() -> None:
    """Create the database tables."""
    init_db()
    click.echo(f"Schema applied to {current_app.config['STEGOSHARE'].DB_PATH}")


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
