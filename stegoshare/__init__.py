"""StegoShare application factory."""

from __future__ import annotations

from flask import Flask, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect

from .config import Config

__all__ = ["create_app", "csrf", "limiter"]

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["600 per hour"],
)


def create_app(config: Config | None = None) -> Flask:
    app = Flask(__name__)

    cfg = config or Config()
    app.config["STEGOSHARE"] = cfg
    app.config.update(cfg.as_flask_mapping())
    app.config["RATELIMIT_STORAGE_URI"] = cfg.RATELIMIT_STORAGE_URI

    # CSRF on every form. The legacy app had none, and drove /approve,
    # /decrypt and /logout from plain <a href> links -- so an <img> tag on any
    # third-party page could approve an access request on a victim's behalf.
    csrf.init_app(app)
    limiter.init_app(app)

    from . import db

    db.init_app(app)

    from .auth import bp as auth_bp
    from .shares import bp as shares_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(shares_bp)

    _register_storage(app, cfg)
    _register_error_handlers(app)
    _register_security_headers(app, cfg)

    return app


def _register_storage(app: Flask, cfg: Config) -> None:
    from .storage import LocalStorage

    if cfg.STORAGE_BACKEND != "local":
        raise RuntimeError(
            f"Unknown storage backend {cfg.STORAGE_BACKEND!r}. "
            "Only 'local' is implemented; S3/MinIO is the hosting-time swap."
        )
    app.extensions["storage"] = LocalStorage(cfg.STORAGE_PATH)


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(403)
    def forbidden(_e):  # noqa: ANN001, ANN202
        return render_template("error.html", code=403,
                               message="You do not have access to that."), 403

    @app.errorhandler(404)
    def not_found(_e):  # noqa: ANN001, ANN202
        return render_template("error.html", code=404,
                               message="That page does not exist."), 404

    @app.errorhandler(413)
    def too_large(_e):  # noqa: ANN001, ANN202
        limit = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return render_template("error.html", code=413,
                               message=f"That upload is over the {limit} MB limit."), 413

    @app.errorhandler(429)
    def rate_limited(_e):  # noqa: ANN001, ANN202
        return render_template("error.html", code=429,
                               message="Too many attempts. Wait a minute and try again."), 429

    @app.errorhandler(CSRFError)
    def csrf_failed(_e):  # noqa: ANN001, ANN202
        return render_template("error.html", code=400,
                               message="That form expired. Go back and try again."), 400


def _register_security_headers(app: Flask, cfg: Config) -> None:
    @app.after_request
    def set_headers(response):  # noqa: ANN001, ANN202
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # Decrypted content must never sit in a shared cache.
        response.headers.setdefault("Cache-Control", "no-store")
        if cfg.IS_PRODUCTION:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response
