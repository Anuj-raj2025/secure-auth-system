"""Database tables (SQLAlchemy)."""
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    """Current UTC time as a naive datetime (works the same on PostgreSQL and SQLite)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"  # "user" is a reserved word in PostgreSQL

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(60), nullable=False)   # bcrypt hash, never the password
    phone_encrypted = db.Column(db.Text)                       # Fernet-encrypted at rest
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class RefreshToken(db.Model):
    """One row per active login session. Only a SHA-256 hash of the token is stored."""
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class LoginLog(db.Model):
    """Audit trail of every login attempt."""
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    email = db.Column(db.String(120), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
