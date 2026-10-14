"""Security helpers: bcrypt, JWT, encryption, validation and the @token_required decorator."""
import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from flask import g, jsonify, request

from config import Config
from models import User, db

_fernet = Fernet(Config.ENCRYPTION_KEY.encode())

# Used to make "unknown email" take as long as "wrong password" (prevents user enumeration by timing)
DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(Config.BCRYPT_ROUNDS))


# ---------------------------------------------------------------- passwords (bcrypt)
def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(Config.BCRYPT_ROUNDS)).decode("utf-8")


def check_password(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# ---------------------------------------------------------------- JWT
def _make_token(user_id, token_type, lifetime):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": token_type,          # "access" or "refresh"
        "jti": uuid.uuid4().hex,     # unique id of this token
        "iat": now,
        "exp": now + lifetime,
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")


def create_access_token(user_id):
    return _make_token(user_id, "access", timedelta(minutes=Config.ACCESS_TOKEN_MINUTES))


def create_refresh_token(user_id):
    return _make_token(user_id, "refresh", timedelta(days=Config.REFRESH_TOKEN_DAYS))


def decode_token(token, expected_type):
    """Verify signature + expiry + token type. Raises jwt exceptions on failure."""
    payload = jwt.decode(
        token,
        Config.JWT_SECRET_KEY,
        algorithms=["HS256"],  # fixed list -> "alg: none" attacks do not work
        options={"require": ["exp", "iat", "sub", "jti", "type"]},
    )
    if payload["type"] != expected_type:
        raise jwt.InvalidTokenError("Wrong token type")
    return payload


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_required(f):
    """Protect a route: requires 'Authorization: Bearer <access_token>'."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Missing access token"), 401
        try:
            payload = decode_token(header[7:], "access")
        except jwt.ExpiredSignatureError:
            return jsonify(error="Access token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid access token"), 401
        user = db.session.get(User, int(payload["sub"]))
        if not user:
            return jsonify(error="User not found"), 401
        g.user = user
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------- encryption (Fernet / AES)
def encrypt(text):
    return _fernet.encrypt(text.encode("utf-8")).decode("utf-8") if text else None


def decrypt(token):
    if not token:
        return ""
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""


# ---------------------------------------------------------------- validation
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
PHONE_RE = re.compile(r"^\+?[0-9 \-]{7,20}$")


def password_errors(password):
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if len(password.encode("utf-8")) > 72:
        errors.append("at most 72 bytes (bcrypt limit)")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("a number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("a special character")
    return errors
