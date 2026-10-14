"""Configuration. Secrets are read from the .env file (auto-created on first run)."""
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)


def _ensure_secret(name, generator):
    """Return the secret from the environment, or generate one and save it to .env."""
    value = os.getenv(name)
    if value and value != "change-me":
        return value
    value = generator()
    needs_newline = ENV_FILE.exists() and ENV_FILE.stat().st_size > 0 and not ENV_FILE.read_text().endswith("\n")
    with open(ENV_FILE, "a") as f:
        f.write(("\n" if needs_newline else "") + f"{name}={value}\n")
    os.environ[name] = value
    print(f"[config] Generated {name} and saved it to .env")
    return value


def _database_url():
    url = os.getenv("DATABASE_URL")
    if not url:
        print("[config] DATABASE_URL not set -> using local SQLite file (auth.db). "
              "Set DATABASE_URL in .env to use PostgreSQL.")
        return "sqlite:///" + str(BASE_DIR / "auth.db")
    if url.startswith("postgres://"):  # some providers still use the old prefix
        url = url.replace("postgres://", "postgresql://", 1)
    return url


class Config:
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = _ensure_secret("JWT_SECRET_KEY", lambda: secrets.token_hex(32))
    ENCRYPTION_KEY = _ensure_secret("ENCRYPTION_KEY", lambda: Fernet.generate_key().decode())

    ACCESS_TOKEN_MINUTES = 15       # short-lived access token
    REFRESH_TOKEN_DAYS = 7          # long-lived refresh token (stored hashed in DB)
    MAX_FAILED_ATTEMPTS = 5         # lock the account after 5 wrong passwords
    LOCKOUT_MINUTES = 15
    BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))
