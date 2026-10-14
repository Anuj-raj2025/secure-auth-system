"""Use a throw-away SQLite database and fixed test secrets (set BEFORE the app is imported)."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(tempfile.mkdtemp()) / "test.db")
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-unit-tests-only-1234567890"
os.environ["ENCRYPTION_KEY"] = "ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg="
os.environ["BCRYPT_ROUNDS"] = "4"  # fast hashing in tests
