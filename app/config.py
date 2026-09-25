import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"

STATIC_DIR = BASE_DIR / "static"

EXIFTOOL_PATH = os.getenv("EXIFTOOL_PATH", "exiftool")

MAX_UPLOAD_SIZE = 250 * 1024 * 1024  # 250 MB


UPLOAD_DIR.mkdir(parents=True, exist_ok=True)