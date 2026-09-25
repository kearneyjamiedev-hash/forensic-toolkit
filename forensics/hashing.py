import hashlib
from pathlib import Path


BUFFER_SIZE = 1024 * 1024


def calculate_hashes(file_path: Path) -> dict:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with file_path.open("rb") as file:
        while chunk := file.read(BUFFER_SIZE):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }