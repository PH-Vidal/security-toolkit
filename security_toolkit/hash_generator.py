"""Cryptographic hashing and file integrity verification utilities."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

DIGEST_LENGTH_TO_ALGO = {
    32: "md5",
    64: "sha256",
    128: "sha512",
}


def generate_hash(text: str) -> dict[str, str]:
    """Generate MD5 (checksum/IOC lookup only), SHA-256, and SHA-512 digests for text."""
    encoded = text.encode("utf-8")
    return {
        "md5": hashlib.md5(encoded, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sha512": hashlib.sha512(encoded).hexdigest(),
    }


def hash_file(file_path: str | Path, chunk_size: int = 65536) -> dict[str, Any]:
    """Compute MD5, SHA-256, and SHA-512 hashes of a file using streaming chunks."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo nao encontrado: {path}")

    md5_hasher = hashlib.md5(usedforsecurity=False)
    sha256_hasher = hashlib.sha256()
    sha512_hasher = hashlib.sha512()

    size_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            size_bytes += len(chunk)
            md5_hasher.update(chunk)
            sha256_hasher.update(chunk)
            sha512_hasher.update(chunk)

    return {
        "file": str(path),
        "size_bytes": size_bytes,
        "md5": md5_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest(),
        "sha512": sha512_hasher.hexdigest(),
    }


def verify_hash(
    target: str | Path,
    expected_hash: str,
    *,
    is_file: bool = False,
) -> dict[str, Any]:
    """Verify text or file digest using constant-time comparison."""
    normalized = expected_hash.strip().lower()
    algorithm = DIGEST_LENGTH_TO_ALGO.get(len(normalized))
    if algorithm is None:
        raise ValueError(
            "Hash esperado invalido: forneca um digest hexadecimal MD5 (32), "
            "SHA-256 (64) ou SHA-512 (128)."
        )

    digests = hash_file(target) if is_file else generate_hash(str(target))
    actual = digests[algorithm]
    matched = hmac.compare_digest(actual, normalized)

    return {
        "algorithm": algorithm,
        "expected": normalized,
        "actual": actual,
        "matched": matched,
        "target_type": "file" if is_file else "text",
    }
