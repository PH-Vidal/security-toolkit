"""Unit tests for hash_generator module."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from security_toolkit.hash_generator import generate_hash, hash_file, verify_hash


class TestHashGenerator(unittest.TestCase):
    def test_generate_hash_known_values(self) -> None:
        result = generate_hash("hello")
        self.assertEqual(result["md5"], hashlib.md5(b"hello", usedforsecurity=False).hexdigest())
        self.assertEqual(result["sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(result["sha512"], hashlib.sha512(b"hello").hexdigest())

    def test_generate_hash_empty_string(self) -> None:
        result = generate_hash("")
        self.assertSetEqual(set(result.keys()), {"md5", "sha256", "sha512"})
        self.assertEqual(len(result["sha256"]), 64)

    def test_hash_file_and_verify_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "artifact.bin"
            sample.write_bytes(b"cybersecurity-evidence")

            file_result = hash_file(sample)
            self.assertEqual(file_result["size_bytes"], 22)
            expected_sha256 = hashlib.sha256(b"cybersecurity-evidence").hexdigest()
            self.assertEqual(file_result["sha256"], expected_sha256)

            ok = verify_hash(sample, file_result["sha256"], is_file=True)
            self.assertTrue(ok["matched"])
            self.assertEqual(ok["algorithm"], "sha256")

            tampered = verify_hash(sample, "0" * 64, is_file=True)
            self.assertFalse(tampered["matched"])

    def test_verify_hash_invalid_length_raises(self) -> None:
        with self.assertRaises(ValueError):
            verify_hash("hello", "not-a-valid-hash")

    def test_hash_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            hash_file("nonexistent_file_12345.bin")


if __name__ == "__main__":
    unittest.main()
