"""Unit tests for password_checker module."""

from __future__ import annotations

import unittest

from security_toolkit.password_checker import calculate_entropy, check_password


class TestPasswordChecker(unittest.TestCase):
    def test_very_strong_password(self) -> None:
        result = check_password("K9#mP2!vX8$qL4@z")
        self.assertEqual(result["strength"], "VERY_STRONG")
        self.assertGreaterEqual(result["score"], 85)
        self.assertGreater(result["entropy_bits"], 75)
        self.assertEqual(result["recommendations"], [])

    def test_common_password_penalized(self) -> None:
        result = check_password("Password123")
        self.assertEqual(result["strength"], "WEAK")
        self.assertFalse(result["checks"]["not_common"])
        self.assertLessEqual(result["score"], 10)

    def test_sequence_and_repeat_penalties(self) -> None:
        result = check_password("Aaa1234!bbbb")
        self.assertFalse(result["checks"]["no_simple_sequence"])
        self.assertFalse(result["checks"]["no_excessive_repeats"])

    def test_short_weak_password(self) -> None:
        result = check_password("abc")
        self.assertEqual(result["strength"], "WEAK")
        self.assertFalse(result["checks"]["min_length_8"])

    def test_entropy_empty_string(self) -> None:
        self.assertEqual(calculate_entropy(""), 0.0)


if __name__ == "__main__":
    unittest.main()
