"""Password strength analyzer inspired by NIST SP 800-63B with entropy calculation."""

from __future__ import annotations

import math
import re
from typing import Any

COMMON_PASSWORDS = frozenset(
    {
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "password",
        "password123",
        "qwerty",
        "qwerty123",
        "abc123",
        "admin",
        "admin123",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "iloveyou",
        "senha",
        "senha123",
        "mudar123",
        "p@ssw0rd",
        "passw0rd",
        "root",
        "toor",
    }
)

SEQUENTIAL_PATTERNS = (
    "0123",
    "1234",
    "2345",
    "3456",
    "4567",
    "5678",
    "6789",
    "abcd",
    "bcde",
    "qwer",
    "asdf",
    "zxcv",
)


def calculate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on character pool size and length."""
    if not password:
        return 0.0

    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9\s]", password):
        pool += 32
    if re.search(r"\s", password):
        pool += 1

    if pool == 0:
        return 0.0

    return round(len(password) * math.log2(pool), 2)


def _has_sequence(password: str) -> bool:
    lowered = password.lower()
    return any(seq in lowered for seq in SEQUENTIAL_PATTERNS)


def _has_repeated_chars(password: str) -> bool:
    return bool(re.search(r"(.)\1{2,}", password))


def check_password(password: str) -> dict[str, Any]:
    """Evaluate password strength without exposing the raw password in the result."""
    length = len(password)
    entropy = calculate_entropy(password)
    is_common = password.lower() in COMMON_PASSWORDS
    has_sequence = _has_sequence(password)
    has_repeats = _has_repeated_chars(password)

    checks = {
        "min_length_8": length >= 8,
        "recommended_length_12": length >= 12,
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9\s]", password)),
        "not_common": not is_common,
        "no_simple_sequence": not has_sequence,
        "no_excessive_repeats": not has_repeats,
    }

    score = 0
    recommendations: list[str] = []

    if checks["recommended_length_12"]:
        score += 30
    elif checks["min_length_8"]:
        score += 15
        recommendations.append("Use pelo menos 12 caracteres (recomendacao NIST SP 800-63B).")
    else:
        recommendations.append("Aumente o tamanho para no minimo 8 caracteres (ideal: 12+).")

    if checks["has_uppercase"]:
        score += 10
    else:
        recommendations.append("Adicione letras maiusculas.")

    if checks["has_lowercase"]:
        score += 10
    else:
        recommendations.append("Adicione letras minusculas.")

    if checks["has_digit"]:
        score += 10
    else:
        recommendations.append("Adicione numeros.")

    if checks["has_special"]:
        score += 15
    else:
        recommendations.append("Adicione caracteres especiais (!@#$%...).")

    if entropy >= 75:
        score += 25
    elif entropy >= 50:
        score += 15
    elif entropy >= 35:
        score += 5
    else:
        recommendations.append("Aumente a variedade e o comprimento para elevar a entropia.")

    if is_common:
        score = min(score, 10)
        recommendations.insert(0, "Senha presente em listas comuns de vazamentos; troque imediatamente.")

    if has_sequence:
        score = max(0, score - 15)
        recommendations.append("Evite sequencias previsiveis (ex: 1234, abcd, qwer).")

    if has_repeats:
        score = max(0, score - 10)
        recommendations.append("Evite repeticao consecutiva do mesmo caractere (ex: aaa, 111).")

    score = max(0, min(100, score))

    if score < 40:
        strength = "WEAK"
    elif score < 65:
        strength = "MODERATE"
    elif score < 85:
        strength = "STRONG"
    else:
        strength = "VERY_STRONG"

    return {
        "score": score,
        "strength": strength,
        "entropy_bits": entropy,
        "length": length,
        "checks": checks,
        "recommendations": recommendations,
    }
