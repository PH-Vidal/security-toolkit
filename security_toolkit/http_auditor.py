"""HTTP security headers and TLS certificate auditor (OWASP-aligned, stdlib only)."""

from __future__ import annotations

import datetime
import http.client
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

REQUIRED_SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "strict-transport-security": {
        "display": "Strict-Transport-Security",
        "weight": 20,
        "https_only": True,
        "recommendation": "Configure HSTS (ex: max-age=31536000; includeSubDomains).",
    },
    "content-security-policy": {
        "display": "Content-Security-Policy",
        "weight": 25,
        "https_only": False,
        "recommendation": "Defina uma Content-Security-Policy restritiva para mitigar XSS.",
    },
    "x-content-type-options": {
        "display": "X-Content-Type-Options",
        "weight": 15,
        "https_only": False,
        "expected": "nosniff",
        "recommendation": "Configure 'X-Content-Type-Options: nosniff' contra MIME sniffing.",
    },
    "x-frame-options": {
        "display": "X-Frame-Options",
        "weight": 15,
        "https_only": False,
        "recommendation": "Configure 'X-Frame-Options: DENY' ou 'SAMEORIGIN' contra Clickjacking.",
    },
    "referrer-policy": {
        "display": "Referrer-Policy",
        "weight": 10,
        "https_only": False,
        "recommendation": "Defina 'Referrer-Policy: strict-origin-when-cross-origin' ou 'no-referrer'.",
    },
    "permissions-policy": {
        "display": "Permissions-Policy",
        "weight": 15,
        "https_only": False,
        "recommendation": "Restrinja APIs do navegador via header Permissions-Policy.",
    },
}

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version")
DEPRECATED_TLS_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def audit_http_headers(
    headers: dict[str, str],
    *,
    is_https: bool = True,
) -> dict[str, Any]:
    """Evaluate a dictionary of HTTP response headers against OWASP best practices."""
    normalized = {k.lower(): v.strip() for k, v in headers.items()}

    score = 0
    max_score = 0
    present: dict[str, str] = {}
    missing: list[dict[str, str]] = []
    warnings: list[str] = []

    for key, spec in REQUIRED_SECURITY_HEADERS.items():
        if spec["https_only"] and not is_https:
            continue

        max_score += spec["weight"]
        value = normalized.get(key)
        if value:
            present[spec["display"]] = value
            expected = spec.get("expected")
            if expected and value.lower() != expected:
                score += spec["weight"] // 2
                warnings.append(
                    f"Header '{spec['display']}' presente, mas com valor inesperado ('{value}'). "
                    f"Esperado: '{expected}'."
                )
            else:
                score += spec["weight"]
        else:
            missing.append(
                {
                    "header": spec["display"],
                    "recommendation": spec["recommendation"],
                }
            )

    disclosed: dict[str, str] = {}
    for header_name in DISCLOSURE_HEADERS:
        if header_name in normalized:
            disclosed[header_name] = normalized[header_name]
            warnings.append(
                f"Header '{header_name}' expoe informacoes de stack ('{normalized[header_name]}'). "
                "Considere remove-lo ou ofusca-lo."
            )

    if not is_https:
        warnings.insert(0, "Alvo acessado sem HTTPS; trafego sujeito a interceptacao (MitM).")

    normalized_score = round((score / max_score) * 100) if max_score else 0
    if not is_https:
        normalized_score = min(normalized_score, 50)

    return {
        "score": normalized_score,
        "grade": _score_to_grade(normalized_score),
        "present_headers": present,
        "missing_headers": missing,
        "information_disclosure": disclosed,
        "warnings": warnings,
    }


def _flatten_cert_name(entries: tuple[Any, ...]) -> dict[str, str]:
    flattened: dict[str, str] = {}
    for rdn in entries:
        for key, value in rdn:
            flattened[key] = value
    return flattened


def audit_tls(hostname: str, port: int = 443, *, timeout: float = 5.0) -> dict[str, Any]:
    """Inspect TLS protocol version, cipher suite, and X.509 certificate expiration."""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert() or {}
            protocol = tls_sock.version() or "unknown"
            cipher_info = tls_sock.cipher()

    not_after_raw = cert.get("notAfter")
    days_until_expiry: int | None = None
    expired = False
    if isinstance(not_after_raw, str):
        expires_at = datetime.datetime.strptime(
            not_after_raw, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.UTC)
        now = datetime.datetime.now(datetime.UTC)
        days_until_expiry = (expires_at - now).days
        expired = days_until_expiry < 0

    warnings: list[str] = []
    if protocol in DEPRECATED_TLS_VERSIONS:
        warnings.append(f"Protocolo TLS obsoleto negociado: {protocol}. Utilize TLSv1.2 ou TLSv1.3.")
    if expired:
        warnings.append("Certificado TLS expirado!")
    elif days_until_expiry is not None and days_until_expiry <= 30:
        warnings.append(f"Certificado TLS expira em breve ({days_until_expiry} dias).")

    subject = _flatten_cert_name(cert.get("subject", ()))
    issuer = _flatten_cert_name(cert.get("issuer", ()))

    return {
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "cipher": cipher_info[0] if cipher_info else None,
        "subject_cn": subject.get("commonName"),
        "issuer_org": issuer.get("organizationName") or issuer.get("commonName"),
        "not_after": not_after_raw,
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "warnings": warnings,
    }


def audit_url(
    url: str,
    *,
    timeout: float = 5.0,
    check_tls: bool = True,
) -> dict[str, Any]:
    """Fetch HTTP response headers from a validated HTTP/HTTPS URL and optionally audit TLS."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL invalida. Utilize o formato http:// ou https:// com hostname valido.")

    is_https = parsed.scheme == "https"
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    conn: http.client.HTTPConnection
    if is_https:
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)

    try:
        conn.request("GET", path, headers={"User-Agent": "SecurityToolkit-Auditor/2.0"})
        response = conn.getresponse()
        status_code = response.status
        raw_headers = dict(response.getheaders())
    finally:
        conn.close()

    header_report = audit_http_headers(raw_headers, is_https=is_https)
    tls_report: dict[str, Any] | None = None
    if is_https and check_tls:
        tls_report = audit_tls(parsed.hostname, port, timeout=timeout)

    return {
        "url": url,
        "status_code": status_code,
        "https": is_https,
        "headers_audit": header_report,
        "tls_audit": tls_report,
    }
