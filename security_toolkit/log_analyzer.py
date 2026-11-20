"""Blue Team log & IOC analyzer with MITRE ATT&CK technique mapping."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Linux SSH / auth.log patterns
SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Nginx / Apache Combined access log pattern
WEB_ACCESS_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})'
)

SQLI_RE = re.compile(
    r"(?:union\s+select|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|sleep\s*\(|benchmark\s*\(|"
    r"information_schema|--\s*$|%27|%20union%20)",
    re.IGNORECASE,
)
TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|/etc/shadow|win\.ini)",
    re.IGNORECASE,
)
XSS_RE = re.compile(
    r"(?:<script|%3cscript|onerror\s*=|onload\s*=|javascript:)",
    re.IGNORECASE,
)
SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/phpinfo",
    "/admin",
    "/actuator",
    "/backup",
    "/config.php",
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def detect_log_type(lines: list[str]) -> str:
    """Heuristically identify whether log lines come from SSH auth logs or web access logs."""
    auth_hits = 0
    web_hits = 0
    for line in lines[:50]:
        if "sshd" in line or SSH_FAILED_RE.search(line) or SSH_ACCEPTED_RE.search(line):
            auth_hits += 1
        if WEB_ACCESS_RE.search(line):
            web_hits += 1
    if auth_hits >= web_hits and auth_hits > 0:
        return "auth"
    if web_hits > 0:
        return "web"
    return "auth"


def analyze_auth_lines(lines: list[str], *, threshold: int = 5) -> dict[str, Any]:
    """Analyze Linux SSH/auth log lines for brute force, enumeration, and compromise."""
    failed_by_ip: Counter[str] = Counter()
    invalid_users_by_ip: dict[str, set[str]] = defaultdict(set)
    accepted_by_ip: dict[str, list[str]] = defaultdict(list)

    for line in lines:
        if match := SSH_FAILED_RE.search(line):
            failed_by_ip[match.group("ip")] += 1
        if match := SSH_INVALID_USER_RE.search(line):
            invalid_users_by_ip[match.group("ip")].add(match.group("user"))
        if match := SSH_ACCEPTED_RE.search(line):
            accepted_by_ip[match.group("ip")].append(match.group("user"))

    findings: list[dict[str, Any]] = []
    suspicious_ips: set[str] = set()

    for ip, fail_count in failed_by_ip.items():
        if fail_count >= threshold:
            suspicious_ips.add(ip)
            findings.append(
                {
                    "severity": "HIGH",
                    "rule": "SSH Brute Force Detected",
                    "mitre_attack": "T1110 - Brute Force",
                    "source_ip": ip,
                    "evidence_count": fail_count,
                    "details": f"{fail_count} tentativas falhas de autenticacao SSH a partir de {ip}.",
                    "recommendation": (
                        "Bloquear IP no firewall/fail2ban, desabilitar autenticacao por senha "
                        "e exigir chaves SSH."
                    ),
                }
            )
            if ip in accepted_by_ip:
                users = sorted(set(accepted_by_ip[ip]))
                findings.append(
                    {
                        "severity": "CRITICAL",
                        "rule": "Successful Login After Brute Force",
                        "mitre_attack": "T1110 / T1078 - Valid Accounts",
                        "source_ip": ip,
                        "evidence_count": len(accepted_by_ip[ip]),
                        "details": (
                            f"IP {ip} obteve login bem-sucedido para conta(s) {', '.join(users)} "
                            f"apos {fail_count} falhas!"
                        ),
                        "recommendation": (
                            "Isolar o host, revogar sessoes/credenciais das contas afetadas e "
                            "iniciar investigacao de incidente (IR)."
                        ),
                    }
                )

    for ip, users in invalid_users_by_ip.items():
        if len(users) >= 3:
            suspicious_ips.add(ip)
            findings.append(
                {
                    "severity": "MEDIUM",
                    "rule": "SSH Username Enumeration",
                    "mitre_attack": "T1589.001 - Gather Victim Identity Information",
                    "source_ip": ip,
                    "evidence_count": len(users),
                    "details": (
                        f"IP {ip} testou {len(users)} usuarios inexistentes "
                        f"(ex: {', '.join(sorted(users)[:5])})."
                    ),
                    "recommendation": (
                        "Restringir acesso a porta 22 por allowlist/VPN e ativar rate limiting."
                    ),
                }
            )

    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], -item["evidence_count"]))

    return {
        "log_type": "auth",
        "total_lines": len(lines),
        "failed_auth_events": sum(failed_by_ip.values()),
        "successful_auth_events": sum(len(v) for v in accepted_by_ip.values()),
        "suspicious_ips": sorted(suspicious_ips),
        "findings_count": len(findings),
        "findings": findings,
    }


def analyze_web_lines(lines: list[str], *, threshold: int = 5) -> dict[str, Any]:
    """Analyze Nginx/Apache web access logs for OWASP attack probes and recon."""
    sqli_by_ip: Counter[str] = Counter()
    traversal_by_ip: Counter[str] = Counter()
    xss_by_ip: Counter[str] = Counter()
    sensitive_by_ip: dict[str, set[str]] = defaultdict(set)
    not_found_by_ip: Counter[str] = Counter()
    parsed_requests = 0

    for line in lines:
        match = WEB_ACCESS_RE.search(line)
        if not match:
            continue

        parsed_requests += 1
        ip = match.group("ip")
        path = match.group("path")
        status = int(match.group("status"))
        lowered_path = path.lower()

        if SQLI_RE.search(path):
            sqli_by_ip[ip] += 1
        if TRAVERSAL_RE.search(path):
            traversal_by_ip[ip] += 1
        if XSS_RE.search(path):
            xss_by_ip[ip] += 1
        if any(lowered_path.startswith(sensitive) for sensitive in SENSITIVE_PATHS):
            sensitive_by_ip[ip].add(path)
        if status in (403, 404):
            not_found_by_ip[ip] += 1

    findings: list[dict[str, Any]] = []
    suspicious_ips: set[str] = set()

    for ip, count in sqli_by_ip.items():
        suspicious_ips.add(ip)
        findings.append(
            {
                "severity": "HIGH",
                "rule": "SQL Injection Probe Detected",
                "mitre_attack": "T1190 - Exploit Public-Facing Application",
                "source_ip": ip,
                "evidence_count": count,
                "details": f"{count} requisicao(oes) com padrao de SQL Injection vindas de {ip}.",
                "recommendation": "Garantir queries parametrizadas/ORM e ativar regras de WAF.",
            }
        )

    for ip, count in traversal_by_ip.items():
        suspicious_ips.add(ip)
        findings.append(
            {
                "severity": "HIGH",
                "rule": "Path Traversal / LFI Probe Detected",
                "mitre_attack": "T1190 - Exploit Public-Facing Application",
                "source_ip": ip,
                "evidence_count": count,
                "details": f"{count} tentativa(s) de Path Traversal/LFI vindas de {ip}.",
                "recommendation": (
                    "Validar e normalizar caminhos de arquivo no servidor e restringir diretorios."
                ),
            }
        )

    for ip, count in xss_by_ip.items():
        suspicious_ips.add(ip)
        findings.append(
            {
                "severity": "MEDIUM",
                "rule": "XSS Probe Detected",
                "mitre_attack": "T1189 - Drive-by Compromise",
                "source_ip": ip,
                "evidence_count": count,
                "details": f"{count} payload(s) suspeito(s) de XSS vindos de {ip}.",
                "recommendation": "Aplicar output encoding e Content-Security-Policy (CSP).",
            }
        )

    for ip, paths in sensitive_by_ip.items():
        suspicious_ips.add(ip)
        findings.append(
            {
                "severity": "MEDIUM",
                "rule": "Sensitive Endpoint Reconnaissance",
                "mitre_attack": "T1595.003 - Wordlist Scanning",
                "source_ip": ip,
                "evidence_count": len(paths),
                "details": (
                    f"IP {ip} buscou caminhos sensiveis: {', '.join(sorted(paths)[:5])}."
                ),
                "recommendation": (
                    "Garantir que arquivos .env/.git nao sejam servidos e bloquear scanners."
                ),
            }
        )

    for ip, count in not_found_by_ip.items():
        if count >= threshold:
            suspicious_ips.add(ip)
            findings.append(
                {
                    "severity": "MEDIUM",
                    "rule": "Directory / Endpoint Enumeration Scan",
                    "mitre_attack": "T1595.003 - Wordlist Scanning",
                    "source_ip": ip,
                    "evidence_count": count,
                    "details": f"IP {ip} gerou {count} respostas HTTP 403/404 (possivel fuzzing/scan).",
                    "recommendation": "Aplicar rate limiting por IP no proxy reverso ou WAF.",
                }
            )

    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], -item["evidence_count"]))

    return {
        "log_type": "web",
        "total_lines": len(lines),
        "parsed_requests": parsed_requests,
        "suspicious_ips": sorted(suspicious_ips),
        "findings_count": len(findings),
        "findings": findings,
    }


def analyze_log_file(
    file_path: str | Path,
    *,
    log_type: str = "auto",
    threshold: int = 5,
) -> dict[str, Any]:
    """Read and analyze a log file for suspicious patterns and IOCs."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo de log nao encontrado: {path}")

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    selected_type = detect_log_type(lines) if log_type == "auto" else log_type

    if selected_type == "auth":
        result = analyze_auth_lines(lines, threshold=threshold)
    elif selected_type == "web":
        result = analyze_web_lines(lines, threshold=threshold)
    else:
        raise ValueError(f"Tipo de log nao suportado: '{selected_type}'. Use 'auto', 'auth' ou 'web'.")

    result["file"] = str(path)
    return result
