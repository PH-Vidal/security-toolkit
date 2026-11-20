"""Security Toolkit — Modular CLI for DevSecOps, Network Recon, Web/TLS Audit, and Log Analysis."""

from security_toolkit.hash_generator import generate_hash, hash_file, verify_hash
from security_toolkit.http_auditor import audit_http_headers, audit_tls, audit_url
from security_toolkit.log_analyzer import analyze_log_file
from security_toolkit.password_checker import calculate_entropy, check_password
from security_toolkit.ping_sweep import ping_sweep
from security_toolkit.port_scanner import parse_ports, scan_ports

__version__ = "2.0.0"

__all__ = [
    "__version__",
    "analyze_log_file",
    "audit_http_headers",
    "audit_tls",
    "audit_url",
    "calculate_entropy",
    "check_password",
    "generate_hash",
    "hash_file",
    "parse_ports",
    "ping_sweep",
    "scan_ports",
    "verify_hash",
]
