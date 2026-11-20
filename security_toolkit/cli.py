"""Unified command-line interface for Security Toolkit."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any

from security_toolkit import __version__
from security_toolkit.hash_generator import generate_hash, hash_file, verify_hash
from security_toolkit.http_auditor import audit_url
from security_toolkit.log_analyzer import analyze_log_file
from security_toolkit.password_checker import check_password
from security_toolkit.ping_sweep import ping_sweep
from security_toolkit.port_scanner import DEFAULT_PORTS, parse_ports, scan_ports


def _configure_stdio() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def _print_human(command: str, result: dict[str, Any]) -> None:
    if command == "hash":
        if "matched" in result:
            status = "OK (MATCH)" if result["matched"] else "MISMATCH (ALERTA)"
            print(f"[Hash Verify] Status: {status}")
            print(f"  Algorithm: {result['algorithm'].upper()}")
            print(f"  Expected:  {result['expected']}")
            print(f"  Actual:    {result['actual']}")
        else:
            if "file" in result:
                print(f"[Hash File] {result['file']} ({result['size_bytes']} bytes)")
            else:
                print("[Hash Text]")
            print(f"  MD5:    {result['md5']}")
            print(f"  SHA256: {result['sha256']}")
            print(f"  SHA512: {result['sha512']}")
        return

    if command == "password":
        print(
            f"[Password Audit] Strength: {result['strength']} "
            f"(Score: {result['score']}/100 | Entropy: {result['entropy_bits']} bits)"
        )
        if result["recommendations"]:
            print("  Recommendations:")
            for tip in result["recommendations"]:
                print(f"    - {tip}")
        return

    if command == "ports":
        print(
            f"[Port Scan] Host: {result['host']} ({result['resolved_ip']}) | "
            f"Open: {result['open_count']}/{result['scanned_count']}"
        )
        for item in result["open_ports"]:
            banner_txt = f" | Banner: {item['banner']}" if item["banner"] else ""
            print(f"  [OPEN] {item['port']}/tcp ({item['service']}){banner_txt}")
        return

    if command == "ping":
        print(
            f"[Ping Sweep] Network: {result['network']} | "
            f"Alive: {result['alive_count']}/{result['total_hosts']}"
        )
        for ip in result["alive_hosts"]:
            print(f"  [ALIVE] {ip}")
        return

    if command == "http-audit":
        headers_audit = result["headers_audit"]
        print(
            f"[HTTP Audit] {result['url']} (HTTP {result['status_code']}) | "
            f"Grade: {headers_audit['grade']} ({headers_audit['score']}/100)"
        )
        if headers_audit["missing_headers"]:
            print("  Missing Security Headers:")
            for item in headers_audit["missing_headers"]:
                print(f"    - {item['header']}: {item['recommendation']}")
        if headers_audit["warnings"]:
            print("  Warnings:")
            for warning in headers_audit["warnings"]:
                print(f"    ! {warning}")
        tls_audit = result.get("tls_audit")
        if tls_audit:
            print(
                f"  [TLS] Protocol: {tls_audit['protocol']} | Cipher: {tls_audit['cipher']} | "
                f"Expires in: {tls_audit['days_until_expiry']} days"
            )
            for warning in tls_audit["warnings"]:
                print(f"    ! {warning}")
        return

    if command == "log-analyze":
        print(
            f"[Log Analyzer] File: {result['file']} | Type: {result['log_type']} | "
            f"Findings: {result['findings_count']} | Suspicious IPs: {len(result['suspicious_ips'])}"
        )
        for finding in result["findings"]:
            print(
                f"  [{finding['severity']}] {finding['rule']} "
                f"({finding['mitre_attack']}) -> IP: {finding['source_ip']}"
            )
            print(f"    Details: {finding['details']}")
            print(f"    Action:  {finding['recommendation']}")
        return

    print(json.dumps(result, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sec-toolkit",
        description="Security Toolkit — CLI modular para DevSecOps, Recon, Web/TLS Audit e Blue Team.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", dest="as_json", help="Exibir saida em JSON.")
    common.add_argument("--output", type=str, help="Salvar relatorio JSON em um arquivo.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # hash
    hash_p = subparsers.add_parser(
        "hash", parents=[common], help="Gerar ou verificar hashes MD5, SHA-256 e SHA-512."
    )
    hash_target = hash_p.add_mutually_exclusive_group(required=True)
    hash_target.add_argument("--text", type=str, help="Texto de entrada.")
    hash_target.add_argument("--file", type=str, help="Caminho do arquivo para calculo de integridade.")
    hash_p.add_argument("--verify", type=str, help="Hash esperado para verificacao de integridade.")

    # password
    pwd_p = subparsers.add_parser(
        "password", parents=[common], help="Avaliar forca e entropia de senha (NIST SP 800-63B)."
    )
    pwd_p.add_argument(
        "--password",
        type=str,
        default=None,
        help="Senha a avaliar (se omitido, solicita com entrada oculta).",
    )

    # ports
    port_p = subparsers.add_parser(
        "ports", parents=[common], help="Scanner TCP concorrente com deteccao de servicos e banners."
    )
    port_p.add_argument("--host", required=True, help="Hostname ou IP alvo (apenas alvos autorizados).")
    port_p.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Lista/intervalo de portas (ex: 22,80,443,8000-8010).",
    )
    port_p.add_argument("--timeout", type=float, default=1.0, help="Timeout por porta em segundos.")
    port_p.add_argument("--workers", type=int, default=50, help="Numero maximo de threads.")
    port_p.add_argument("--banner", action="store_true", help="Tentar capturar banner do servico.")

    # ping
    ping_p = subparsers.add_parser(
        "ping", parents=[common], help="Descoberta ICMP concorrente de hosts em uma rede CIDR."
    )
    ping_p.add_argument(
        "--network",
        required=True,
        help="Rede IPv4 em formato CIDR (ex: 192.168.1.0/24).",
    )
    ping_p.add_argument("--timeout", type=float, default=1.0, help="Timeout por host em segundos.")
    ping_p.add_argument("--workers", type=int, default=50, help="Numero maximo de threads.")

    # http-audit
    http_p = subparsers.add_parser(
        "http-audit", parents=[common], help="Auditoria de headers HTTP de seguranca e certificado TLS."
    )
    http_p.add_argument("--url", required=True, help="URL alvo (ex: https://example.com).")
    http_p.add_argument("--timeout", type=float, default=5.0, help="Timeout da conexao em segundos.")
    http_p.add_argument("--skip-tls", action="store_true", help="Pular inspecao do certificado TLS.")

    # log-analyze
    log_p = subparsers.add_parser(
        "log-analyze",
        parents=[common],
        help="Analise Blue Team de logs (SSH auth / Web access) com mapeamento MITRE ATT&CK.",
    )
    log_p.add_argument("--file", required=True, help="Caminho do arquivo de log.")
    log_p.add_argument(
        "--type",
        choices=("auto", "auth", "web"),
        default="auto",
        help="Formato do log (default: auto).",
    )
    log_p.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Limite de eventos para alertar brute force / enumeracao (default: 5).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result: dict[str, Any]
        if args.command == "hash":
            if args.verify:
                target = args.file if args.file else args.text
                result = verify_hash(target, args.verify, is_file=bool(args.file))
            elif args.file:
                result = hash_file(args.file)
            else:
                result = generate_hash(args.text)

        elif args.command == "password":
            secret = args.password if args.password is not None else getpass.getpass("Digite a senha: ")
            result = check_password(secret)

        elif args.command == "ports":
            ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
            result = scan_ports(
                args.host,
                ports,
                timeout=args.timeout,
                max_workers=args.workers,
                grab_banner=args.banner,
            )

        elif args.command == "ping":
            result = ping_sweep(args.network, timeout=args.timeout, max_workers=args.workers)

        elif args.command == "http-audit":
            result = audit_url(args.url, timeout=args.timeout, check_tls=not args.skip_tls)

        elif args.command == "log-analyze":
            result = analyze_log_file(args.file, log_type=args.type, threshold=args.threshold)

        else:
            parser.error(f"Comando desconhecido: {args.command}")
            return 2

    except (ValueError, FileNotFoundError, RuntimeError, OSError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_human(args.command, result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
