"""Concurrent TCP port scanner with common service identification and optional banner grabbing."""

from __future__ import annotations

import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

COMMON_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def parse_ports(port_spec: str) -> list[int]:
    """Parse a comma-separated port list and/or ranges (e.g. '22,80,443,8000-8005')."""
    ports: set[int] = set()
    for part in port_spec.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            bounds = token.split("-", maxsplit=1)
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise ValueError(f"Intervalo de portas invalido: '{token}'")
            start, end = int(bounds[0]), int(bounds[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Intervalo fora do limite (1-65535): '{token}'")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Porta invalida: '{token}'")
            port = int(token)
            if port < 1 or port > 65535:
                raise ValueError(f"Porta fora do limite (1-65535): {port}")
            ports.add(port)

    if not ports:
        raise ValueError("Nenhuma porta valida foi informada.")
    return sorted(ports)


def scan_port(
    host: str,
    port: int,
    *,
    timeout: float = 1.0,
    grab_banner: bool = False,
) -> dict[str, Any]:
    """Check whether a single TCP port is open and optionally grab a service banner."""
    service = COMMON_SERVICES.get(port, "unknown")
    banner: str | None = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        is_open = result == 0

        if is_open and grab_banner:
            try:
                if port in (80, 8080):
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii"))
                raw = sock.recv(256)
                decoded = raw.decode("utf-8", errors="replace").strip()
                if decoded:
                    banner = decoded.splitlines()[0][:120]
            except OSError:
                banner = None

    return {
        "port": port,
        "state": "open" if is_open else "closed",
        "service": service,
        "banner": banner,
    }


def scan_ports(
    host: str,
    ports: Iterable[int] | None = None,
    *,
    timeout: float = 1.0,
    max_workers: int = 50,
    grab_banner: bool = False,
) -> dict[str, Any]:
    """Scan multiple TCP ports concurrently on a target host."""
    target_ports = sorted(set(ports if ports is not None else DEFAULT_PORTS))
    if not target_ports:
        raise ValueError("Lista de portas nao pode ser vazia.")

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Nao foi possivel resolver o host '{host}': {exc}") from exc

    open_ports: list[dict[str, Any]] = []
    closed_count = 0

    worker_count = max(1, min(max_workers, len(target_ports)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                scan_port,
                resolved_ip,
                port,
                timeout=timeout,
                grab_banner=grab_banner,
            ): port
            for port in target_ports
        }
        for future in as_completed(futures):
            port_result = future.result()
            if port_result["state"] == "open":
                open_ports.append(port_result)
            else:
                closed_count += 1

    open_ports.sort(key=lambda item: item["port"])

    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "scanned_count": len(target_ports),
        "open_count": len(open_ports),
        "closed_count": closed_count,
        "open_ports": open_ports,
    }
