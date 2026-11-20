"""Validated, cross-platform concurrent ICMP ping sweep utility."""

from __future__ import annotations

import ipaddress
import platform
import shutil
import subprocess  # nosec B404
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

MAX_ALLOWED_HOSTS = 1024


def _build_ping_command(ping_binary: str, ip: str, timeout: float) -> list[str]:
    if platform.system().lower() == "windows":
        timeout_ms = max(100, int(timeout * 1000))
        return [ping_binary, "-n", "1", "-w", str(timeout_ms), ip]
    timeout_sec = max(1, int(timeout))
    return [ping_binary, "-c", "1", "-W", str(timeout_sec), ip]


def _ping_host(ping_binary: str, ip: str, timeout: float) -> bool:
    cmd = _build_ping_command(ping_binary, ip, timeout)
    result = subprocess.run(  # nosec B603
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def ping_sweep(
    network_cidr: str,
    *,
    timeout: float = 1.0,
    max_workers: int = 50,
    max_hosts: int = MAX_ALLOWED_HOSTS,
) -> dict[str, Any]:
    """Perform a concurrent ICMP ping sweep over an IPv4 CIDR network."""
    try:
        network = ipaddress.IPv4Network(network_cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(
            f"Rede CIDR invalida '{network_cidr}'. Exemplo valido: 192.168.1.0/24"
        ) from exc

    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        hosts = [str(network.network_address)]

    if len(hosts) > max_hosts:
        raise ValueError(
            f"A rede {network} possui {len(hosts)} hosts, excedendo o limite seguro de {max_hosts}."
        )

    ping_binary = shutil.which("ping")
    if not ping_binary:
        raise RuntimeError("Binario 'ping' nao encontrado no sistema.")

    alive_hosts: list[str] = []
    worker_count = max(1, min(max_workers, len(hosts)))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_ping_host, ping_binary, ip, timeout): ip
            for ip in hosts
        }
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive_hosts.append(ip)

    alive_hosts.sort(key=ipaddress.IPv4Address)

    return {
        "network": str(network),
        "total_hosts": len(hosts),
        "alive_count": len(alive_hosts),
        "alive_hosts": alive_hosts,
    }
