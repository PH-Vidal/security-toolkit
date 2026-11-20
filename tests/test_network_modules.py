"""Unit tests for port_scanner and ping_sweep modules."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from security_toolkit.ping_sweep import ping_sweep
from security_toolkit.port_scanner import parse_ports, scan_ports


class TestPortScanner(unittest.TestCase):
    def test_parse_ports_list_and_range(self) -> None:
        self.assertEqual(parse_ports("443, 22, 8000-8002"), [22, 443, 8000, 8001, 8002])

    def test_parse_ports_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("0,70000")
        with self.assertRaises(ValueError):
            parse_ports("abc")

    @patch("security_toolkit.port_scanner.socket.gethostbyname", return_value="127.0.0.1")
    @patch("security_toolkit.port_scanner.socket.socket")
    def test_scan_ports_open_and_closed(
        self,
        mock_socket_cls: MagicMock,
        _mock_resolve: MagicMock,
    ) -> None:
        def make_socket(*_args, **_kwargs):
            sock = MagicMock()
            sock.__enter__.return_value = sock
            sock.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 1
            return sock

        mock_socket_cls.side_effect = make_socket

        result = scan_ports("localhost", [80, 9999], max_workers=2)
        self.assertEqual(result["resolved_ip"], "127.0.0.1")
        self.assertEqual(result["open_count"], 1)
        self.assertEqual(result["closed_count"], 1)
        self.assertEqual(result["open_ports"][0]["port"], 80)
        self.assertEqual(result["open_ports"][0]["service"], "HTTP")


class TestPingSweep(unittest.TestCase):
    def test_invalid_cidr_raises(self) -> None:
        with self.assertRaises(ValueError):
            ping_sweep("--evil-flag")

    def test_oversized_network_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ping_sweep("10.0.0.0/16")

    @patch("security_toolkit.ping_sweep.shutil.which", return_value="/bin/ping")
    @patch("security_toolkit.ping_sweep.subprocess.run")
    def test_ping_sweep_finds_alive_hosts(
        self,
        mock_run: MagicMock,
        _mock_which: MagicMock,
    ) -> None:
        def fake_ping(cmd, **_kwargs):
            proc = MagicMock()
            proc.returncode = 0 if cmd[-1] == "192.0.2.1" else 1
            return proc

        mock_run.side_effect = fake_ping

        result = ping_sweep("192.0.2.0/30", max_workers=2)
        self.assertEqual(result["total_hosts"], 2)
        self.assertEqual(result["alive_hosts"], ["192.0.2.1"])


if __name__ == "__main__":
    unittest.main()
