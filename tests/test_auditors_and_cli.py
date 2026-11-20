"""Unit tests for http_auditor, log_analyzer, and CLI."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from security_toolkit.cli import main
from security_toolkit.http_auditor import audit_http_headers, audit_url
from security_toolkit.log_analyzer import analyze_auth_lines, analyze_log_file, analyze_web_lines


class TestHttpAuditor(unittest.TestCase):
    def test_full_security_headers_grade_a(self) -> None:
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        result = audit_http_headers(headers, is_https=True)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["missing_headers"], [])

    def test_missing_headers_and_disclosure_flagged(self) -> None:
        headers = {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/8.1"}
        result = audit_http_headers(headers, is_https=False)
        self.assertEqual(result["grade"], "F")
        self.assertIn("server", result["information_disclosure"])
        self.assertIn("x-powered-by", result["information_disclosure"])

    def test_invalid_url_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            audit_url("file:///etc/passwd")


class TestLogAnalyzer(unittest.TestCase):
    def test_auth_log_detects_bruteforce_and_compromise(self) -> None:
        sample = Path(__file__).resolve().parent.parent / "samples" / "sample_auth.log"
        result = analyze_log_file(sample, threshold=5)
        self.assertEqual(result["log_type"], "auth")
        self.assertIn("203.0.113.45", result["suspicious_ips"])

        rules = {f["rule"] for f in result["findings"]}
        self.assertIn("SSH Brute Force Detected", rules)
        self.assertIn("Successful Login After Brute Force", rules)
        self.assertIn("SSH Username Enumeration", rules)
        self.assertEqual(result["findings"][0]["severity"], "CRITICAL")

    def test_web_log_detects_owasp_probes_and_enum(self) -> None:
        sample = Path(__file__).resolve().parent.parent / "samples" / "sample_access.log"
        result = analyze_log_file(sample, threshold=5)
        self.assertEqual(result["log_type"], "web")
        rules = {f["rule"] for f in result["findings"]}
        self.assertIn("SQL Injection Probe Detected", rules)
        self.assertIn("Path Traversal / LFI Probe Detected", rules)
        self.assertIn("XSS Probe Detected", rules)
        self.assertIn("Sensitive Endpoint Reconnaissance", rules)
        self.assertIn("Directory / Endpoint Enumeration Scan", rules)

    def test_benign_logs_produce_zero_findings(self) -> None:
        auth_line = (
            "Nov 19 02:16:02 host sshd[1]: Accepted publickey "
            "for pedro from 198.51.100.10 port 54011 ssh2"
        )
        web_line = (
            '198.51.100.12 - - [19/Nov/2026:03:01:10 +0000] '
            '"GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        )
        auth_res = analyze_auth_lines([auth_line])
        web_res = analyze_web_lines([web_line])
        self.assertEqual(auth_res["findings_count"], 0)
        self.assertEqual(web_res["findings_count"], 0)


class TestCli(unittest.TestCase):
    def test_cli_hash_json_and_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "report.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["hash", "--text", "devsecops", "--json", "--output", str(out_file)])

            self.assertEqual(code, 0)
            payload = json.loads(buf.getvalue())
            self.assertIn("sha256", payload)
            self.assertTrue(out_file.is_file())

    def test_cli_log_analyze_sample(self) -> None:
        sample = Path(__file__).resolve().parent.parent / "samples" / "sample_auth.log"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["log-analyze", "--file", str(sample), "--json"])

        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertGreaterEqual(payload["findings_count"], 3)


if __name__ == "__main__":
    unittest.main()
