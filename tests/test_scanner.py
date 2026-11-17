"""
AegisSec: Automated Unit & Security Regression Test Suite
Validates detection accuracy, masking, and SARIF output compliance.
"""

import unittest
import os
import tempfile
import json
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.scanner import (
    scan_secrets,
    scan_code_vulnerabilities,
    scan_packages,
    calculate_security_score,
    to_sarif,
    parse_semver,
)


class TestAegisSecEngine(unittest.TestCase):

    def test_secret_detection_and_masking(self):
        """Verify that AWS and Stripe keys are flagged and masked."""
        dummy_stripe = "sk_" + "live_" + "MOCKKEY12345678901234567890"
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".py") as tf:
            tf.write("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
            tf.write(f"STRIPE = '{dummy_stripe}'\n")
            temp_path = tf.name

        try:
            findings = scan_secrets(temp_path)
            self.assertEqual(len(findings), 2)
            # Test that secret is masked and doesn't expose the full token in logs
            for f in findings:
                self.assertIn("...", f["masked_match"])
                self.assertEqual(f["severity"], "CRITICAL")
        finally:
            os.remove(temp_path)

    def test_sql_injection_detection(self):
        """Verify that dynamic SQL string interpolation is flagged."""
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".py") as tf:
            tf.write("query = f'SELECT * FROM users WHERE id = {user_id}'\n")
            tf.write("cursor.execute(query)\n")
            temp_path = tf.name

        try:
            findings = scan_code_vulnerabilities(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule_id"], "SAST-001")
            self.assertEqual(findings[0]["severity"], "HIGH")
            self.assertEqual(findings[0]["cwe"], "CWE-89")
        finally:
            os.remove(temp_path)

    def test_semver_parser_and_sca(self):
        """Verify semver comparisons for dependency checking."""
        self.assertTrue(parse_semver("0.12.0") < parse_semver("2.0.0"))
        self.assertTrue(parse_semver("2.18.0") < parse_semver("2.20.0"))
        self.assertFalse(parse_semver("3.0.0") < parse_semver("2.0.0"))

        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as tf:
            tf.write("flask==0.12.0\n")
            tf.write("requests==2.31.0\n")  # Safe
            temp_path = tf.name

        try:
            findings = scan_packages(temp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["package"], "flask")
        finally:
            os.remove(temp_path)

    def test_posture_score_calculation(self):
        """Verify posture scoring deductions and grade assignment."""
        mock_findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]
        # 100 - 25 - 15 - 10 = 50
        result = calculate_security_score(mock_findings)
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["grade"], "D (High Risk)")

        # Empty findings = 100 / Grade A
        clean_result = calculate_security_score([])
        self.assertEqual(clean_result["score"], 100)
        self.assertEqual(clean_result["grade"], "A (Excellent)")

    def test_sarif_export_format(self):
        """Verify OASIS SARIF 2.1.0 output complies with schema requirements."""
        mock_report = {
            "findings": [
                {
                    "rule_id": "SEC-001",
                    "severity": "CRITICAL",
                    "title": "Exposed AWS Access Key",
                    "recommendation": "Rotate key",
                    "file": "app.py",
                    "line": 10,
                }
            ]
        }
        sarif = to_sarif(mock_report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "AegisSec")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
