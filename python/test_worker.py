import unittest
from unittest.mock import patch

from xploitscope_detector import analyze, module_descriptions
from xploitscope_detector.worker import handle


class WorkerProtocolTests(unittest.TestCase):
    def test_ping_returns_ready_response(self):
        response = handle({"version": 1, "id": "test-1", "type": "ping"})

        self.assertEqual(response["version"], 1)
        self.assertEqual(response["id"], "test-1")
        self.assertEqual(response["type"], "pong")
        self.assertEqual(response["payload"], {"status": "ready"})

    def test_rejects_unsupported_protocol_version(self):
        with self.assertRaisesRegex(ValueError, "unsupported protocol version"):
            handle({"version": 2, "id": "test-2", "type": "ping"})

    def test_rejects_unsupported_request_type(self):
        with self.assertRaisesRegex(ValueError, "unsupported request type"):
            handle({"version": 1, "id": "test-3", "type": "scan"})

    def test_lists_separate_detection_modules(self):
        names = {module["name"] for module in module_descriptions()}

        self.assertTrue({"headers", "cookies", "cors", "sqli", "xss", "ssrf", "access_control"} <= names)

    def test_analyzes_saved_observation_without_network_activity(self):
        result = analyze(
            {
                "observations": [
                    {
                        "url": "https://local.test/",
                        "headers": {"Set-Cookie": "session=redacted; Path=/"},
                        "body": "You have an error in your SQL syntax; check the manual for your MySQL server version",
                        "reflected_values": [],
                    }
                ]
            }
        )

        self.assertEqual(result["analysis_mode"], "offline_passive")
        self.assertEqual(result["observation_count"], 1)
        modules = {finding["module"] for finding in result["findings"]}
        self.assertTrue({"cookies", "headers", "sqli"} <= modules)
        self.assertTrue(all(finding["status"] == "potential" for finding in result["findings"]))
        sql_finding = next(finding for finding in result["findings"] if finding["module"] == "sqli")
        self.assertEqual(sql_finding["owasp"], "A05:2025 Injection")
        self.assertEqual(sql_finding["location"], "response body, line 1")

    def test_cors_flags_reflected_origin_with_credentials(self):
        result = analyze(
            {
                "observations": [
                    {
                        "url": "https://local.test/",
                        "request_headers": {"Origin": "https://untrusted.test"},
                        "headers": {
                            "Access-Control-Allow-Origin": "https://untrusted.test",
                            "Access-Control-Allow-Credentials": "true",
                        },
                    }
                ],
                "modules": ["cors"],
            }
        )

        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["module"], "cors")
        self.assertEqual(finding["owasp"], "A02:2025 Security Misconfiguration")

    def test_analysis_redacts_query_values_in_finding_urls(self):
        result = analyze(
            {
                "observations": [
                    {
                        "url": "https://local.test/path?token=secret&view=1#fragment",
                        "headers": {},
                        "body": "You have an error in your SQL syntax; check the manual for your MySQL server version",
                    }
                ],
                "modules": ["sqli"],
            }
        )

        self.assertEqual(
            result["findings"][0]["url"],
            "https://local.test/path?token=%5BREDACTED%5D&view=%5BREDACTED%5D",
        )

    def test_sqli_ignores_generic_database_documentation(self):
        result = analyze(
            {
                "observations": [
                    {
                        "url": "https://local.test/docs",
                        "body": "PostgreSQL documentation says ERROR handling should be generic.",
                    }
                ],
                "modules": ["sqli"],
            }
        )

        self.assertEqual(result["findings"], [])

    def test_sqli_detects_vendor_error_signatures(self):
        samples = (
            "You have an error in your SQL syntax; check the manual for your MySQL server version",
            "sqlite3.OperationalError: no such table: users",
            "ORA-00933: SQL command not properly ended",
            "ERROR: syntax error at or near \"FROM\"",
            "Unclosed quotation mark after the character string",
        )
        for body in samples:
            with self.subTest(body=body):
                result = analyze(
                    {
                        "observations": [{"url": "https://local.test/", "body": body}],
                        "modules": ["sqli"],
                    }
                )
                self.assertEqual(len(result["findings"]), 1)

    def test_xss_ignores_benign_reflection(self):
        result = analyze(
            {
                "observations": [
                    {"url": "https://local.test/", "body": "Hello Alice", "reflected_values": ["Alice"]}
                ],
                "modules": ["xss"],
            }
        )

        self.assertEqual(result["findings"], [])

    def test_xss_ignores_html_escaped_reflection(self):
        value = "<img src=x onerror=handler>"
        result = analyze(
            {
                "observations": [
                    {
                        "url": "https://local.test/",
                        "body": "&lt;img src=x onerror=handler&gt;",
                        "reflected_values": [value],
                    }
                ],
                "modules": ["xss"],
            }
        )

        self.assertEqual(result["findings"], [])

    def test_xss_flags_raw_active_markup_with_location(self):
        value = "<img src=x onerror=handler>"
        result = analyze(
            {
                "observations": [
                    {
                        "url": "https://local.test/",
                        "body": "safe content\n" + value,
                        "reflected_values": [value],
                    }
                ],
                "modules": ["xss"],
            }
        )

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["location"], "response body, line 2")
        self.assertEqual(result["findings"][0]["status"], "potential")

    def test_failed_module_is_reported_and_other_checks_continue(self):
        observation = {
            "url": "https://local.test/",
            "headers": {},
            "body": "You have an error in your SQL syntax; check the manual for your MySQL server version",
        }
        with patch("xploitscope_detector.sqli.inspect", side_effect=RuntimeError("internal detail")):
            result = analyze({"observations": [observation]})

        self.assertEqual(result["module_errors"], [{
            "module": "sqli",
            "error": "RuntimeError",
            "message": "Check failed at observation 0; remaining checks continued.",
        }])
        self.assertFalse(any(finding["module"] == "sqli" for finding in result["findings"]))
        self.assertTrue(any(finding["module"] == "headers" for finding in result["findings"]))

    def test_rejects_empty_observations(self):
        with self.assertRaisesRegex(ValueError, "non-empty observations"):
            analyze({"observations": []})

    def test_runs_only_selected_modules(self):
        result = analyze(
            {
                "observations": [
                    {
                        "url": "http://local.test/",
                        "headers": {},
                        "body": "You have an error in your SQL syntax; check the manual for your MySQL server version",
                    }
                ],
                "modules": ["sqli"],
            }
        )

        self.assertEqual(result["modules"], ["sqli"])
        self.assertEqual({finding["module"] for finding in result["findings"]}, {"sqli"})

    def test_rejects_unknown_modules(self):
        with self.assertRaisesRegex(ValueError, "unknown module"):
            analyze({"observations": [{"url": "https://local.test/"}], "modules": ["unknown"]})


if __name__ == "__main__":
    unittest.main()
