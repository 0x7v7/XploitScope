import unittest

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
                        "body": "SQL syntax error in MySQL",
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
                        "body": "SQL syntax error in MySQL",
                    }
                ],
                "modules": ["sqli"],
            }
        )

        self.assertEqual(
            result["findings"][0]["url"],
            "https://local.test/path?token=%5BREDACTED%5D&view=%5BREDACTED%5D",
        )

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
                        "body": "SQL syntax error in MySQL",
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
