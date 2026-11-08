"""Passive reflection indicators for values explicitly supplied with a snapshot."""

from xploitscope_detector.common import finding

NAME = "xss"
DESCRIPTION = "Looks for exact caller-supplied values reflected in a saved response."
MODE = "passive"


def inspect(observation):
    body = observation.get("body", "")
    values = observation.get("reflected_values", [])
    if not isinstance(body, str) or not isinstance(values, list):
        return []
    results = []
    for value in values[:100]:
        if not isinstance(value, str) or not value or value not in body:
            continue
        results.append(
            finding(
                NAME,
                "Supplied value is reflected in the response",
                "low",
                4,
                str(observation.get("url", "")),
                "A caller-supplied value occurs verbatim in the saved response.",
                "Review output encoding in its rendering context. Reflection alone does not confirm XSS.",
                owasp="A05:2025 Injection",
                location="response body",
            )
        )
    return results
