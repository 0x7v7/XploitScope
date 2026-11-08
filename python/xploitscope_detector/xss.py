"""Passive reflection indicators for values explicitly supplied with a snapshot."""

import re

from xploitscope_detector.common import finding

NAME = "xss"
DESCRIPTION = "Looks for exact caller-supplied values reflected in a saved response."
MODE = "passive"

_ACTIVE_MARKUP = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b"
    r"|<[^>]+\bon[a-z][a-z0-9_-]*\s*="
    r"|<[^>]+\b(?:href|src)\s*=\s*['\"]?\s*javascript\s*:",
    re.IGNORECASE,
)


def inspect(observation):
    body = observation.get("body", "")
    values = observation.get("reflected_values", [])
    if not isinstance(body, str) or not isinstance(values, list):
        return []
    results = []
    seen_lines = set()
    for value in values[:100]:
        if not isinstance(value, str) or not value:
            continue
        position = body.find(value)
        if position < 0 or not _ACTIVE_MARKUP.search(value):
            continue
        line = body.count("\n", 0, position) + 1
        if line in seen_lines:
            continue
        seen_lines.add(line)
        results.append(
            finding(
                NAME,
                "Raw active HTML markup is reflected in the response",
                "medium",
                5,
                str(observation.get("url", "")),
                "A caller-supplied value containing an active markup pattern occurs verbatim in the response; execution is not confirmed.",
                "Review contextual output encoding and sanitizer behavior. Validate in a controlled environment; reflection alone does not confirm XSS.",
                owasp="A05:2025 Injection",
                location=f"response body, line {line}",
            )
        )
    return results
