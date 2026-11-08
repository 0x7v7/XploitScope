"""Passive indicators for database errors disclosed in saved response bodies."""

import re

from xploitscope_detector.common import finding

NAME = "sqli"
DESCRIPTION = "Flags recognizable database error text in supplied response snapshots."
MODE = "passive"

_ERROR_PATTERNS = (
    re.compile(r"SQL syntax.*?(?:MySQL|MariaDB)", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"sqlite(?:3)?\.OperationalError", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
)


def inspect(observation):
    body = observation.get("body", "")
    if not isinstance(body, str):
        return []
    for pattern in _ERROR_PATTERNS:
        match = pattern.search(body)
        if match:
            line = body.count("\n", 0, match.start()) + 1
            return [
                finding(
                    NAME,
                    "Database error text appears in the response",
                    "medium",
                    6,
                    str(observation.get("url", "")),
                    match.group(0)[:200],
                    "Review server-side error handling. This indicator alone does not confirm SQL injection.",
                    owasp="A05:2025 Injection",
                    location=f"response body, line {line}",
                )
            ]
    return []
