"""Passive indicators for database errors disclosed in saved response bodies."""

import re

from xploitscope_detector.common import finding

NAME = "sqli"
DESCRIPTION = "Flags recognizable database error text in supplied response snapshots."
MODE = "passive"

_ERROR_PATTERNS = (
    re.compile(r"You have an error in your SQL syntax.{0,200}(?:MySQL|MariaDB)", re.IGNORECASE | re.DOTALL),
    re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"\bsqlite3?\.OperationalError\s*:", re.IGNORECASE),
    re.compile(r"\bORA-\d{5}\b"),
    re.compile(
        r"\b(?:psycopg2?\.errors\.\w+|(?:PostgreSQL\s+)?ERROR:\s*syntax error at or near)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\[(?:Microsoft|SQL Server)\].{0,160}\b(?:syntax|statement|query)\b", re.IGNORECASE | re.DOTALL),
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
                    "Database-specific error signature appears in the response",
                    "medium",
                    6,
                    str(observation.get("url", "")),
                    match.group(0)[:200],
                    "Review server-side error handling and query parameterization. Error disclosure alone does not confirm SQL injection.",
                    owasp="A05:2025 Injection",
                    location=f"response body, line {line}",
                )
            ]
    return []
