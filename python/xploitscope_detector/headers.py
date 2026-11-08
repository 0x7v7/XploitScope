"""Passive checks for missing browser-facing security headers."""

from urllib.parse import urlparse

from xploitscope_detector.common import finding, header_value, headers_of

NAME = "headers"
DESCRIPTION = "Checks HTTP snapshots for common security-header omissions."
MODE = "passive"


def inspect(observation):
    headers = headers_of(observation)
    url = str(observation.get("url", ""))
    checks = (
        ("content-security-policy", "Content Security Policy is absent", "medium"),
        ("x-content-type-options", "X-Content-Type-Options is absent", "low"),
        ("referrer-policy", "Referrer-Policy is absent", "low"),
    )
    results = []
    for header, title, severity in checks:
        if not header_value(headers, header):
            results.append(
                finding(
                    NAME,
                    title,
                    severity,
                    8,
                    url,
                    f"Response does not include {header}.",
                    f"Review whether {header} should be configured for this application.",
                )
            )
    for header in ("server", "x-powered-by"):
        value = header_value(headers, header)
        if value:
            results.append(
                finding(
                    NAME,
                    f"{header} response header discloses implementation details",
                    "low",
                    7,
                    url,
                    f"{header}: {value[:120]}",
                    "Consider removing unnecessary product and version details from public response headers.",
                )
            )
    try:
        is_https = urlparse(url).scheme.lower() == "https"
    except ValueError:
        is_https = False
    if is_https and not header_value(headers, "strict-transport-security"):
        results.append(
            finding(
                NAME,
                "Strict-Transport-Security is absent",
                "low",
                8,
                url,
                "HTTPS response does not include strict-transport-security.",
                "Review HSTS deployment and ensure it matches the application's hosting setup.",
            )
        )
    tls_version = str(observation.get("tls_version", ""))
    if tls_version in {"TLS 1.0", "TLS 1.1"}:
        results.append(
            finding(
                NAME,
                f"Deprecated {tls_version} negotiated",
                "medium",
                9,
                url,
                f"The HTTPS connection negotiated {tls_version}.",
                "Disable deprecated TLS versions and require TLS 1.2 or newer.",
            )
        )
    return results
