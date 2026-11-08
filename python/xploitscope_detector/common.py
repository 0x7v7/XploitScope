"""Shared helpers for passive snapshot analyzers."""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def sanitize_url(url):
    try:
        parts = urlsplit(str(url))
        query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    except ValueError:
        return str(url)


def finding(
    module,
    title,
    severity,
    confidence,
    url,
    evidence,
    recommendation,
    owasp="",
    location="",
):
    return {
        "module": module,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "status": "potential",
        "url": sanitize_url(url),
        "location": location,
        "owasp": owasp,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def headers_of(observation):
    headers = observation.get("headers", {})
    if not isinstance(headers, dict):
        return {}
    return {str(key).lower(): value for key, value in headers.items()}


def header_value(headers, name):
    value = headers.get(name, "")
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)
