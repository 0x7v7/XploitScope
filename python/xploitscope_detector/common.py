"""Shared helpers for passive snapshot analyzers."""


def finding(module, title, severity, confidence, url, evidence, recommendation):
    return {
        "module": module,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "status": "potential",
        "url": url,
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
