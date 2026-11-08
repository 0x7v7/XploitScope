"""Passive CORS checks using only request/response headers in supplied snapshots."""

from xploitscope_detector.common import finding, header_value, headers_of

NAME = "cors"
DESCRIPTION = "Checks observed CORS headers for risky origin reflection patterns."
MODE = "passive"


def inspect(observation):
    headers = headers_of(observation)
    request_headers = observation.get("request_headers", {})
    if not isinstance(request_headers, dict):
        request_headers = {}
    request_headers = {str(key).lower(): value for key, value in request_headers.items()}
    origin = str(request_headers.get("origin", ""))
    allowed_origin = header_value(headers, "access-control-allow-origin")
    allow_credentials = header_value(headers, "access-control-allow-credentials").lower() == "true"
    url = str(observation.get("url", ""))
    results = []

    if origin and allowed_origin == origin and allow_credentials:
        results.append(
            finding(
                NAME,
                "CORS reflects the supplied Origin while allowing credentials",
                "medium",
                7,
                url,
                "The saved request Origin is mirrored in Access-Control-Allow-Origin and credentials are allowed.",
                "Allow only explicitly trusted origins and review whether credentialed cross-origin access is required.",
                owasp="A02:2025 Security Misconfiguration",
                location="response headers: Access-Control-Allow-Origin / Access-Control-Allow-Credentials",
            )
        )
    elif allowed_origin == "*" and allow_credentials:
        results.append(
            finding(
                NAME,
                "CORS combines wildcard origin with credentials",
                "low",
                5,
                url,
                "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true; browsers reject this combination.",
                "Use an explicit allowlist if credentialed cross-origin access is intended.",
                owasp="A02:2025 Security Misconfiguration",
                location="response headers: Access-Control-Allow-Origin / Access-Control-Allow-Credentials",
            )
        )
    return results
