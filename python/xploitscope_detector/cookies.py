"""Passive checks for security attributes on observed response cookies."""

from xploitscope_detector.common import finding, headers_of

NAME = "cookies"
DESCRIPTION = "Checks Set-Cookie response values for common security attributes."
MODE = "passive"


def inspect(observation):
    headers = headers_of(observation)
    value = headers.get("set-cookie", "")
    cookies = value if isinstance(value, list) else [value]
    results = []
    for cookie in cookies:
        parts = [part.strip() for part in str(cookie).split(";")]
        if not parts or "=" not in parts[0]:
            continue
        cookie_name = parts[0].split("=", 1)[0].strip()
        attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:] if part}
        missing = []
        if "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if "samesite" not in attributes:
            missing.append("SameSite")
        if missing:
            results.append(
                finding(
                    NAME,
                    f"Cookie {cookie_name} is missing security attributes",
                    "low",
                    8,
                    str(observation.get("url", "")),
                    "Missing attributes: " + ", ".join(missing),
                    "Review cookie purpose and configure appropriate Secure, HttpOnly, and SameSite attributes.",
                    owasp="A02:2025 Security Misconfiguration",
                    location=f"response header: Set-Cookie ({cookie_name})",
                )
            )
    return results
