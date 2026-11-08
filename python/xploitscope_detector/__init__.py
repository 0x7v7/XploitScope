"""Passive analyzers for user-provided HTTP snapshots."""

from xploitscope_detector import access_control, cookies, cors, headers, sqli, ssrf, xss

MODULES = (
    access_control,
    cookies,
    cors,
    headers,
    sqli,
    ssrf,
    xss,
)


def module_descriptions():
    return [
        {
            "name": module.NAME,
            "description": module.DESCRIPTION,
            "mode": module.MODE,
        }
        for module in MODULES
    ]


def analyze(payload):
    if not isinstance(payload, dict):
        raise ValueError("analyze payload must be a JSON object")
    observations = payload.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("payload must contain a non-empty observations array")
    if len(observations) > 500:
        raise ValueError("at most 500 observations are accepted per analysis")

    selected_names = payload.get("modules")
    modules = MODULES
    if selected_names is not None:
        if not isinstance(selected_names, list) or not selected_names:
            raise ValueError("modules must be a non-empty array")
        if any(not isinstance(name, str) for name in selected_names):
            raise ValueError("module names must be strings")
        available = {module.NAME: module for module in MODULES}
        unknown = sorted(set(selected_names) - available.keys())
        if unknown:
            raise ValueError("unknown module(s): " + ", ".join(unknown))
        modules = tuple(available[name] for name in dict.fromkeys(selected_names))

    findings = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise ValueError(f"observation {index} must be a JSON object")
        for module in modules:
            findings.extend(module.inspect(observation))
    return {
        "analysis_mode": "offline_passive",
        "observation_count": len(observations),
        "modules": [module.NAME for module in modules],
        "findings": findings,
        "notice": "Potential findings require manual validation; no network requests were made.",
    }
