#!/usr/bin/env python3
"""JSON Lines worker for XploitScope's Go/Python health-check protocol."""

import json
from pathlib import Path
import sys

# Support both the source tree and the installer's shared-data layout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from xploitscope_detector import analyze, module_descriptions

PROTOCOL_VERSION = 1


def handle(message):
    if not isinstance(message, dict):
        raise ValueError("request must be a JSON object")
    if message.get("version") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if not isinstance(message.get("id"), str) or not message["id"]:
        raise ValueError("request id must be a non-empty string")
    request_type = message.get("type")
    if request_type == "ping":
        return {
            "version": PROTOCOL_VERSION,
            "id": message["id"],
            "type": "pong",
            "payload": {"status": "ready"},
        }
    if request_type == "list_modules":
        payload = {"modules": module_descriptions()}
    elif request_type == "analyze":
        payload = analyze(message.get("payload"))
    else:
        raise ValueError("unsupported request type")

    return {
        "version": PROTOCOL_VERSION,
        "id": message["id"],
        "type": "result",
        "payload": payload,
    }


def main():
    for line in sys.stdin:
        request_id = ""
        try:
            message = json.loads(line)
            if isinstance(message, dict) and isinstance(message.get("id"), str):
                request_id = message["id"]
            response = handle(message)
        except (json.JSONDecodeError, ValueError) as error:
            response = {
                "version": PROTOCOL_VERSION,
                "id": request_id,
                "type": "error",
                "error": str(error),
            }
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
