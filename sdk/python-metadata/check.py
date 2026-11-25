#!/usr/bin/env python3

import json
import sys

MAX_INPUT_BYTES = 1024 * 1024


def main():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        sys.stderr.write("input exceeds the 1 MiB script limit\n")
        return 2
    try:
        context = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        sys.stderr.write("invalid JSON input: " + str(error) + "\n")
        return 2
    if not isinstance(context, dict) or context.get("api") != 1:
        sys.stderr.write("unsupported script API\n")
        return 2

    service = context.get("service")
    name = service.get("name") if isinstance(service, dict) else ""
    finding = {
        "id": "sdk-python-template",
        "title": "Python metadata script executed",
        "severity": "info",
        "confidence": 0.90,
        "description": "Replace this template finding with passive checks over the supplied service and TLS metadata.",
        "evidence": "service=" + str(name) + " port=" + str(context.get("port", 0)),
    }
    json.dump({"findings": [finding]}, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
