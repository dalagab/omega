#!/usr/bin/env python3
"""Deliver a previously-built Omega Discord notice without exposing its secret."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


WEBHOOK_ENVIRONMENTS = {
    "catalog": "DISCORD_CATALOG_WEBHOOK_URL",
    "security": "DISCORD_SECURITY_WEBHOOK_URL",
    "definitions": "DISCORD_DEFINITIONS_WEBHOOK_URL",
    "evidence": "DISCORD_EVIDENCE_WEBHOOK_URL",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notice", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    notice = json.loads(args.notice.read_text(encoding="utf-8-sig"))
    if notice.get("schema") != "omega.discord-notice.v1":
        raise ValueError("unsupported Discord notice schema")
    if not notice.get("shouldNotify"):
        print("Discord notice has no publishable change.")
        return 0
    payload = notice.get("payload")
    if not isinstance(payload, dict) or payload.get("allowed_mentions") != {"parse": []}:
        raise ValueError("notice payload does not meet mention safety policy")
    webhook_key = str(notice.get("webhookKey") or "")
    environment_name = WEBHOOK_ENVIRONMENTS.get(webhook_key)
    if environment_name is None:
        raise ValueError(f"unsupported Discord webhook key: {webhook_key!r}")
    if args.dry_run:
        print(f"Would deliver through {environment_name}.")
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    url = os.environ.get(environment_name, "")
    if not url.startswith("https://discord.com/api/webhooks/"):
        raise RuntimeError(f"{environment_name} must be a Discord incoming webhook URL")
    request = Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
    for attempt in range(3):
        try:
            with urlopen(request, timeout=15) as response:
                if 200 <= response.status < 300:
                    print("Discord notice delivered.")
                    return 0
                raise RuntimeError(f"Discord returned HTTP {response.status}")
        except HTTPError as error:
            if error.code != 429 or attempt == 2:
                raise RuntimeError(f"Discord delivery failed with HTTP {error.code}") from error
            time.sleep(min(float(error.headers.get("Retry-After", "1")), 10.0))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
