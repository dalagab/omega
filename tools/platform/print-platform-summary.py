#!/usr/bin/env python3
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))

print(f"- Plugin target runtime: `{data.get('target_runtime', 'unknown')}`")
for env in data.get("player_environments", []):
    display = env.get("display_os", env.get("id", "unknown"))
    execution = env.get("execution_model", "unknown")
    status = env.get("status", "unverified")
    confidence = env.get("confidence", "low")
    print(f"- {display}: `{status}` ({confidence}; {execution})")

runtime = data.get("analysis_runtime_verification")
if runtime:
    classification = runtime.get("classification", "unknown")
    print(f"- Current Rift execution classification: `{classification}`")
