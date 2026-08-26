#!/usr/bin/env python3
"""Consume one approved Omega deep-scan queue item.

Current executable work remains non-executing. Scan depth changes only code-owned
resource budgets and extra static inspection families; plugin code is never executed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import re
import time
import urllib.request
import zipfile
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SCRIPT_DIR.parent / "catalog"
if str(CATALOG_DIR) not in sys.path:
    sys.path.insert(0, str(CATALOG_DIR))

import deep_scan_contract
import deep_scan_queue
import sigmascope

UA = "Omega-DeepScan/1"
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{6,200}")
URL_RE = re.compile(r"https?://[^\s\"'<>]{4,300}", re.IGNORECASE)
INTERESTING_SUFFIXES = {".dll", ".exe", ".so", ".dylib", ".json", ".config", ".yaml", ".yml", ".txt"}


def _deadline(item: Mapping[str, Any]) -> float:
    seconds = max(60, min(55 * 60, int(item.get("workerBudgetSeconds") or 900)))
    return time.monotonic() + seconds


def _check(deadline: float, stage: str) -> None:
    if time.monotonic() > deadline:
        raise RuntimeError(f"deep-scan worker budget exhausted during {stage}")


def _download(url: str, expected_sha: str, max_bytes: int) -> bytes:
    if not str(url).startswith("https://"):
        raise RuntimeError("deep scan artifact URL must be HTTPS")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=45) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RuntimeError("artifact exceeds deep-scan profile size ceiling")
    actual = hashlib.sha256(data).hexdigest()
    if expected_sha and actual != expected_sha.lower():
        raise RuntimeError(f"artifact SHA-256 mismatch: {actual} != {expected_sha}")
    return data


def _inventory(data: bytes, max_entries: int, max_member: int, max_uncompressed: int | None = None, *, deadline: float | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"archive": False, "members": {}}
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["bytes"] = len(data)
        return result
    infos = archive.infolist()
    if len(infos) > max_entries:
        raise RuntimeError("archive exceeds deep-scan entry ceiling")
    result["archive"] = True
    total_uncompressed = 0
    seen_names: set[str] = set()
    for info in infos:
        if deadline is not None:
            _check(deadline, "package inventory")
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in Path(name).parts:
            raise RuntimeError("unsafe archive path in deep-scan input")
        if info.is_dir():
            continue
        normalized = name.casefold()
        if normalized in seen_names:
            raise RuntimeError("archive contains duplicate normalized paths")
        seen_names.add(normalized)
        if info.file_size > max_member:
            raise RuntimeError("archive member exceeds deep-scan member ceiling")
        total_uncompressed += int(info.file_size)
        if max_uncompressed is not None and total_uncompressed > max_uncompressed:
            raise RuntimeError("archive exceeds deep-scan total uncompressed ceiling")
        payload = archive.read(info)
        result["members"][normalized] = {"path": name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    return result


def _compare(candidate: Mapping[str, Any], baseline: Mapping[str, Any]) -> dict[str, Any]:
    c = candidate.get("members") if isinstance(candidate.get("members"), Mapping) else {}
    b = baseline.get("members") if isinstance(baseline.get("members"), Mapping) else {}
    added = [c[k] for k in sorted(set(c) - set(b))]
    removed = [b[k] for k in sorted(set(b) - set(c))]
    changed = [{"path": c[k]["path"], "candidateSha256": c[k]["sha256"], "baselineSha256": b[k]["sha256"], "candidateBytes": c[k]["bytes"], "baselineBytes": b[k]["bytes"]} for k in sorted(set(c) & set(b)) if c[k]["sha256"] != b[k]["sha256"]]
    same = sum(1 for k in set(c) & set(b) if c[k]["sha256"] == b[k]["sha256"])
    return {"added": added, "removed": removed, "changed": changed, "sameMemberCount": same, "candidateMemberCount": len(c), "baselineMemberCount": len(b)}


def _static_behavior(data: bytes, *, deadline: float | None = None) -> dict[str, Any]:
    if deadline is not None:
        _check(deadline, "SigmaScope static behavior")
    hits: dict[str, list[str]] = defaultdict(list)
    intel = sigmascope.empty_dependency_intelligence("artifact")
    metadata = sigmascope.scan_archive(data, hits, intel)
    sigmascope.finalize_intelligence(intel)
    endpoints = sorted({str(item.get("url") or "") for item in intel.get("networkEndpoints") or [] if isinstance(item, Mapping) and str(item.get("url") or "")})
    deps = sorted({f"{item.get('kind','')}:{item.get('name','')}:{item.get('version','')}" for item in intel.get("dependencies") or [] if isinstance(item, Mapping)})
    return {
        "ruleHits": {key: len(values) for key, values in sorted(hits.items()) if values},
        "networkEndpoints": endpoints[:256],
        "dependencies": deps[:512],
        "bundledExecutables": sorted(metadata.get("bundledExecutables") or []),
        "bundledNativeLibraries": sorted(metadata.get("bundledNativeLibraries") or []),
        "binaryClassifications": [{k: item.get(k) for k in ("path", "kind", "role", "architecture") if k in item} for item in (metadata.get("binaryClassifications") or [])[:256] if isinstance(item, Mapping)],
    }


def _behavior_diff(candidate: Mapping[str, Any], baseline: Mapping[str, Any]) -> dict[str, Any]:
    c_hits, b_hits = set((candidate.get("ruleHits") or {}).keys()), set((baseline.get("ruleHits") or {}).keys())
    c_ep, b_ep = set(candidate.get("networkEndpoints") or []), set(baseline.get("networkEndpoints") or [])
    c_dep, b_dep = set(candidate.get("dependencies") or []), set(baseline.get("dependencies") or [])
    return {
        "addedRuleHits": sorted(c_hits - b_hits), "removedRuleHits": sorted(b_hits - c_hits),
        "addedNetworkEndpoints": sorted(c_ep - b_ep), "removedNetworkEndpoints": sorted(b_ep - c_ep),
        "addedDependencies": sorted(c_dep - b_dep), "removedDependencies": sorted(b_dep - c_dep),
    }


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = [0] * 256
    for byte in payload:
        counts[byte] += 1
    length = len(payload)
    return round(-sum((count / length) * math.log2(count / length) for count in counts if count), 4)


def _content_summary(data: bytes, spec: Mapping[str, Any], *, deadline: float) -> dict[str, Any]:
    max_total = int(spec.get("contentInspectionBytes") or 0)
    max_strings = int(spec.get("maxExtractedStrings") or 0)
    if max_total <= 0 or max_strings <= 0:
        return {}
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {}
    inspected = 0
    strings: set[str] = set()
    urls: set[str] = set()
    members: list[dict[str, Any]] = []
    for info in archive.infolist():
        _check(deadline, "member content inspection")
        if info.is_dir() or Path(info.filename).suffix.casefold() not in INTERESTING_SUFFIXES:
            continue
        if inspected >= max_total or len(strings) >= max_strings:
            break
        to_read = min(int(info.file_size), int(spec.get("maxMemberBytes") or 0), max_total - inspected)
        if to_read <= 0:
            break
        with archive.open(info) as stream:
            payload = stream.read(to_read)
        inspected += len(payload)
        local_strings = []
        for match in PRINTABLE_RE.finditer(payload):
            text = match.group(0).decode("ascii", errors="ignore")
            strings.add(text)
            local_strings.append(text)
            for url in URL_RE.findall(text):
                urls.add(url[:300])
            if len(strings) >= max_strings:
                break
        members.append({"path": info.filename.replace("\\", "/"), "sampledBytes": len(payload), "entropy": _entropy(payload), "printableStringCount": len(local_strings)})
    return {
        "inspectedBytes": inspected,
        "memberCount": len(members),
        "members": members[:512],
        "urlLiterals": sorted(urls)[:2048],
        "stringDigest": hashlib.sha256("\n".join(sorted(strings)).encode("utf-8")).hexdigest(),
        "stringCount": len(strings),
    }


def _content_diff(candidate: Mapping[str, Any], baseline: Mapping[str, Any]) -> dict[str, Any]:
    cu, bu = set(candidate.get("urlLiterals") or []), set(baseline.get("urlLiterals") or [])
    cm = {str(x.get("path") or ""): x for x in candidate.get("members") or [] if isinstance(x, Mapping)}
    bm = {str(x.get("path") or ""): x for x in baseline.get("members") or [] if isinstance(x, Mapping)}
    entropy_changes = []
    for path in sorted(set(cm) & set(bm)):
        delta = float(cm[path].get("entropy") or 0) - float(bm[path].get("entropy") or 0)
        if abs(delta) >= 0.75:
            entropy_changes.append({"path": path, "candidateEntropy": cm[path].get("entropy"), "baselineEntropy": bm[path].get("entropy"), "delta": round(delta, 4)})
    return {"addedUrlLiterals": sorted(cu - bu), "removedUrlLiterals": sorted(bu - cu), "entropyChanges": entropy_changes[:256]}


def run_item(item: Mapping[str, Any]) -> dict[str, Any]:
    profile = str(item.get("profile") or "")
    depth = deep_scan_contract.normalize_depth(item.get("depth"))
    spec = deep_scan_contract.profile_status(profile, depth)
    if not spec.get("profile") or profile not in deep_scan_contract.PROFILES:
        raise RuntimeError("unknown deep-scan profile")
    if not spec.get("available"):
        raise RuntimeError(str(spec.get("blockedReason") or "deep-scan profile unavailable"))
    if profile != "artifact-differential-v1":
        raise RuntimeError("no executable implementation for this deep-scan profile")
    deadline = _deadline(item)
    candidate = _download(str(item.get("artifactUrl") or ""), str(item.get("artifactSha256") or ""), int(spec["maxArtifactBytes"]))
    _check(deadline, "candidate download")
    baseline = _download(str(item.get("baselineArtifactUrl") or ""), str(item.get("baselineArtifactSha256") or ""), int(spec["maxArtifactBytes"]))
    _check(deadline, "baseline download")
    c_inv = _inventory(candidate, int(spec["maxArchiveEntries"]), int(spec["maxMemberBytes"]), int(spec["maxUncompressedBytes"]), deadline=deadline)
    b_inv = _inventory(baseline, int(spec["maxArchiveEntries"]), int(spec["maxMemberBytes"]), int(spec["maxUncompressedBytes"]), deadline=deadline)
    c_behavior = _static_behavior(candidate, deadline=deadline)
    b_behavior = _static_behavior(baseline, deadline=deadline)
    result: dict[str, Any] = {
        "schema": deep_scan_contract.RESULT_SCHEMA,
        "requestId": str(item.get("requestId") or ""),
        "variantId": int(item.get("variantId") or 0),
        "profile": profile,
        "depth": depth,
        "profileSetRevision": deep_scan_contract.profile_set_revision(),
        "artifactSha256": str(item.get("artifactSha256") or ""),
        "baselineArtifactSha256": str(item.get("baselineArtifactSha256") or ""),
        "behaviorExecutionPerformed": False,
        "pluginCodeExecuted": False,
        "budget": {
            "workflowTimeoutMinutes": int(spec.get("workflowTimeoutMinutes") or 20),
            "workerBudgetSeconds": int(spec.get("workerBudgetSeconds") or 900),
            "analysisFamilies": list(spec.get("analysisFamilies") or []),
        },
        "comparison": _compare(c_inv, b_inv),
        "staticBehavior": {"candidate": c_behavior, "baseline": b_behavior, "difference": _behavior_diff(c_behavior, b_behavior)},
    }
    if "member-content-summary" in (spec.get("analysisFamilies") or []):
        c_content = _content_summary(candidate, spec, deadline=deadline)
        b_content = _content_summary(baseline, spec, deadline=deadline)
        result["contentInspection"] = {"candidate": c_content, "baseline": b_content, "difference": _content_diff(c_content, b_content)}
    _check(deadline, "result finalization")
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--queue", type=Path, required=True)
    p.add_argument("--request-id", default="")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    item = deep_scan_queue.select_request(queue, args.request_id)
    if not item:
        print("No executable pending deep-scan request.")
        return 0
    result = run_item(item)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"requestId": result["requestId"], "profile": result["profile"], "depth": result["depth"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
