from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

SECURITY = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import security_system_state


def test_readiness_keeps_planned_external_and_failed_distinct(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "variantId": 42,
        "plugin": {"canonical_name": "Broken Example"},
        "current": {"status": "failed", "error": "bounded parser timeout", "scanned_at_utc": "2026-08-29T12:00:00Z"},
    }
    monkeypatch.setattr(security_system_state.security_evidence_v2, "iter_variant_entries", lambda _root: iter([({"variantId": 42}, payload)]))
    monkeypatch.setattr(security_system_state.security_evidence_v2, "variant_coverage_summary", lambda _payload: {"status": "failed"})

    descriptor = security_system_state.materialize(tmp_path)
    document = json.loads((tmp_path / descriptor["path"]).read_text(encoding="utf-8"))
    by_id = {row["id"]: row for row in document["systems"]}

    assert document["policy"]["noFindingDoesNotImplyCovered"] is True
    assert by_id["omega.sigmascope"]["state"] == "degraded"
    assert by_id["omega.sigmascope"]["recentErrors"][0]["variantId"] == 42
    assert by_id["omega.rift"]["state"] == "blocked"
    assert by_id["omega.rebuilder"]["state"] == "planned"
    assert descriptor["stateRevision"] == document["stateRevision"]


def test_all_declared_runtime_states_are_supported() -> None:
    assert security_system_state.ALLOWED_STATES == {
        "operational", "degraded", "experimental", "disabled", "blocked",
        "incomplete", "planned", "failed", "stale", "unsupported",
    }
