from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_orchestration_alignment as oa


def work_state(*queues):
    return {"schema": "omega.work-state.v1", "generatedAtUtc": "2026-09-01T18:27:05Z", "queues": list(queues)}


def queue(queue_id, **counts):
    base = {"pending": 0, "leased": 0, "blocked": 0, "completed": 0, "terminal": 0}
    base.update(counts)
    return {
        "queueId": queue_id,
        "component": "omega.sigmascope",
        "counts": base,
        "queueRevision": "queue-v1-test",
        "requiredRevision": "inputs-v1-test",
        "resultBranch": f"{queue_id}-state",
    }


def test_settled_durable_lane_overrides_failed_legacy_runner():
    payload = {
        "collectors": [{
            "id": "advisory-collector",
            "title": "NuGet / OSV advisory collector",
            "state": "failed",
            "trendState": "degraded",
            "workflow": "catalog-builder.yml",
            "latest": {"state": "failed", "runNumber": 12},
        }]
    }
    aligned = oa.align_collector_payload(payload, work_state(queue("osv-advisories", completed=7)))
    row = aligned["collectors"][0]
    assert row["state"] == "healthy"
    assert row["trendState"] == "healthy"
    assert row["stateAuthority"] == "security-work-state"
    assert row["workflow"] == "osv-worker.yml"
    assert row["runnerDiagnostic"]["state"] == "failed"
    assert row["runnerDiagnostic"]["workflow"] == "catalog-builder.yml"
    assert aligned["failingCount"] == 0


def test_durable_state_priorities_are_terminal_blocked_lease_pending_settled():
    assert oa.queue_state(queue("x", terminal=1))["state"] == "failed"
    assert oa.queue_state(queue("x", blocked=2, completed=3))["state"] == "warning"
    assert oa.queue_state(queue("x", leased=1, completed=3))["state"] == "running"
    assert oa.queue_state(queue("x", pending=4, completed=3))["state"] == "running"
    settled = oa.queue_state(queue("x", completed=32))
    assert settled["state"] == "healthy"
    assert settled["label"] == "settled"


def test_operations_put_durable_lanes_first_and_drop_legacy_catalog_aggregate():
    operations = {
        "components": [
            {"componentId": "catalog-definitions", "component": "Catalog / Definitions", "state": "failed", "observed": True},
            {"componentId": "sigmascope", "component": "SigmaScope", "state": "healthy", "observed": True, "latestRun": {"workflow": "sigmascope.yml"}},
        ]
    }
    aligned = oa.align_operations_payload(
        operations,
        work_state(queue("catalog-enrichment", completed=32), queue("threat-intelligence", completed=30)),
    )
    ids = [row["componentId"] for row in aligned["components"]]
    assert ids[:2] == ["durable:catalog-enrichment", "durable:threat-intelligence"]
    assert "catalog-definitions" not in ids
    diag = next(row for row in aligned["components"] if row["componentId"] == "sigmascope")
    assert diag["diagnosticOnly"] is True
    assert diag["component"].startswith("Actions diagnostic ·")


def test_stale_fallback_contracts_are_repointed_to_current_workers():
    rows = oa.apply_collector_contract_overrides([
        {"id": "advisory-collector", "workflow": "catalog-builder.yml", "job": "old", "step": "old"},
        {"id": "manifest-normalization", "workflow": "catalog-builder.yml", "job": "old", "step": "old"},
        {"id": "website-enrichment", "workflow": "catalog-builder.yml", "job": "old", "step": "old"},
    ])
    by_id = {row["id"]: row for row in rows}
    assert by_id["advisory-collector"]["workflow"] == "osv-worker.yml"
    assert by_id["manifest-normalization"]["workflow"] == "catalog-enrichment-worker.yml"
    assert by_id["website-enrichment"]["workflow"] == "catalog-scrape-worker.yml"
    assert by_id["advisory-collector"]["queueId"] == "osv-advisories"
    assert "secondary-security-definitions" in by_id


def test_current_worker_classifier_precedes_legacy_actions_classifier():
    def legacy(path, name, branch):
        return "legacy", "Legacy"

    assert oa.classify_current_workflow(".github/workflows/osv-worker.yml", "OSV", "sigmascope", legacy) == ("omega.sigmascope", "SigmaScope")
    assert oa.classify_current_workflow(".github/workflows/catalog-enrichment-worker.yml", "Catalog", "sigmascope", legacy) == ("omega.catalog", "Catalog collection")
    assert oa.classify_current_workflow(".github/workflows/security-reconcile.yml", "Reconcile", "sigmascope", legacy) == ("omega.platform.main", "Security work reconciler")
    assert oa.classify_current_workflow(".github/workflows/unknown.yml", "Unknown", "x", legacy) == ("legacy", "Legacy")
