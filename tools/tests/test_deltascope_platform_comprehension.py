from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "security" / "deltascope_platform_comprehension.py"
spec = importlib.util.spec_from_file_location("deltascope_platform_comprehension", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_market_data_to_purchase_gets_semantic_chain() -> None:
    payload = {
        "visibleBehaviors": [{
            "behaviorId": "b1",
            "behaviorKey": "source-behavior.market-data-drives-purchase",
            "ruleId": "source-behavior.market-data-drives-purchase",
            "description": "source flow",
            "evidenceRows": [{
                "row": {
                    "relation": "value-used-by",
                    "fromServiceCapabilities": ["ffxiv.market-data"],
                    "toOperation": "game.marketboard.purchase",
                }
            }],
        }]
    }
    result = module.augment_behavior_payload(payload)
    chain = result["visibleBehaviors"][0]["semanticChain"]
    assert chain["summary"].startswith("Retained source value-flow")
    labels = [node["label"] for node in chain["nodes"]]
    assert "value-used-by" in labels
    assert "game.marketboard.purchase" in labels
    assert "runtime" in chain["boundary"].lower()


def test_coverage_keeps_missing_distinct_from_negative_result() -> None:
    detail = {
        "identity": {"artifact_sha256": "a" * 64, "scan_status": "complete"},
        "sourceCoverage": {"artifactAvailable": True, "sourceCodeAvailable": True, "sourceToBinaryVerified": False},
        "networkEndpoints": [{"host": "example.invalid"}],
        "secondarySecurity": {"engines": [{"engine": "yara", "status": "complete", "available": True}]},
    }
    observations = {
        "sourceOperations": [{"operation": "network.http.request"}],
        "sourceDataFlow": [],
        "sourceFlowEdges": [],
        "binarySignatureTrust": [],
    }
    coverage = module.evidence_coverage(detail, observations, {"available": True})
    by_domain = {row["domain"]: row for row in coverage}
    assert by_domain["artifact"]["state"] == "complete"
    assert by_domain["source-semantics"]["state"] == "observed"
    assert by_domain["threat-intelligence"]["state"] == "not-linked"
    assert by_domain["signature"]["state"] == "not-recorded"
    assert by_domain["build-proof"]["state"] == "not-verified"


def test_journey_adds_semantic_and_threat_intelligence_stages() -> None:
    base = {
        "stages": [
            {"stageId": "evidence-normalization", "title": "Normalize", "status": "complete"},
            {"stageId": "stigma-rules", "title": "Rules", "status": "complete"},
        ]
    }
    detail = {
        "identity": {"artifact_sha256": "b" * 64, "scan_status": "complete"},
        "sourceCoverage": {"artifactAvailable": True, "sourceCodeAvailable": True},
        "networkEndpoints": [{"host": "universalis.app"}],
    }
    observations = {
        "sourceOperations": [{"operation": "network.http.request"}],
        "endpointReputation": [{"host": "universalis.app", "status": "unlisted"}],
    }
    result = module.augment_journey_payload(base, detail, observations, {})
    ids = [stage["stageId"] for stage in result["stages"]]
    assert ids.index("semantic-behavior") > ids.index("evidence-normalization")
    assert ids.index("threat-intelligence") > ids.index("semantic-behavior")
    assert result["coverageSummary"]["domains"] >= 10


def test_ui_uses_hash_verified_semantic_definitions_and_durable_work_state() -> None:
    assert "crypto.subtle.digest('SHA-256'" in module._JS
    assert "semanticApiRegistry" in module._JS
    assert "serviceRegistry" in module._JS
    assert "security-work-state" in module._JS
    assert "Work-state is operational lineage only" in module._JS


def test_install_wraps_existing_projection_modules_without_authority(monkeypatch) -> None:
    import sys
    import types

    fake_view = types.SimpleNamespace(HTML="<html><style></style><script></script></html>")
    fake_behaviors = types.SimpleNamespace(project_plugin_behaviors=lambda *a, **k: {"visibleBehaviors": []})
    fake_workbench = types.SimpleNamespace(project_asset_journey=lambda detail, observations=None, projection_state=None: {"stages": []})
    monkeypatch.setitem(sys.modules, "developer_view", fake_view)
    monkeypatch.setitem(sys.modules, "deltascope_behaviors", fake_behaviors)
    monkeypatch.setitem(sys.modules, "deltascope_workbench", fake_workbench)
    module._INSTALLED = False
    module.install()
    assert "__deltascopePlatformComprehensionInstalled" in fake_view.HTML
    behavior = fake_behaviors.project_plugin_behaviors()
    assert behavior["comprehension"]["schema"] == module.COMPREHENSION_SCHEMA
    journey = fake_workbench.project_asset_journey({"identity": {}}, {}, {})
    assert journey["comprehension"]["mutationAuthority"] == "none"
    module._INSTALLED = False
