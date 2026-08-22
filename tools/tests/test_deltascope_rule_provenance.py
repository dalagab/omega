from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import common

SECURITY = common.ROOT / "tools" / "security"
CATALOG = common.ROOT / "tools" / "catalog"
for item in (SECURITY, CATALOG):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import definition_packs
import deltascope_provenance
import deltascope_workbench
import developer_view
from production_sigmascope_v2_pipeline import materialize_definition_provenance_index


class DeltaScopeRuleProvenanceTests(unittest.TestCase):
    def frozen_definitions(self, root: Path, revision: str = "defs-v1-provenance-fixture") -> Path:
        definitions = root / "definitions"
        definitions.mkdir(parents=True, exist_ok=True)
        descriptor = definition_packs.freeze_pack_root(
            common.ROOT / "security-definitions" / "packs", definitions, include_local=False
        )
        (definitions / "index.json").write_text(
            json.dumps({
                "schema": "omega.definitions.v1",
                "definitionsRevision": revision,
                "generatedAtUtc": "2026-08-21T18:00:00Z",
                "builtFromDevCommit": "phase11d-test",
                "scannerVersion": "2.15.0-unreleased",
                "scannerRevision": "scanner-test",
                "artifactAnalysisRevision": "artifact-test",
                "sourceAnalysisRevision": "source-test",
                "sourceObservationRevision": "observations-test",
                "ruleSetRevision": "legacy-rules-test",
                "advisoryRevision": "advisories-test",
                "srlDefinitionPacks": descriptor,
            }, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return definitions

    def provenance(self) -> dict:
        with tempfile.TemporaryDirectory(prefix="omega-provenance-fixture-") as td:
            return deltascope_provenance.build_definition_provenance(self.frozen_definitions(Path(td)))

    def test_exact_frozen_definition_provenance_is_read_only_and_complete(self) -> None:
        payload = self.provenance()
        self.assertEqual(deltascope_provenance.DEFINITION_PROVENANCE_SCHEMA, payload["schema"])
        self.assertTrue(payload["readOnly"])
        self.assertEqual("none", payload["mutationAuthority"])
        self.assertFalse(payload["policyInput"])
        self.assertEqual("github-permission-ci-review-normal-pr", payload["authoritativeChangeBoundary"])
        self.assertEqual(2, payload["srl"]["packCount"])
        self.assertEqual(7, payload["srl"]["activeRuleCount"])
        self.assertFalse(payload["srl"]["productionRuleEvaluationEnabled"])
        self.assertEqual(7, len(payload["activeRules"]))
        self.assertTrue(all(item.get("review", {}).get("reviewer") for item in payload["activeRules"]))
        self.assertTrue(all(item.get("sourceSha256") for item in payload["activeRules"]))
        self.assertTrue(all(pack["fixtures"] for pack in payload["packs"]))

    def test_provenance_revision_and_bytes_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-provenance-deterministic-") as td:
            root = Path(td)
            definitions = self.frozen_definitions(root)
            first = deltascope_provenance.write_definition_provenance(definitions, root / "one" / "definition-provenance.json")
            second = deltascope_provenance.write_definition_provenance(definitions, root / "two" / "definition-provenance.json")
            self.assertEqual(first["provenanceRevision"], second["provenanceRevision"])
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual((root / "one" / "definition-provenance.json").read_bytes(), (root / "two" / "definition-provenance.json").read_bytes())

    def test_provenance_build_fails_closed_when_frozen_pack_is_tampered(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-provenance-tamper-") as td:
            root = Path(td)
            definitions = self.frozen_definitions(root)
            parent = json.loads((definitions / "index.json").read_text(encoding="utf-8"))
            descriptor = parent["srlDefinitionPacks"]
            srl_index = json.loads((definitions / descriptor["path"]).read_text(encoding="utf-8"))
            source = definitions / "srl" / "packs" / srl_index["packs"][0]["id"] / srl_index["packs"][0]["rules"][0]["path"]
            source.write_text(source.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "verification"):
                deltascope_provenance.build_definition_provenance(definitions)

    def test_provenance_revision_ignores_snapshot_timestamp_only_churn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-provenance-timestamp-") as td:
            root = Path(td)
            definitions = self.frozen_definitions(root)
            first = deltascope_provenance.build_definition_provenance(definitions)
            parent = json.loads((definitions / "index.json").read_text(encoding="utf-8"))
            parent["generatedAtUtc"] = "2026-08-22T18:00:00Z"
            (definitions / "index.json").write_text(json.dumps(parent, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            second = deltascope_provenance.build_definition_provenance(definitions)
            self.assertEqual(first["provenanceRevision"], second["provenanceRevision"])
            self.assertNotEqual(first["definitions"]["generatedAtUtc"], second["definitions"]["generatedAtUtc"])

    def test_provenance_validator_detects_semantic_review_mutation(self) -> None:
        payload = self.provenance()
        payload["activeRules"][0]["review"]["reviewer"] = "tampered reviewer"
        errors = deltascope_provenance.validate_definition_provenance(payload)
        self.assertIn("definition provenance semantic revision mismatch", errors)

    def test_provenance_validator_rejects_policy_authority_or_active_production_srl(self) -> None:
        payload = self.provenance()
        payload["policyInput"] = True
        payload["srl"]["productionRuleEvaluationEnabled"] = True
        errors = deltascope_provenance.validate_definition_provenance(payload)
        self.assertTrue(any("policy input" in item for item in errors), errors)
        self.assertTrue(any("production SRL" in item for item in errors), errors)

    def test_repository_definition_library_surfaces_source_rules_without_claiming_activation(self) -> None:
        library = developer_view.local_definition_library(common.ROOT / "security-definitions" / "packs")
        self.assertEqual("omega.deltascope.definition-library.v1", library["schema"])
        self.assertTrue(library["readOnly"])
        self.assertEqual("none", library["mutationAuthority"])
        self.assertFalse(library["policyInput"])
        self.assertEqual("repository-source-only", library["sourceAuthority"])
        self.assertEqual(2, library["packCount"])
        self.assertEqual(7, library["ruleCount"])
        self.assertEqual(6, library["fixtureCount"])
        rule = next(
            item
            for pack in library["packs"]
            for item in pack["rules"]
            if item["ruleId"] == "compound.network-execute"
        )
        self.assertEqual("correlation", rule["kind"])
        self.assertEqual("compound.network-execute", rule["output"])
        self.assertIn("schema: omega.sigmascope.rule.v1", rule["candidateYaml"])
        self.assertIn("condition:", rule["candidateYaml"])
        self.assertTrue(rule["ruleRevision"].startswith("srl-rule-v1-"))
        self.assertTrue(rule["sourcePath"].startswith("security-definitions/packs/"))

    def test_rule_catalog_preserves_review_fixture_and_github_boundary(self) -> None:
        payload = self.provenance()
        payload["available"] = True
        catalog = deltascope_workbench.project_rule_catalog(payload)
        self.assertEqual(deltascope_workbench.RULE_CATALOG_SCHEMA, catalog["schema"])
        self.assertTrue(catalog["readOnly"])
        self.assertEqual("none", catalog["mutationAuthority"])
        self.assertFalse(catalog["policyInput"])
        self.assertEqual(2, len(catalog["packs"]))
        self.assertEqual(7, len(catalog["rules"]))
        self.assertTrue(all(pack["fixtureCount"] == pack["fixturesPassed"] for pack in catalog["packs"]))
        self.assertEqual("github-permission-ci-review-normal-pr", catalog["authoritativeChangeBoundary"])

    def test_reports_and_system_surface_reprojection_queue_and_revision_health_read_only(self) -> None:
        context = {
            "generatedAtUtc": "2026-08-21T18:00:00Z",
            "evidence": {
                "schema": "omega.security-evidence.v2",
                "revisions": {"evidenceRevision": "ev-1", "securityRevision": "sec-1", "catalogRevision": "cat-1"},
                "publication": {"rootWrittenLast": True},
            },
            "engine": {"name": "Sigmascope", "version": "2.15.0-unreleased"},
            "source": {"definitionsRevision": "defs-1"},
            "queue": {"available": True, "summary": {"total": 8, "states": {"pending": 3, "retry": 1, "complete": 4}}},
            "ruleProjections": {
                "available": True, "ruleSetRevision": "srl-1", "projectionSetRevision": "set-1",
                "counts": {"checkedVariants": 10, "reprojectedVariants": 8, "reanalysisRequiredVariants": 2, "auditErrorVariants": 0},
                "productionRuleEvaluationEnabled": False, "productionWriteBack": False, "queueMutationAuthorized": False,
            },
            "relationshipIndex": {"available": True, "relationshipRevision": "rel-1"},
            "definitionProvenance": {"available": True, "provenanceRevision": "prov-1"},
        }
        summary = {"counts": {"variants": 10, "completeScans": 8, "failedScans": 1, "unscannedVariantsPending": 1, "reviewVariants": 2}}
        reports = deltascope_workbench.project_reports({}, summary, context)
        self.assertEqual(deltascope_workbench.REPORT_CATALOG_SCHEMA, reports["schema"])
        self.assertEqual("none", reports["mutationAuthority"])
        reprojection = next(item for item in reports["reports"] if item["reportId"] == "srl-reprojection")
        self.assertEqual(2, reprojection["metrics"]["reanalysisRequiredVariants"])
        self.assertEqual("gated", reprojection["status"])

        provenance = self.provenance()
        system = deltascope_workbench.project_system_status(context, provenance)
        self.assertEqual(deltascope_workbench.SYSTEM_STATUS_SCHEMA, system["schema"])
        self.assertEqual("none", system["mutationAuthority"])
        checks = {item["code"]: item for item in system["checks"]}
        self.assertEqual("gated", checks["srl.production"]["status"])
        self.assertEqual("pass", checks["srl.writeback"]["status"])
        self.assertEqual("pass", checks["queue.authority"]["status"])

    def test_pipeline_materializer_hash_pins_definition_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-provenance-materialize-") as td:
            root = Path(td)
            definitions = self.frozen_definitions(root)
            candidate = root / "candidate"
            entry = materialize_definition_provenance_index(candidate, definitions)
            self.assertEqual("indexes/definition-provenance.json", entry["path"])
            data = (candidate / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
            self.assertEqual(len(data), entry["bytes"])
            payload = json.loads(data)
            self.assertEqual([], deltascope_provenance.validate_definition_provenance(payload))
            self.assertEqual(entry["provenanceRevision"], payload["provenanceRevision"])

    def test_workbench_http_rules_reports_system_are_read_only_and_promotion_is_absent(self) -> None:
        provenance = self.provenance()
        provenance["available"] = True
        context = {
            "generatedAtUtc": "2026-08-21T18:00:00Z",
            "evidence": {"schema": "omega.security-evidence.v2", "revisions": {}, "publication": {}},
            "engine": {}, "source": {},
            "queue": {"available": False, "summary": {}},
            "ruleProjections": {"available": False, "productionRuleEvaluationEnabled": False, "productionWriteBack": False, "queueMutationAuthorized": False},
            "relationshipIndex": {"available": False},
            "definitionProvenance": {"available": True, "provenanceRevision": provenance["provenanceRevision"]},
        }

        class FakeInspector:
            def definition_provenance(self):
                return provenance
            def summary(self):
                return {"counts": {}, "revisions": {}}
            def workbench_system_context(self):
                return context

        handler = type("RuleProvenanceHandler", (developer_view.AppHandler,), {"inspector": FakeInspector()})
        server = developer_view.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            for endpoint, schema in (
                ("/api/workbench/rule-library", developer_view.LOCAL_DEFINITION_LIBRARY_SCHEMA),
                ("/api/workbench/rules", deltascope_workbench.RULE_CATALOG_SCHEMA),
                ("/api/workbench/reports", deltascope_workbench.REPORT_CATALOG_SCHEMA),
                ("/api/workbench/system", deltascope_workbench.SYSTEM_STATUS_SCHEMA),
            ):
                with urllib.request.urlopen(base + endpoint, timeout=5) as response:
                    value = json.load(response)
                self.assertEqual(schema, value["schema"])
                self.assertTrue(value["readOnly"])
                self.assertEqual("none", value["mutationAuthority"])
            request = urllib.request.Request(base + "/api/rule-lab/promote", method="POST", data=b"{}", headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(404, caught.exception.code)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
