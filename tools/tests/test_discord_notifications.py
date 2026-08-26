from __future__ import annotations

from pathlib import Path
from contextlib import closing
import json
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

import common

NOTIFICATIONS = common.ROOT / "tools" / "notifications"
sys.path.insert(0, str(NOTIFICATIONS))
import discord_notice
import post_discord_notice


class DiscordNoticeTests(unittest.TestCase):
    def test_notice_sender_identity_is_exactly_toni(self) -> None:
        result = discord_notice.notice(
            "catalog",
            "catalog",
            {"embeds": [{"title": "Test"}]},
            {"event": "identity"},
        )
        self.assertEqual("TONI", result["payload"]["username"])
        self.assertNotIn("Omega Updates", json.dumps(result))

    def test_catalog_notice_is_sanitised_and_compares_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "current.json"
            definitions = root / "definitions.json"
            previous_definitions = root / "previous-definitions.json"
            current.parent.joinpath("plugins").mkdir()
            current.write_text(json.dumps({"catalogRevision": "current"}), encoding="utf-8")
            current.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": [{"pluginId": 1, "active": True, "name": "@here <plugin>"}]}), encoding="utf-8")
            # A separate prior catalog root makes the revision comparison realistic.
            previous_root = root / "previous" / "index.json"
            previous_root.parent.joinpath("plugins").mkdir(parents=True)
            previous_root.write_text(json.dumps({"catalogRevision": "previous"}), encoding="utf-8")
            previous_root.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": []}), encoding="utf-8")
            definitions.write_text(json.dumps({"definitionsRevision": "definitions"}), encoding="utf-8")
            previous_definitions.write_text(json.dumps({"definitionsRevision": "previous-definitions"}), encoding="utf-8")
            result = discord_notice.build_catalog(current, previous_root, definitions, previous_definitions, "dalagab/omega", "https://example.invalid/run")
        self.assertTrue(result["shouldNotify"])
        self.assertEqual("catalog", result["webhookKey"])
        self.assertEqual({"parse": []}, result["payload"]["allowed_mentions"])
        self.assertNotIn("@here", json.dumps(result))

    def test_security_notice_does_not_publish_without_evidence_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            database = Path(temporary) / "empty.sqlite"
            report.write_text(json.dumps({"publicationRequired": False, "candidate": {}}), encoding="utf-8")
            result = discord_notice.build_sigmascope(report, database, "dalagab/omega", "https://example.invalid/run")
        self.assertFalse(result["shouldNotify"])

    def test_definitions_change_publishes_without_catalog_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "catalog" / "index.json"
            previous = root / "previous" / "index.json"
            definitions = root / "definitions.json"
            previous_definitions = root / "previous-definitions.json"
            current.parent.joinpath("plugins").mkdir(parents=True)
            previous.parent.joinpath("plugins").mkdir(parents=True)
            for path in (current, previous):
                path.write_text(json.dumps({"catalogRevision": "same"}), encoding="utf-8")
                path.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": []}), encoding="utf-8")
            definitions.write_text(json.dumps({"definitionsRevision": "new"}), encoding="utf-8")
            previous_definitions.write_text(json.dumps({"definitionsRevision": "old"}), encoding="utf-8")
            result = discord_notice.build_catalog(current, previous, definitions, previous_definitions, "dalagab/omega", "https://example.invalid/run")
        self.assertTrue(result["shouldNotify"])
        self.assertEqual("definitions", result["webhookKey"])

    def test_security_notice_only_names_new_high_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            database = root / "security.sqlite"
            report.write_text(json.dumps({
                "publicationRequired": True,
                "candidate": {"revisions": {"evidenceRevision": "evidence"}},
                "queue": {"selected": {"variantId": 9, "name": "@here test", "workType": "artifact"}},
            }), encoding="utf-8")
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript("""
                    CREATE TABLE plugin_security_current(variant_id INTEGER, scan_id INTEGER, highest_severity TEXT);
                    CREATE TABLE plugin_security_scan_lineage(current_scan_id INTEGER, previous_scan_id INTEGER);
                    CREATE TABLE plugin_security_findings(scan_id INTEGER, rule_id TEXT, severity TEXT, title TEXT);
                    INSERT INTO plugin_security_current VALUES(9, 2, 'high');
                    INSERT INTO plugin_security_scan_lineage VALUES(2, 1);
                    INSERT INTO plugin_security_findings VALUES(1, 'same', 'high', 'Existing');
                    INSERT INTO plugin_security_findings VALUES(2, 'same', 'high', 'Existing');
                    INSERT INTO plugin_security_findings VALUES(2, 'new', 'high', '@everyone New');
                """)
                connection.commit()
            result = discord_notice.build_sigmascope(report, database, "dalagab/omega", "https://example.invalid/run")
        encoded = json.dumps(result)
        self.assertTrue(result["shouldNotify"])
        self.assertEqual("security", result["webhookKey"])
        self.assertIn("New", encoded)
        self.assertNotIn("Existing", encoded)
        self.assertNotIn("@everyone", encoded)

    def test_ordinary_review_routes_to_evidence_toni(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            database = root / "unused.sqlite"
            report.write_text(json.dumps({
                "publicationRequired": True,
                "candidate": {"revisions": {"evidenceRevision": "evidence"}},
                "queue": {"selected": {"name": "Test", "workType": "source"}},
            }), encoding="utf-8")
            result = discord_notice.build_sigmascope(report, database, "dalagab/omega", "https://example.invalid/run")
        self.assertEqual("evidence", result["webhookKey"])


    def test_voice_selection_is_deterministic_and_not_generated(self) -> None:
        identity = {"catalog": "cat-json-v1-abc", "definitions": "defs-v1-def"}
        first = discord_notice.voice_line("catalog", identity)
        second = discord_notice.voice_line("catalog", identity)
        self.assertEqual(first, second)
        self.assertIn(first, discord_notice.VOICE_LINES["catalog"])

    def test_voice_grammar_has_hundreds_of_deterministic_combinations_per_family(self) -> None:
        for kind in ("security", "catalog", "definitions", "evidence"):
            self.assertEqual(discord_notice.VOICE_COMBINATIONS_PER_KIND, len(discord_notice.VOICE_LINES[kind]))
            self.assertEqual(discord_notice.VOICE_COMBINATIONS_PER_KIND, len(set(discord_notice.VOICE_LINES[kind])))

    def test_voice_grammar_varies_across_event_identities_without_randomness(self) -> None:
        variants = {
            discord_notice.voice_line("catalog", {"catalog": f"catalog-{index}", "definitions": f"defs-{index}"})
            for index in range(200)
        }
        self.assertGreater(len(variants), 50)
        source = (common.ROOT / "tools" / "notifications" / "discord_notice.py").read_text(encoding="utf-8")
        self.assertNotIn("import random", source)
        self.assertNotIn("secrets.choice", source)

    def test_catalog_voice_is_rich_and_definitions_voice_is_happy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "catalog" / "index.json"
            previous = root / "previous" / "index.json"
            definitions = root / "definitions.json"
            previous_definitions = root / "previous-definitions.json"
            current.parent.joinpath("plugins").mkdir(parents=True)
            previous.parent.joinpath("plugins").mkdir(parents=True)
            current.write_text(json.dumps({"catalogRevision": "new-catalog"}), encoding="utf-8")
            previous.write_text(json.dumps({"catalogRevision": "old-catalog"}), encoding="utf-8")
            current.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": []}), encoding="utf-8")
            previous.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": []}), encoding="utf-8")
            definitions.write_text(json.dumps({"definitionsRevision": "same-defs"}), encoding="utf-8")
            previous_definitions.write_text(json.dumps({"definitionsRevision": "same-defs"}), encoding="utf-8")
            rich = discord_notice.build_catalog(
                current, previous, definitions, previous_definitions,
                "dalagab/omega", "https://example.invalid/run",
            )
            previous.write_text(json.dumps({"catalogRevision": "new-catalog"}), encoding="utf-8")
            definitions.write_text(json.dumps({"definitionsRevision": "new-defs"}), encoding="utf-8")
            previous_definitions.write_text(json.dumps({"definitionsRevision": "old-defs"}), encoding="utf-8")
            happy = discord_notice.build_catalog(
                current, previous, definitions, previous_definitions,
                "dalagab/omega", "https://example.invalid/run",
            )
        self.assertTrue(rich["payload"]["embeds"][0]["title"])
        self.assertTrue(any(line in rich["payload"]["embeds"][0]["description"] for line in discord_notice.VOICE_LINES["catalog"]))
        self.assertTrue(happy["payload"]["embeds"][0]["title"])
        self.assertTrue(any(line in happy["payload"]["embeds"][0]["description"] for line in discord_notice.VOICE_LINES["definitions"]))

    def test_security_voice_is_irritated_and_evidence_voice_smiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "security.sqlite"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript("""
                    CREATE TABLE plugin_security_current(variant_id INTEGER, scan_id INTEGER, highest_severity TEXT);
                    CREATE TABLE plugin_security_scan_lineage(current_scan_id INTEGER, previous_scan_id INTEGER);
                    CREATE TABLE plugin_security_findings(scan_id INTEGER, rule_id TEXT, severity TEXT, title TEXT);
                    INSERT INTO plugin_security_current VALUES(9, 2, 'critical');
                    INSERT INTO plugin_security_scan_lineage VALUES(2, 1);
                    INSERT INTO plugin_security_findings VALUES(2, 'new', 'critical', 'A new problem');
                """)
                connection.commit()
            security_report = root / "security-report.json"
            security_report.write_text(json.dumps({
                "publicationRequired": True,
                "candidate": {"revisions": {"evidenceRevision": "ev-security"}},
                "queue": {"selected": {"variantId": 9, "name": "Test", "workType": "artifact"}},
            }), encoding="utf-8")
            irritated = discord_notice.build_sigmascope(
                security_report, database, "dalagab/omega", "https://example.invalid/run"
            )

            evidence_report = root / "evidence-report.json"
            evidence_report.write_text(json.dumps({
                "publicationRequired": True,
                "candidate": {"revisions": {"evidenceRevision": "ev-review"}},
                "queue": {"selected": {"name": "Test", "workType": "source"}},
            }), encoding="utf-8")
            cocky = discord_notice.build_sigmascope(
                evidence_report, database, "dalagab/omega", "https://example.invalid/run"
            )

        security_embed = irritated["payload"]["embeds"][0]
        self.assertIn("Test", security_embed["title"])
        self.assertIn("Review the findings if you want to know more.", security_embed["description"])
        self.assertNotIn("verdict", security_embed["description"].casefold())
        self.assertTrue(any(line in security_embed["description"] for line in discord_notice.VOICE_LINES["security"]))
        self.assertIn("😏", cocky["payload"]["embeds"][0]["description"])
        self.assertTrue(any(line in cocky["payload"]["embeds"][0]["description"] for line in discord_notice.VOICE_LINES["evidence"]))

    def test_toni_owns_the_personality_and_catalog_language_is_run_agnostic(self) -> None:
        source = (common.ROOT / "tools" / "notifications" / "discord_notice.py").read_text(encoding="utf-8")
        self.assertNotIn("Sigmascope is not amused", source)
        self.assertNotIn("treating it as a verdict", source)
        self.assertNotIn("daily catalog snapshot", source.casefold())
        self.assertNotIn("smug scanner", source.casefold())
        self.assertNotIn("scanner needed one more thing to be irritated", source.casefold())
        self.assertIn("The latest catalog snapshot is published and ready for Omega.", source)
        self.assertIn("Review the findings if you want to know more.", source)
        for kind in ("security", "catalog", "definitions", "evidence"):
            for line in discord_notice.VOICE_LINES[kind]:
                self.assertNotIn("sigmascope", line.casefold())
                self.assertNotIn("scanner", line.casefold())


    def test_catalog_panel_reports_added_updated_removed_counts_and_two_stable_examples(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "current" / "index.json"
            previous = root / "previous" / "index.json"
            definitions = root / "definitions" / "index.json"
            previous_definitions = root / "previous-definitions" / "index.json"
            current.parent.joinpath("plugins").mkdir(parents=True)
            previous.parent.joinpath("plugins").mkdir(parents=True)
            definitions.parent.mkdir(parents=True)
            previous_definitions.parent.mkdir(parents=True)
            current.write_text(json.dumps({
                "catalogRevision": "catalog-new",
                "counts": {"plugins": 4, "variants": 6, "sources": 3},
            }), encoding="utf-8")
            previous.write_text(json.dumps({"catalogRevision": "catalog-old"}), encoding="utf-8")
            current.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": [
                {"pluginId": 1, "active": True, "name": "Kept", "sha256": "same"},
                {"pluginId": 2, "active": True, "name": "Updated One", "sha256": "new-2"},
                {"pluginId": 3, "active": True, "name": "Added One", "sha256": "new-3"},
                {"pluginId": 4, "active": True, "name": "Added Two", "sha256": "new-4"},
            ]}), encoding="utf-8")
            previous.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": [
                {"pluginId": 1, "active": True, "name": "Kept", "sha256": "same"},
                {"pluginId": 2, "active": True, "name": "Updated One", "sha256": "old-2"},
                {"pluginId": 9, "active": True, "name": "Removed One", "sha256": "old-9"},
            ]}), encoding="utf-8")
            definitions.write_text(json.dumps({"definitionsRevision": "defs-same"}), encoding="utf-8")
            previous_definitions.write_text(json.dumps({"definitionsRevision": "defs-same"}), encoding="utf-8")
            first = discord_notice.build_catalog(current, previous, definitions, previous_definitions, "dalagab/omega", "https://example.invalid/run")
            second = discord_notice.build_catalog(current, previous, definitions, previous_definitions, "dalagab/omega", "https://example.invalid/run")

        fields = {field["name"]: field["value"] for field in first["payload"]["embeds"][0]["fields"]}
        self.assertEqual("2", fields["Added"])
        self.assertEqual("1", fields["Updated"])
        self.assertEqual("1", fields["Removed"])
        self.assertIn("4 plugins", fields["Catalog size"])
        self.assertIn("6 active variants", fields["Catalog size"])
        self.assertEqual("3", fields["Sources"])
        self.assertEqual(first["payload"]["embeds"][0]["fields"], second["payload"]["embeds"][0]["fields"])
        example_lines = fields["Examples"].splitlines()
        self.assertGreaterEqual(len(example_lines), 1)
        self.assertLessEqual(len(example_lines), 2)
        self.assertTrue(any(name in fields["Examples"] for name in ("Updated One", "Added One", "Added Two", "Removed One")))

    def test_security_incident_links_new_reviewed_finding_to_exact_rule_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "security.sqlite"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript("""
                    CREATE TABLE plugin_security_current(variant_id INTEGER, scan_id INTEGER, highest_severity TEXT);
                    CREATE TABLE plugin_security_scan_lineage(current_scan_id INTEGER, previous_scan_id INTEGER);
                    CREATE TABLE plugin_security_findings(scan_id INTEGER, rule_id TEXT, severity TEXT, title TEXT);
                    INSERT INTO plugin_security_current VALUES(9, 2, 'high');
                    INSERT INTO plugin_security_scan_lineage VALUES(2, 1);
                    INSERT INTO plugin_security_findings VALUES(2, 'compound.network-execute', 'high', 'Network plus process execution');
                """)
                connection.commit()
            report = root / "report.json"
            report.write_text(json.dumps({
                "publicationRequired": True,
                "candidate": {"revisions": {"evidenceRevision": "ev-new"}},
                "queue": {"selected": {"variantId": 9, "name": "Linked Plugin", "workType": "artifact"}},
            }), encoding="utf-8")
            definitions = root / "definitions" / "index.json"
            rules = definitions.parent / "srl" / "packs" / "omega-core-compound" / "rules" / "compound-correlations.yaml"
            rules.parent.mkdir(parents=True)
            rules.write_text("schema: omega.sigmascope.ruleset.v1\nrules:\n  - id: compound.network-execute\n", encoding="utf-8")
            srl_index = definitions.parent / "srl" / "index.json"
            srl_index.write_text(json.dumps({"packs": [{
                "id": "omega-core-compound",
                "rules": [{"path": "rules/compound-correlations.yaml", "ruleIds": ["compound.network-execute"]}],
            }]}), encoding="utf-8")
            definitions.write_text(json.dumps({
                "builtFromDevCommit": "0123456789abcdef",
                "srlDefinitionPacks": {"path": "srl/index.json"},
            }), encoding="utf-8")
            result = discord_notice.build_sigmascope(
                report, database, "dalagab/omega", "https://example.invalid/run", definitions
            )

        fields = {field["name"]: field["value"] for field in result["payload"]["embeds"][0]["fields"]}
        self.assertIn("Reviewed rule YAML", fields)
        self.assertIn("compound.network-execute", fields["Reviewed rule YAML"])
        self.assertIn("/blob/0123456789abcdef/security-definitions/packs/omega-core-compound/rules/compound-correlations.yaml#L3", fields["Reviewed rule YAML"])
        self.assertNotIn("/blob/sigmascope/", fields["Reviewed rule YAML"])

    def test_definitions_panel_reports_rule_capability_osv_source_metrics_and_changed_pack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "catalog" / "index.json"
            previous = root / "previous" / "index.json"
            definitions = root / "definitions" / "index.json"
            previous_definitions = root / "previous-definitions" / "index.json"
            current.parent.joinpath("plugins").mkdir(parents=True)
            previous.parent.joinpath("plugins").mkdir(parents=True)
            for path in (current, previous):
                path.write_text(json.dumps({"catalogRevision": "same"}), encoding="utf-8")
                path.parent.joinpath("plugins", "index.json").write_text(json.dumps({"plugins": []}), encoding="utf-8")
            for parent in (definitions.parent, previous_definitions.parent):
                parent.joinpath("srl").mkdir(parents=True)
            definitions.write_text(json.dumps({
                "definitionsRevision": "defs-new",
                "srlDefinitionPacks": {"path": "srl/index.json", "packCount": 2, "activeRuleCount": 7},
                "capabilityRegistry": {"capabilityCount": 40, "categoryCount": 14},
                "osv": {"queriedPackages": 123, "matchedPackages": 4},
                "sourceObservations": {"counts": {"repositories": 30, "observed": 28, "failed": 2}},
            }), encoding="utf-8")
            previous_definitions.write_text(json.dumps({
                "definitionsRevision": "defs-old",
                "srlDefinitionPacks": {"path": "srl/index.json", "packCount": 2, "activeRuleCount": 6},
            }), encoding="utf-8")
            definitions.parent.joinpath("srl", "index.json").write_text(json.dumps({"packs": [
                {"id": "omega-core-compound", "title": "Omega Core compound", "packRevision": "new-pack"},
                {"id": "omega-static", "title": "Omega Static", "packRevision": "same-pack"},
            ]}), encoding="utf-8")
            previous_definitions.parent.joinpath("srl", "index.json").write_text(json.dumps({"packs": [
                {"id": "omega-core-compound", "title": "Omega Core compound", "packRevision": "old-pack"},
                {"id": "omega-static", "title": "Omega Static", "packRevision": "same-pack"},
            ]}), encoding="utf-8")
            result = discord_notice.build_catalog(
                current, previous, definitions, previous_definitions, "dalagab/omega", "https://example.invalid/run"
            )

        fields = {field["name"]: field["value"] for field in result["payload"]["embeds"][0]["fields"]}
        self.assertEqual("2 packs • 7 active rules", fields["Rule packs"])
        self.assertEqual("40 capabilities • 14 categories", fields["Capabilities"])
        self.assertEqual("4 matched • 123 package/version pairs checked", fields["OSV coverage"])
        self.assertEqual("28/30 observed • 2 failed", fields["Source watch"])
        self.assertIn("Omega Core compound", fields["Changed packs"])

    def test_evidence_panel_reports_current_findings_and_delta(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "security.sqlite"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript("""
                    CREATE TABLE plugin_security_current(variant_id INTEGER, scan_id INTEGER, highest_severity TEXT);
                    CREATE TABLE plugin_security_scan_lineage(current_scan_id INTEGER, previous_scan_id INTEGER);
                    CREATE TABLE plugin_security_findings(scan_id INTEGER, rule_id TEXT, severity TEXT, title TEXT);
                    INSERT INTO plugin_security_current VALUES(7, 2, 'caution');
                    INSERT INTO plugin_security_scan_lineage VALUES(2, 1);
                    INSERT INTO plugin_security_findings VALUES(1, 'old', 'caution', 'Cleared old finding');
                    INSERT INTO plugin_security_findings VALUES(2, 'new', 'caution', 'New caution finding');
                """)
                connection.commit()
            report = root / "report.json"
            report.write_text(json.dumps({
                "publicationRequired": True,
                "candidate": {"revisions": {"evidenceRevision": "ev-review"}},
                "queue": {"selected": {"variantId": 7, "name": "Evidence Plugin", "workType": "source"}},
            }), encoding="utf-8")
            result = discord_notice.build_sigmascope(report, database, "dalagab/omega", "https://example.invalid/run")

        fields = {field["name"]: field["value"] for field in result["payload"]["embeds"][0]["fields"]}
        self.assertIn("1 total", fields["Current findings"])
        self.assertIn("1 caution", fields["Current findings"])
        self.assertEqual("+1 new • -1 cleared", fields["Finding delta"])
        self.assertIn("New caution finding", fields["Examples"])

    def test_notification_workflows_keep_webhook_secrets_in_isolated_jobs(self) -> None:
        workflow_root = common.ROOT / ".github" / "workflows"
        for name in ("catalog-builder.yml", "sigmascope.yml"):
            workflow = (workflow_root / name).read_text(encoding="utf-8")
            self.assertIn("tools/notifications/discord_notice.py", workflow)
            if name == "sigmascope.yml":
                self.assertIn("--definitions-index catalog/active-state/definitions/index.json", workflow)
            self.assertIn("tools/notifications/post_discord_notice.py", workflow)
            self.assertIn("environment: discord-public", workflow)
            build_side, notify_side = workflow.split("  notify-discord:", 1)
            self.assertNotIn("DISCORD_SECURITY_WEBHOOK_URL", build_side)
            self.assertNotIn("DISCORD_CATALOG_WEBHOOK_URL", build_side)
            self.assertIn("DISCORD_SECURITY_WEBHOOK_URL", notify_side)
            self.assertIn("permissions: {}", notify_side)

    def test_catalog_notification_merge_preserves_migration_and_v2_guards(self) -> None:
        workflow = (common.ROOT / ".github" / "workflows" / "catalog-builder.yml").read_text(encoding="utf-8")
        self.assertIn("id: previous_catalog", workflow)
        self.assertIn('steps.previous_catalog.outputs.current', workflow)
        self.assertIn('args+=(--previous-catalog-root catalog/previous-state/catalog)', workflow)
        self.assertIn("validate_marketplace_catalog.py --root catalog/client-dist --require-v2", workflow)


    def test_sender_uses_discord_api_user_agent_and_safe_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            notice_path = Path(temporary) / "notice.json"
            notice_path.write_text(json.dumps({
                "schema": "omega.discord-notice.v1",
                "event": "catalog",
                "webhookKey": "catalog",
                "eventId": "test",
                "shouldNotify": True,
                "payload": {
                    "username": "TONI",
                    "allowed_mentions": {"parse": []},
                    "embeds": [{"title": "Test"}],
                },
            }), encoding="utf-8")

            captured = {}

            class Response:
                status = 204
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc, tb):
                    return False

            def fake_urlopen(request, timeout=0):
                captured["request"] = request
                captured["timeout"] = timeout
                return Response()

            with patch.dict("os.environ", {
                "DISCORD_CATALOG_WEBHOOK_URL": "https://discord.com/api/webhooks/123/secret-token",
            }, clear=False), patch.object(post_discord_notice, "urlopen", fake_urlopen), patch.object(
                sys, "argv", ["post_discord_notice.py", "--notice", str(notice_path)]
            ):
                self.assertEqual(0, post_discord_notice.main())

        request = captured["request"]
        self.assertEqual("POST", request.get_method())
        self.assertEqual("application/json", request.get_header("Content-type"))
        self.assertEqual("application/json", request.get_header("Accept"))
        self.assertEqual(post_discord_notice.USER_AGENT, request.get_header("User-agent"))
        self.assertTrue(post_discord_notice.USER_AGENT.startswith("DiscordBot ("))
        self.assertEqual(15, captured["timeout"])


if __name__ == "__main__":
    unittest.main()
