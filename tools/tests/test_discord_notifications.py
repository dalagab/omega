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
        self.assertEqual("Omega catalog updated", rich["payload"]["embeds"][0]["title"])
        self.assertTrue(any(line in rich["payload"]["embeds"][0]["description"] for line in discord_notice.VOICE_LINES["catalog"]))
        self.assertEqual("Omega definitions updated", happy["payload"]["embeds"][0]["title"])
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
        self.assertEqual("New security findings for Test", security_embed["title"])
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


    def test_notification_workflows_keep_webhook_secrets_in_isolated_jobs(self) -> None:
        workflow_root = common.ROOT / ".github" / "workflows"
        for name in ("catalog-builder.yml", "sigmascope.yml"):
            workflow = (workflow_root / name).read_text(encoding="utf-8")
            self.assertIn("tools/notifications/discord_notice.py", workflow)
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
        self.assertIn('steps.previous_catalog.outputs.compatible', workflow)
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
