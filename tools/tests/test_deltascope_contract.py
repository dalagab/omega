from __future__ import annotations
import unittest
import common

class DeltaScopeContractTests(unittest.TestCase):
    def test_deltascope_is_explicit_and_read_only(self) -> None:
        wrapper = (common.ROOT / "tools" / "security" / "deltascope.py").read_text(encoding="utf-8")
        view = (common.ROOT / "tools" / "security" / "developer_view.py").read_text(encoding="utf-8")
        workflow = (common.ROOT / ".github" / "workflows" / "deltascope.yml").read_text(encoding="utf-8")
        self.assertIn("read-only Omega security evidence and Stigma-1 / SRL Core workbench", wrapper)
        self.assertIn("DeltaScope", view)
        self.assertIn("definition-packs", view)
        self.assertIn("--definitions-root", view)
        self.assertIn('class="omega-mark"', view)
        self.assertIn('aria-label="Omega">O</span>', view)
        self.assertIn("TONI", view)
        self.assertIn("deterministic evidence guide", view)
        for token in ("Search plugins, hashes, endpoints, authors, rules, CVEs", "Plugin Developer", "Investigator", "Security Researcher", "Operations", "Plugins", "Journey", "Findings", "Network", "Compare", "Malware", "ClamAV & YARA", "ClamAV antivirus", "YARA rules", "Endpoint intelligence", "Code & native", "Supply chain", "Immutable evidence", "Metrics & coverage · exact drill-down counts", "SOURCE CODE", "ARTIFACT ONLY", "Advanced · raw Evidence-v2 / database browser", "Relationship graph", "Version-to-version security comparison", "Why this severity?", "What evidence is missing?", "v2_unscanned_queue", "v2_review_variants", "v2_queue_items", "v2_historical_snapshots", "v2_analyses", "v2_finding_breakdown", 'parsed.path == "/api/snapshot"', 'parsed.path == "/api/analysis-manifest"', 'parsed.path == "/api/workbench/search"', 'parsed.path == "/api/workbench/compare"', 'id="perspectiveSelect"', 'Build .omega/plugin.yaml from what Omega actually observed', 'path == "/api/developer-profile/render"', 'Explain this step'):
            self.assertIn(token, view)
        for token in ("Dashboard", "Cases", "Events", "Intelligence", "Plugins", "Rules", "Reports", "Documentation", "System health", "data-perspective-route", "data-workbench-view", "DERIVED · READ ONLY", "NO DIRECT ACTIVATION", "My Rules stay local until normal GitHub review/CI", "DeltaScope does not assign, close or mutate incidents", "One Stigma-1 workspace"):
            self.assertIn(token, view)
        self.assertIn("const definitionsPill=$('definitionsPill');if(definitionsPill)", view)
        self.assertNotIn("$('definitionsPill').innerHTML=", view)
        self.assertNotIn("rule-reproject", view)
        self.assertNotIn("--projection-output", view)
        self.assertIn('/api/workbench', view)
        self.assertIn('/api/platform-contracts', view)
        self.assertIn('published-frozen-definitions', view)
        self.assertIn('deltascope_resources.sync_published_resources', view)
        self.assertIn('/api/workbench/rule-library', view)
        self.assertIn('Rule library', view)
        self.assertIn('System Rules + versioned My Rules', view)
        self.assertIn('Fork to My Rules', view)
        self.assertIn('Save revision', view)
        self.assertIn('~/.omega/deltascope/rules/v1', view)
        self.assertIn('/api/workbench/rule-workspace', view)
        self.assertIn('/api/rule-lab/local/save', view)
        self.assertIn('/api/rule-lab/local/fork', view)
        self.assertIn('/api/rule-lab/graph', view)
        self.assertIn('/api/rule-lab/graph-yaml', view)
        self.assertIn('Drag nodes into the canvas', view)
        self.assertIn('SRL Core', view)
        # DeltaScope owns the browser viewport: pages never use document/main scrolling;
        # only bounded workbench panels may scroll their own content.
        for token in (
            'html,body{height:100%;min-height:0;overflow:hidden',
            '.app-shell>main{height:100%;min-height:0;overflow:hidden',
            '.workspace-view{height:100%;min-height:0;overflow:hidden}',
            '#workbench-rules>.rule-browser-shell{flex:1 1 auto;height:auto;min-height:0',
            '#workbench-assets #pluginDetail{flex:1 1 auto;min-height:0;overflow:auto',
            '#rawEvidence[open]{display:flex;flex:1 1 auto;flex-direction:column}',
        ):
            self.assertIn(token, view)
        self.assertIn('Published active snapshot provenance', view)
        self.assertIn('/api/workbench/relationships', view)
        self.assertIn('/api/workbench/pivot', view)
        self.assertIn('/api/workbench/asset-relations', view)
        self.assertIn('Relationship graph', view)
        self.assertIn('Shared components', view)
        self.assertIn('Known advisories', view)
        self.assertIn('deltascope_workbench.project_workbench', view)
        self.assertIn('Propose on GitHub', view)
        self.assertIn('/api/rule-lab/proposal', view)
        self.assertIn('GitHub-ready candidate bundle', view)
        self.assertIn('proposal path uses no GitHub API write or repository credentials', view)
        self.assertNotIn('/api/rule-lab/promote', view)
        self.assertIn("--no-download", workflow)
        self.assertNotIn("publish_security_evidence_v2.py", workflow)
        self.assertNotIn("publish_catalog_state.py", workflow)
        self.assertNotIn("schedule:", workflow)

if __name__ == "__main__":
    unittest.main()
