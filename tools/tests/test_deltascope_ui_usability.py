from __future__ import annotations

import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import developer_view


class DeltaScopeUiUsabilityTests(unittest.TestCase):
    def test_developer_subject_actions_are_not_shadowed(self) -> None:
        html = developer_view.HTML
        self.assertEqual(html.count("if(currentPerspective==='developer')return commonSeverity+"), 1)
        self.assertIn('data-subject-tab="findings">Security Review', html)
        self.assertIn('data-subject-tab="journey">Journey', html)
        self.assertIn('data-subject-tab="profile">Omega Profile', html)
        self.assertIn('data-subject-tab="supply">Source & Build', html)

    def test_global_shortcuts_are_available_without_stealing_editor_keys(self) -> None:
        html = developer_view.HTML
        self.assertIn('function keyboardTargetIsEditable', html)
        self.assertIn("key.toLowerCase()==='k'", html)
        self.assertIn("if(key==='/')", html)
        self.assertIn("if(key==='?')", html)
        self.assertIn('Rule-editor shortcuts remain available', html)

    def test_user_selected_perspective_becomes_next_start_perspective(self) -> None:
        self.assertIn(
            "$('perspectiveSelect').addEventListener('change',e=>{rememberPerspective(e.target.value);setPerspective(e.target.value)})",
            developer_view.HTML,
        )

    def test_researcher_landing_prioritizes_novelty_patterns_and_gaps(self) -> None:
        html = developer_view.HTML
        for token in (
            'RESEARCH DELTA',
            'Pattern clusters',
            'Coverage gaps worth researching',
            'Your research context',
            'TONI research leads',
            'Corpus & queue metrics · operational context',
        ):
            self.assertIn(token, html)
        self.assertIn('.perspective-researcher #operationsDashboard{display:none}', html)
        self.assertIn('previous Evidence revision observed by this local DeltaScope instance', html)
        self.assertIn('ranked by spread × severity', html)

    def test_researcher_delta_is_local_and_does_not_fake_corpus_history(self) -> None:
        html = developer_view.HTML
        self.assertIn("RESEARCH_SNAPSHOT_HISTORY_KEY='deltascope.research.snapshot-history.v1'", html)
        self.assertIn('No historical change is being invented.', html)
        self.assertIn('Sparse/unused-rule research still requires finding-frequency indexes', html)

    def test_researcher_metrics_are_demoted_and_operations_keep_actions(self) -> None:
        html = developer_view.HTML
        self.assertIn('id="researcherMetricCards"', html)
        self.assertIn('id="operationsDashboard"', html)
        self.assertIn('<h2>Components & Actions</h2>', html)
        self.assertIn('Operational priority view over published current evidence.', html)


    def test_plugin_developer_landing_is_resolution_first(self) -> None:
        html = developer_view.HTML
        for token in (
            'As users see you',
            'Capability explanations',
            'Resolution path',
            'Why is this flagged?',
            'Suggest phrasing',
            'Legitimate behavior',
            'Fix code',
            'Dispute',
            'Marketplace impact',
            'Resolve next',
        ):
            self.assertIn(token, html)
        self.assertIn('Understand → decide → act → verify', html)
        self.assertIn('This draft feeds the same .omega/plugin.yaml builder', html)
        self.assertIn("DEVELOPER_RESOLUTION_DRAFT_KEY='deltascope.developer-resolution-drafts.v1'", html)

    def test_developer_resolution_does_not_claim_security_authority(self) -> None:
        html = developer_view.HTML
        self.assertIn('local developer draft · independent evidence remains unchanged', html)
        self.assertIn('It does not erase the independent severity badge or finding count.', html)
        self.assertIn('DeltaScope does not mark a finding accepted from this local draft.', html)
        self.assertIn('Comparable developer-explanation examples are not indexed in this snapshot yet', html)

    def test_contextual_documentation_opens_as_dismissible_overlay(self) -> None:
        html = developer_view.HTML
        self.assertIn('id="documentationOverlay"', html)
        self.assertIn('id="documentationOverlayClose"', html)
        self.assertIn('async function openContextDocumentation(){const context=contextualDocumentationForCurrentPage();await openDocumentationOverlay(context.doc)}', html)
        self.assertIn("if(e.target===$('documentationOverlay'))closeDocumentationOverlay()", html)
        self.assertIn("root.querySelector('[data-profile-guide]')?.addEventListener('click',()=>openDocumentationOverlay('plugin-developers'))", html)

    def test_profile_builder_and_resolution_editor_share_one_local_draft(self) -> None:
        html = developer_view.HTML
        self.assertIn('function syncProfileBuilderToDeveloperDraft', html)
        self.assertIn("decision:included&&reason.trim()?'explain'", html)
        self.assertIn("const local=developerCapabilityLocal(d,c),include=!!c.declared||local.decision==='explain'", html)
        self.assertIn('profileDraft=readDeveloperResolutionDraft(d)', html)

    def test_desktop_left_rail_never_scrolls_and_researcher_nav_compacts(self) -> None:
        view = developer_view.HTML
        self.assertIn("DeltaScope 4.21.12 fixed navigation rail", view)
        self.assertIn("#perspectiveNav{overflow:hidden!important", view)
        self.assertIn(".perspective-researcher #perspectiveNav button[data-perspective-route]{min-height:32px!important", view)
        self.assertIn("@media(min-width:901px) and (max-height:850px)", view)
        self.assertIn(".perspective-researcher .toni-rail-message{display:none!important}", view)

    def test_carbon_theme_uses_dark_chrome_light_workspace_and_dark_editor_only(self) -> None:
        html = developer_view.HTML
        self.assertIn('header,.workbench-nav,.toni-rail{background:#161616!important;color:#f4f4f4!important}', html)
        self.assertIn('.app-shell,.app-shell>main,.workspace-view{background:#f4f4f4!important;color:#161616!important}', html)
        self.assertIn('.app-shell>main .developer-resolution-progress,', html)
        self.assertIn('#workbench-rules .rule-intel-panel,', html)
        self.assertIn('#workbench-rules .rule-smart-editor,', html)
        self.assertIn('background:#080c10!important;color:#d9e4ea!important', html)
        self.assertIn('.research-pattern-row,.research-gap-row,.research-lead-row,.research-context-row,', html)
        self.assertIn('.app-shell>main .researcher-metrics>summary{background:#fff!important;color:#393939!important}', html)
        self.assertIn('.app-shell>main .research-lead-row p{color:#525252!important}', html)

    def test_plugin_dossier_keeps_logical_variant_renderer_defined(self) -> None:
        html = developer_view.HTML
        self.assertIn('function logicalPluginVariantsHtml(d,id)', html)
        self.assertIn('function logicalPluginDivergenceHtml(ctx)', html)
        self.assertIn('${logicalPluginVariantsHtml(d,id)}', html)

    def test_rift_page_accepts_explicit_local_or_github_report_intake(self) -> None:
        html = developer_view.HTML
        self.assertIn('id=riftFileInput type=file', html)
        self.assertIn('id=riftGithubUrl type=url', html)
        self.assertIn('/api/workbench/rift-reports/intake', html)
        self.assertIn('Changing pages never reloads or refetches the report.', html)
        self.assertNotIn("$('riftRefresh').addEventListener", html)
        self.assertIn("payload?.rift||{},'rift-runtime'", html)

    def test_workflow_plugin_link_uses_declared_scanner_contract(self) -> None:
        html = developer_view.HTML
        self.assertIn('Plugin GitHub link', html)
        self.assertIn('/api/operations/plugin-link?url=', html)
        self.assertIn("host.querySelector('[data-workflow-input=\"internal_names\"]')", html)
        self.assertIn('DeltaScope never invents an undeclared scanner parameter.', html)
        self.assertIn('through the existing internal_names contract.', html)

    def test_findings_page_is_case_inbox_with_local_triage_and_resolution_actions(self) -> None:
        html = developer_view.HTML
        for token in (
            'Case inbox',
            'Since last visit',
            'My open findings',
            'Triage selected',
            'False positive',
            'Real concern · escalate',
            'Confirm expected',
            'LOCAL TRIAGE · PUBLISHED EVIDENCE UNCHANGED',
            'Reason required for false positive / escalation',
        ):
            self.assertIn(token, html)
        self.assertNotIn('<h2>Latest security findings</h2>', html)
        self.assertNotIn('<h2>Derived incident groups</h2>', html)
        self.assertIn('/api/workbench/triage', html)
        self.assertIn('Rule/category/endpoint/pattern filters use the bounded', html)

    def test_threat_intelligence_leads_with_corpus_intersection_and_cross_links(self) -> None:
        html = developer_view.HTML
        for token in (
            'Feed indicators observed in the corpus',
            'Corpus endpoint research queue',
            'SHARED INFRASTRUCTURE',
            'Unlisted & unrecognised',
            'Feed health & lifecycle',
            'Behavior / ATT&amp;CK research lens',
            'Full frozen feed data',
            'show loopback/private',
            'findingEndpointFilter',
            'Indicator → findings',
            'FEED MATCH',
            'FEED ADJACENCY',
        ):
            self.assertIn(token, html)
        self.assertIn("loadThreatIntelligence(false)};", html)
        self.assertIn('resolved IP is feed-listed', html)
        self.assertIn("latestFindingRows()", html)
        self.assertIn('data-finding-threat-host', html)
        self.assertIn('Open Threat Intelligence for this host.', html)
        self.assertIn('data-threat-attack-query', html)
        self.assertIn('Show findings', html)
        self.assertIn("currentWorkbenchCase&&$('incidentCasePanel')", html)

    def test_findings_my_open_view_requires_local_researcher_identity(self) -> None:
        html = developer_view.HTML
        self.assertIn("myOpen.disabled=!me", html)
        self.assertIn("meOwner.disabled=!me", html)
        self.assertIn('Set My local researcher name first.', html)

    def test_finding_lineage_is_investigator_narrative_not_collection_topology(self) -> None:
        html = developer_view.HTML
        for token in (
            '1 · What was found',
            'Triggering evidence',
            '2 · Why it was found',
            'Rule evaluation trace',
            '3 · Why this severity',
            'Counter-evidence and negative context',
            'Version, time and scope',
            'Other variants this rule matched',
            'Acquire rule fan-out',
            'Developer-friendly export',
            'Copy developer explanation',
            'Inspect matched rows',
        ):
            self.assertIn(token, html)
        self.assertIn('/api/workbench/rule-fanout?', html)
        self.assertIn('This collection view is pre-filtered to rows that participated in the finding lineage.', html)
        self.assertIn('<summary>System provenance graph</summary>', html)



    def test_intelligence_is_fast_corpus_pivot_workspace_with_nonempty_default_brief(self) -> None:
        html = developer_view.HTML
        for token in (
            'Corpus pivots',
            'Capabilities / behaviors',
            'Families / lineage',
            'Authors',
            'Code reuse',
            'Corpus intelligence brief',
            'Co-occurs with',
            'First seen',
            'this DeltaScope instance',
            'Different-repository forks/renames are not inferred',
        ):
            self.assertIn(token, html)
        self.assertIn('Requires a published code/string/resource fingerprint index.', html)
        self.assertNotIn('Select an endpoint, component or advisory to pivot across affected plugins.', html)
        self.assertIn('data-intel-catalog-kind="behavior"', html)
        self.assertIn('data-intel-catalog-kind="family"', html)
        self.assertIn('data-intel-catalog-kind="author"', html)



    def test_primary_workspace_dom_targets_exist(self) -> None:
        html = developer_view.HTML
        for workspace in (
            'workbench-assets',
            'workbench-rules',
            'workbench-collectors',
            'workbench-coverage',
            'workbench-threat-intelligence',
            'workbench-queue',
            'workbench-reports',
        ):
            self.assertIn(f'<section id="{workspace}"', html)

    def test_rules_workspace_dom_contract_and_bootstrap_guard(self) -> None:
        html = developer_view.HTML
        for token in (
            'id="ruleBrowserShell"',
            'id="ruleTree"',
            'id="ruleYaml"',
            'id="ruleLibrarySearch"',
            'id="ruleVisualCanvas"',
        ):
            self.assertIn(token, html)
        self.assertIn("const el=$('ruleYaml');if(!el)return false", html)
        self.assertIn("if(!$('ruleBrowserShell'))return false", html)
        self.assertIn("if($('workbench-rules')&&$('ruleYaml')&&$('ruleTree'))", html)
        self.assertIn("const tree=$('ruleTree'),host=$('workbench-rules');if(tree)", html)

    def test_plugin_behaviors_closes_corpus_pivot_loop_with_matched_evidence(self) -> None:
        html = developer_view.HTML
        for token in (
            'data-research-tab=behaviors',
            'data-plugin-behaviors=',
            'Arrived from Intelligence',
            'Show only this behavior',
            'Show all behaviors',
            'Back to pivot',
            'Other plugins with this evidence',
            'Affected assets & matched evidence',
            'View behavior in plugin',
            '/api/workbench/behaviors',
            '/api/workbench/pivot-evidence',
            '/api/workbench/evidence-fanout',
        ):
            self.assertIn(token, html)
        self.assertIn('What was observed, grouped by behavior rather than by evidence producer.', html)
        self.assertIn('ordinary page navigation still performs no fan-out', html)
        self.assertIn("await loadDetail(variantId,'behaviors')", html)



if __name__ == '__main__':
    unittest.main()
