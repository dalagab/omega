from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_0015_compat
import deltascope_availability
import deltascope_workflow_center
import developer_view


class DeltaScopeAvailabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        deltascope_0015_compat.install()
        deltascope_workflow_center.install()
        deltascope_availability.install()

    def test_plugin_scoped_navigation_remains_visible_but_disabled_without_subject(self) -> None:
        html = developer_view.HTML
        self.assertIn("developer:new Set(['Security Review','Journey','Behaviors','Changes','Omega Profile','Source & Build'])", html)
        self.assertIn("setUnavailable(button,needsPlugin&&!selected,'Select a plugin from the top bar first.')", html)
        self.assertIn('.workbench-nav button[data-perspective-route]:disabled', html)

    def test_contextual_disabled_controls_explain_how_to_unlock(self) -> None:
        html = developer_view.HTML
        for text in (
            'Select a plugin first.',
            'Connect GitHub first.',
            'Select a local Rift JSON report first.',
            'Paste a GitHub JSON report link first.',
            'Acquire workflow details first.',
            'Type DISPATCH to enable this action.',
            'Type ${expected} to enable this action.',
        ):
            self.assertIn(text, html)
        self.assertIn('el.dataset.unavailableReason=', html)
        self.assertIn("el.setAttribute('aria-disabled','true')", html)

    def test_workflow_actions_stay_visible_when_unavailable(self) -> None:
        html = developer_view.HTML
        self.assertIn("dispatch.dataset.availabilityPlaceholder='dispatch'", html)
        self.assertIn('This acquired workflow does not declare workflow_dispatch on the selected ref.', html)
        self.assertIn('Connect GitHub workflow access, then reacquire this workflow to enable run controls.', html)

    def test_confirmation_gates_mutating_workflow_actions(self) -> None:
        html = developer_view.HTML
        self.assertIn("String(confirmation?.value||'').trim()==='DISPATCH'", html)
        self.assertIn("String(runConfirm?.value||'').trim()===expected", html)
        self.assertIn("setUnavailable(dispatch,!connected||!confirmed,reason)", html)


if __name__ == '__main__':
    unittest.main()
