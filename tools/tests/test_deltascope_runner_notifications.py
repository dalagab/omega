from __future__ import annotations
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "tools" / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))

import deltascope_runner_notifications as notifications

class RunnerNotificationTests(unittest.TestCase):
    def test_patch_reuses_notification_center_and_live_endpoint(self) -> None:
        html = "<html><script>function upsertNotification(){} function setWorkbenchView(){}</script></html>"
        patched = notifications._patch_html(html)
        self.assertIn("__deltascopeRunnerNotificationsInstalled", patched)
        self.assertIn("upsertNotification(n)", patched)
        self.assertIn("/api/operations/live?foreground=0", patched)
        self.assertIn("deltascope.runner-notifications.state.v1", patched)
        self.assertIn("Notification.requestPermission()", patched)
        self.assertIn("MAX_HISTORY=80", patched)
        self.assertNotIn("Authorization", patched)
        self.assertNotIn("Bearer ", patched)

    def test_first_snapshot_is_baseline(self) -> None:
        source = notifications._NOTIFICATION_JS
        self.assertIn("if(prev&&prev.runs&&prev.jobs&&prev.runners)compare(prev,cur)", source)
        self.assertIn("saveJson(STATE_KEY,cur)", source)

    def test_categories_cover_runner_progress_and_failure(self) -> None:
        source = notifications._NOTIFICATION_JS
        for marker in ("completed with", "assigned", "progressed", "reports this runner offline", "Runner status is stale"):
            self.assertIn(marker, source)

if __name__ == "__main__":
    unittest.main()
