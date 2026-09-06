#!/usr/bin/env python3
"""DeltaScope: developer-only, read-only Omega security evidence and Stigma-1 / SRL Core workbench entry point.

DeltaScope never scans plugins and never publishes catalog, Definitions, or Security
Evidence state. Published/security state is inspected read-only. The Rules workspace may
write only versioned user-authored SRL YAML under the configured local rule home
(default: ~/.omega/deltascope/rules/v1).
"""
from __future__ import annotations

from developer_view import main
import deltascope_0015_compat
import deltascope_workflow_center
import deltascope_availability
import deltascope_delivery_dashboard
import deltascope_scan_report
import deltascope_platform_comprehension
import deltascope_orchestration_alignment

deltascope_0015_compat.install()
deltascope_workflow_center.install()
deltascope_availability.install()
deltascope_delivery_dashboard.install()
deltascope_scan_report.install()
deltascope_platform_comprehension.install()
deltascope_orchestration_alignment.install()

if __name__ == "__main__":
    raise SystemExit(main())
