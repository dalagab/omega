#!/usr/bin/env python3
"""Local Omega Sigmascope runner for filling a disposable Security Evidence v2 test set.

This tool is intentionally separate from the production GitHub Actions pipeline.  It
creates a small working SQLite catalog containing the normal Omega plugin/source
identity tables but *none* of the old multi-gigabyte security history.  The existing
Sigmascope then examines selected live plugin artifacts/sources into that working
catalog, OSV advisories are collected from the newly observed NuGet package versions,
and the result is exported to a normal Security Evidence v2 tree for local testing.

The validated v1 database and the previously migrated v2 baseline are never modified.

Typical test run from the Omega repository root::

    python tools/security/local_sigmascope_v2_test.py \
      --evidence D:/OmegaEvidenceV2 \
      --work-dir D:/OmegaSigmascopeTest \
      --max-scans 50

Examine every active downloadable variant (can take a long time)::

    python tools/security/local_sigmascope_v2_test.py \
      --evidence D:/OmegaEvidenceV2 \
      --work-dir D:/OmegaSigmascopeTest \
      --all

Set GITHUB_TOKEN or GH_TOKEN before running when source examination is enabled.  A token
is strongly recommended because public repository metadata/source downloads otherwise
hit GitHub's anonymous API rate limit quickly.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
from types import SimpleNamespace
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR.parent
CATALOG_DIR = TOOLS_DIR / "catalog"
for path in (SCRIPT_DIR, CATALOG_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import collect_public_advisories  # noqa: E402
import sigmascope  # noqa: E402
from migrate_security_evidence_v2 import migrate  # noqa: E402
from security_evidence_v2 import NUGET_KINDS, open_ro, read_meta, sha256_file, table_exists  # noqa: E402
from validate_security_evidence_v2 import infer_database_from_migration_state, validate  # noqa: E402

SCHEMA = "omega.local-security-v2-test.v1"
DEFAULT_MAX_SCANS = 50
IDENTITY_TABLES = ("sources", "plugins", "plugin_variants")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def source_signature(database: Path) -> dict[str, Any]:
    with closing(open_ro(database)) as db:
        meta = read_meta(db)
        return {
            "databaseBytes": database.stat().st_size,
            "baseRevision": meta.get("base_revision", meta.get("catalog_base_revision", "")),
            "catalogRevision": meta.get("catalog_revision", meta.get("catalog_revision_candidate", "")),
            "securityRevision": meta.get("security_revision", ""),
            "evidenceRevision": meta.get("evidence_revision", ""),
        }


def _copy_table_schema_and_rows(source: sqlite3.Connection, target: sqlite3.Connection, table: str) -> None:
    row = source.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if row is None or not row[0]:
        raise RuntimeError(f"source database is missing required identity table {table}")
    target.execute(str(row[0]))
    columns = [str(item[1]) for item in source.execute(f'PRAGMA table_info("{table}")')]
    if not columns:
        return
    quoted = ",".join(f'"{column}"' for column in columns)
    placeholders = ",".join("?" for _ in columns)
    insert = f'INSERT INTO "{table}"({quoted}) VALUES({placeholders})'
    cursor = source.execute(f'SELECT {quoted} FROM "{table}"')
    while True:
        rows = cursor.fetchmany(1000)
        if not rows:
            break
        target.executemany(insert, rows)


def _copy_identity_indexes(source: sqlite3.Connection, target: sqlite3.Connection) -> None:
    for row in source.execute(
        """SELECT sql FROM sqlite_master
             WHERE type='index' AND sql IS NOT NULL AND tbl_name IN ('sources','plugins','plugin_variants')
             ORDER BY name"""
    ):
        try:
            target.execute(str(row[0]))
        except sqlite3.OperationalError:
            # Identity indexes are an optimization only.  Some source indexes can
            # refer to generated/collation details unavailable in a reduced test DB.
            pass


def _copy_catalog_meta(source: sqlite3.Connection, target: sqlite3.Connection) -> None:
    target.execute("CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
    if table_exists(source, "catalog_meta"):
        target.executemany(
            "INSERT INTO catalog_meta(key,value) VALUES(?,?)",
            [(str(row[0]), str(row[1])) for row in source.execute("SELECT key,value FROM catalog_meta")],
        )


def _copy_minimal_presentation(source: sqlite3.Connection, target: sqlite3.Connection) -> None:
    target.execute("CREATE TABLE presentation(plugin_id INTEGER PRIMARY KEY, preferred_variant_id INTEGER)")
    if not table_exists(source, "presentation"):
        return
    columns = {str(row[1]) for row in source.execute("PRAGMA table_info(presentation)")}
    if not {"plugin_id", "preferred_variant_id"}.issubset(columns):
        return
    target.executemany(
        "INSERT INTO presentation(plugin_id,preferred_variant_id) VALUES(?,?)",
        source.execute("SELECT plugin_id,preferred_variant_id FROM presentation"),
    )


def prepare_work_database(source_database: Path, work_database: Path, *, reset: bool = False) -> dict[str, Any]:
    """Create/reuse the small mutable Sigmascope database.

    Only catalog identity is cloned from the enormous v1 source.  Security tables are
    created fresh by sigmascope.ensure_schema(), so local Sigmascope runs don't copy the
    historical symbol/call corpus and don't mutate the parity baseline.
    """
    source_database = source_database.resolve()
    work_database = work_database.resolve()
    if source_database == work_database:
        raise RuntimeError("the local Sigmascope work database must not be the v1 source database")
    signature = source_signature(source_database)
    marker = json.dumps(signature, sort_keys=True, separators=(",", ":"))

    if reset and work_database.exists():
        work_database.unlink()
    if work_database.exists():
        with closing(sqlite3.connect(work_database)) as db:
            if not table_exists(db, "catalog_meta"):
                raise RuntimeError(f"existing work database is not an Omega local Sigmascope DB: {work_database}")
            row = db.execute("SELECT value FROM catalog_meta WHERE key='local_security_test_source'").fetchone()
            if row is None or str(row[0]) != marker:
                raise RuntimeError(
                    "existing local Sigmascope database belongs to a different v1 source revision; "
                    "use --reset or choose another --work-dir"
                )
        return signature

    work_database.parent.mkdir(parents=True, exist_ok=True)
    temp = work_database.with_suffix(work_database.suffix + ".tmp")
    temp.unlink(missing_ok=True)
    with closing(open_ro(source_database)) as source, closing(sqlite3.connect(temp)) as target:
        target.execute("PRAGMA foreign_keys=OFF")
        _copy_catalog_meta(source, target)
        for table in IDENTITY_TABLES:
            _copy_table_schema_and_rows(source, target, table)
        _copy_minimal_presentation(source, target)
        _copy_identity_indexes(source, target)
        target.execute(
            "INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('local_security_test_source',?)", (marker,)
        )
        target.execute(
            "INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('local_security_test_created_at_utc',?)", (utc_now(),)
        )
        sigmascope.ensure_schema(target)
        target.commit()
    os.replace(temp, work_database)
    return signature


def _active_downloadable_count(database: Path, internal_names: str) -> int:
    names = {item.strip().casefold() for item in internal_names.split(",") if item.strip()}
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT p.internal_name
                 FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id
                WHERE v.active=1 AND p.active=1
                  AND (COALESCE(v.download_link_install,'')<>'' OR COALESCE(v.download_link_testing,'')<>'')"""
        )
        return sum(1 for row in rows if not names or str(row[0] or "").casefold() in names)


def _sigmascope_args(
    work_database: Path,
    work_dir: Path,
    *,
    max_scans: int,
    rescan_after_hours: int,
    internal_names: str,
    advisories: Path,
    source_overrides: Path,
    skip_source: bool,
    report_name: str,
    max_batch_seconds: int,
) -> SimpleNamespace:
    return SimpleNamespace(
        database=str(work_database),
        bundle="",
        descriptor="",
        report=str(work_dir / report_name),
        ledger=str(work_dir / "security-scan-ledger.json"),
        max_scans=max_scans,
        max_batch_seconds=max_batch_seconds,
        rescan_after_hours=rescan_after_hours,
        internal_names=internal_names,
        advisories=str(advisories) if advisories.exists() else "",
        source_overrides=str(source_overrides) if source_overrides.exists() else "",
        skip_source=skip_source,
        skip_revision_update=True,
    )


def _count_scalar(db: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> int:
    row = db.execute(sql, tuple(params)).fetchone()
    return int(row[0] or 0) if row is not None else 0


def summarize(database: Path) -> dict[str, Any]:
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        placeholders = ",".join("?" for _ in NUGET_KINDS)
        nuget_pairs = _count_scalar(db, f"""
            SELECT COUNT(*) FROM (
              SELECT lower(TRIM(d.name)),COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))
                FROM plugin_security_dependencies d
                JOIN plugin_security_current c ON c.scan_id=d.scan_id
               WHERE c.status='complete' AND lower(d.kind) IN ({placeholders})
                 AND TRIM(d.name)<>''
                 AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))<>''
               GROUP BY 1,2
            )
        """, NUGET_KINDS)
        report_rows = db.execute(
            "SELECT report_json FROM plugin_security_current WHERE status='complete'"
        ).fetchall()
        scope_modes: dict[str, int] = {}
        source_errors = 0
        deps_json_hits = 0
        for row in report_rows:
            try:
                report = json.loads(str(row[0] or "{}"))
            except json.JSONDecodeError:
                continue
            source = report.get("source") if isinstance(report.get("source"), dict) else {}
            scope = source.get("scope") if isinstance(source.get("scope"), dict) else {}
            mode = str(scope.get("mode") or "unknown")
            scope_modes[mode] = scope_modes.get(mode, 0) + 1
            if str(source.get("error") or ""):
                source_errors += 1
            intel = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
            for dep in intel.get("dependencies") or []:
                if isinstance(dep, dict) and str(dep.get("path") or "").casefold().endswith(".deps.json"):
                    deps_json_hits += 1
        return {
            "schema": SCHEMA,
            "generatedAtUtc": utc_now(),
            "currentScans": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_current"),
            "completeScans": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_current WHERE status='complete'"),
            "failedCurrent": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_current WHERE status<>'complete'"),
            "sourceAvailable": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_current WHERE status='complete' AND source_available=1"),
            "sourceErrors": source_errors,
            "sourceScopeModes": scope_modes,
            "dependencyRows": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_dependencies"),
            "nugetPackageVersionPairs": nuget_pairs,
            "depsJsonDependencyObservations": deps_json_hits,
            "ipcProviders": _count_scalar(db, """
                SELECT COUNT(*) FROM plugin_security_ipc_endpoints e
                JOIN plugin_security_current c ON c.scan_id=e.scan_id
                WHERE c.status='complete' AND e.role='provider' AND TRIM(e.channel)<>''
            """),
            "ipcConsumers": _count_scalar(db, """
                SELECT COUNT(*) FROM plugin_security_ipc_endpoints e
                JOIN plugin_security_current c ON c.scan_id=e.scan_id
                WHERE c.status='complete' AND e.role='consumer' AND TRIM(e.channel)<>''
            """),
            "ipcRegistryRows": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_ipc_registry"),
            "advisoryMatches": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_dependency_advisory_matches"),
            "dependencyComponents": _count_scalar(db, "SELECT COUNT(*) FROM plugin_security_dependency_components"),
        }


def run_local_scan(args: argparse.Namespace) -> dict[str, Any]:
    if args.database:
        source_database = args.database.expanduser().resolve()
    elif args.evidence:
        source_database = infer_database_from_migration_state(args.evidence.expanduser().resolve())
    else:
        raise RuntimeError("provide --database or --evidence")
    if not source_database.is_file():
        raise FileNotFoundError(source_database)

    work_dir = args.work_dir.expanduser().resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    work_database = work_dir / "omega-security-local-test.sqlite"
    signature = prepare_work_database(source_database, work_database, reset=args.reset)

    # Sigmascope currently reads GITHUB_TOKEN only.  Respect the common GH_TOKEN
    # spelling for local operator convenience without ever printing either value.
    if not os.environ.get("GITHUB_TOKEN") and os.environ.get("GH_TOKEN"):
        os.environ["GITHUB_TOKEN"] = os.environ["GH_TOKEN"]
    if not args.skip_source and not os.environ.get("GITHUB_TOKEN"):
        print(
            "WARNING: source examination is enabled without GITHUB_TOKEN/GH_TOKEN; "
            "GitHub anonymous API limits may stop a larger run.",
            file=sys.stderr,
        )

    overrides = args.source_overrides.expanduser().resolve()
    advisories = work_dir / "public-advisories.json"
    total_eligible = _active_downloadable_count(work_database, args.internal_names)
    max_scans = total_eligible if args.all else max(0, args.max_scans)
    if max_scans <= 0:
        raise RuntimeError("no scans requested; use --max-scans N or --all")

    first_args = _sigmascope_args(
        work_database,
        work_dir,
        max_scans=max_scans,
        rescan_after_hours=0 if args.force_rescan else args.rescan_after_hours,
        internal_names=args.internal_names,
        advisories=advisories,
        source_overrides=overrides,
        skip_source=args.skip_source,
        report_name="sigmascope-report.json",
        max_batch_seconds=args.max_batch_seconds,
    )
    print(
        f"Local Sigmascope run: source={source_database.name}, eligible={total_eligible}, "
        f"requested={max_scans}, sourceScan={not args.skip_source}",
        flush=True,
    )
    scan_report = sigmascope.run(first_args)

    advisory_report: dict[str, Any]
    if args.skip_osv:
        advisory_report = {
            "schema": "omega.public-advisories.v1",
            "generatedAtUtc": utc_now(),
            "source": "OSV",
            "ecosystem": "NuGet",
            "queriedPackages": 0,
            "matchedPackages": 0,
            "advisories": [],
            "skipped": True,
        }
        write_json(advisories, advisory_report)
    else:
        print("Collecting OSV advisories for NuGet versions observed by the fresh local scans...", flush=True)
        advisory_report = collect_public_advisories.collect(
            work_database, advisories, timeout=args.osv_timeout, max_packages=args.max_osv_packages
        )

    # Run Sigmascope's deterministic graph/advisory projection without downloading
    # any plugin again.  This refreshes dependency components, IPC registry and OSV
    # matches from the freshly collected evidence.
    refresh_args = _sigmascope_args(
        work_database,
        work_dir,
        max_scans=0,
        rescan_after_hours=args.rescan_after_hours,
        internal_names=args.internal_names,
        advisories=advisories,
        source_overrides=overrides,
        skip_source=True,
        report_name="sigmascope-projection-refresh-report.json",
        max_batch_seconds=0,
    )
    projection_report = sigmascope.run(refresh_args)
    database_summary = summarize(work_database)

    v2_report: dict[str, Any] | None = None
    v2_output = args.v2_output.expanduser().resolve() if args.v2_output else (work_dir / "security-evidence-v2-test")
    if not args.no_v2:
        print(f"Exporting fresh local Sigmascope database to Security Evidence v2: {v2_output}", flush=True)
        index = migrate(work_database, v2_output, reset=True)
        parity = validate(work_database, v2_output, quick=args.quick_validation)
        write_json(v2_output / "validation-report.json", parity)
        v2_report = {
            "path": str(v2_output),
            "indexSha256": sha256_file(v2_output / "index.json"),
            "counts": index.get("counts") or {},
            "validation": parity,
        }
        if not parity.get("ok"):
            raise RuntimeError("fresh local Security Evidence v2 export failed parity validation")

    result = {
        "schema": SCHEMA,
        "generatedAtUtc": utc_now(),
        "sourceDatabase": str(source_database),
        "sourceSignature": signature,
        "workDatabase": str(work_database),
        "eligibleVariants": total_eligible,
        "scan": scan_report,
        "advisories": {
            "queriedPackages": int(advisory_report.get("queriedPackages") or 0),
            "matchedPackages": int(advisory_report.get("matchedPackages") or 0),
            "generatedAtUtc": str(advisory_report.get("generatedAtUtc") or ""),
            "skipped": bool(advisory_report.get("skipped")),
        },
        "projection": projection_report,
        "summary": database_summary,
        "v2": v2_report,
    }
    write_json(work_dir / "local-sigmascope-test-report.json", result)
    return result


def self_test() -> None:
    import tempfile
    from unittest import mock

    # Verify the Sigmascope-only fix that matters for real packaged plugins: exact
    # NuGet versions are recovered from a runtime .deps.json without source code.
    intel = sigmascope.empty_dependency_intelligence("artifact")
    deps = {
        "runtimeTarget": {"name": ".NETCoreApp,Version=v9.0/win-x64"},
        "libraries": {
            "FixturePlugin/1.0.0": {"type": "project", "serviceable": False},
            "Newtonsoft.Json/13.0.3": {"type": "package", "serviceable": True},
            "Microsoft.Extensions.Http/9.0.0": {"type": "package", "serviceable": True},
        },
    }
    sigmascope.scan_dependency_json("FixturePlugin.deps.json", json.dumps(deps), intel)
    sigmascope.finalize_intelligence(intel)
    pairs = {
        (str(item.get("kind")), str(item.get("name")), str(item.get("resolvedVersion")))
        for item in intel.get("dependencies") or []
    }
    assert ("nuget-resolved", "Newtonsoft.Json", "13.0.3") in pairs
    assert ("nuget-resolved", "Microsoft.Extensions.Http", "9.0.0") in pairs
    assert not any(item[1] == "FixturePlugin" for item in pairs)

    # Exercise reduced identity DB construction without copying security history.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        source_path = root / "source.sqlite"
        with closing(sqlite3.connect(source_path)) as db:
            db.executescript("""
                CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                INSERT INTO catalog_meta VALUES('security_revision','sec-test');
                INSERT INTO catalog_meta VALUES('evidence_revision','ev-test');
                CREATE TABLE sources(source_id INTEGER PRIMARY KEY,name TEXT,url TEXT,source_repo_url TEXT);
                CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT,name TEXT,author TEXT,active INTEGER);
                CREATE TABLE plugin_variants(
                  variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,source_id INTEGER,name TEXT,author TEXT,
                  assembly_version TEXT,testing_assembly_version TEXT,download_link_install TEXT,download_link_testing TEXT,
                  repo_url TEXT,active INTEGER
                );
                CREATE TABLE presentation(plugin_id INTEGER PRIMARY KEY,preferred_variant_id INTEGER);
                INSERT INTO sources VALUES(1,'Fixture','https://example.invalid/repo.json','');
                INSERT INTO plugins VALUES(1,'FixturePlugin','Fixture Plugin','Tester',1);
                INSERT INTO plugin_variants VALUES(1,1,1,'Fixture Plugin','Tester','1.0.0','','https://example.invalid/plugin.zip','','https://github.com/example/fixture',1);
                INSERT INTO presentation VALUES(1,1);
            """)
            db.commit()
        work = root / "work.sqlite"
        prepare_work_database(source_path, work)
        with closing(sqlite3.connect(work)) as db:
            assert db.execute("SELECT COUNT(*) FROM plugin_variants").fetchone()[0] == 1
            assert table_exists(db, "plugin_security_current")
            assert db.execute("SELECT COUNT(*) FROM plugin_security_current").fetchone()[0] == 0
        with mock.patch.object(sigmascope, "scan_row"):
            # Import/argument path smoke test only; network scanning is intentionally
            # not part of the deterministic local self-test.
            assert _active_downloadable_count(work, "FixturePlugin") == 1
    print("Omega local Sigmascope / Security Evidence v2 self-test passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Locally scan Omega plugins into a disposable fresh Security Evidence v2 test dataset"
    )
    parser.add_argument("--database", type=Path, help="v1 SQLite baseline; kept read-only")
    parser.add_argument("--evidence", type=Path, help="migrated v2 baseline; source DB is inferred from its migration state")
    parser.add_argument("--work-dir", type=Path, default=Path("omega-security-local-test"))
    parser.add_argument("--v2-output", type=Path, help="fresh v2 test output; defaults below --work-dir")
    parser.add_argument("--max-scans", type=int, default=DEFAULT_MAX_SCANS)
    parser.add_argument("--all", action="store_true", help="scan every active downloadable variant matching --internal-names")
    parser.add_argument("--internal-names", default="", help="optional comma-separated InternalName allow-list")
    parser.add_argument("--rescan-after-hours", type=int, default=168)
    parser.add_argument("--force-rescan", action="store_true", help="re-scan matching variants even when the local test copy is fresh")
    parser.add_argument("--max-batch-seconds", type=int, default=0, help="0 means no local wall-clock scan budget")
    parser.add_argument("--source-overrides", type=Path, default=TOOLS_DIR.parent / "sources" / "source-overrides.json")
    parser.add_argument("--skip-source", action="store_true", help="artifact-only test scan")
    parser.add_argument("--skip-osv", action="store_true", help="do not contact OSV after scanning")
    parser.add_argument("--osv-timeout", type=float, default=20.0)
    parser.add_argument("--max-osv-packages", type=int, default=2000)
    parser.add_argument("--no-v2", action="store_true", help="keep only the small working SQLite test database")
    parser.add_argument("--quick-validation", action="store_true", help="skip the largest three v2 forensic digest comparisons")
    parser.add_argument("--reset", action="store_true", help="recreate the reduced local test database before scanning")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.database and not args.evidence:
        parser.error("one of --database or --evidence is required")
    try:
        result = run_local_scan(args)
    except (OSError, RuntimeError, sqlite3.Error, ValueError) as exc:
        print(f"Local security test scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    summary = result["summary"]
    print("\nLocal security test scan complete.")
    print(f"  Complete scans:          {summary['completeScans']}")
    print(f"  Source available:        {summary['sourceAvailable']}")
    print(f"  NuGet package versions:  {summary['nugetPackageVersionPairs']}")
    print(f"  .deps.json observations: {summary['depsJsonDependencyObservations']}")
    print(f"  IPC providers:           {summary['ipcProviders']}")
    print(f"  IPC consumers:           {summary['ipcConsumers']}")
    print(f"  OSV packages queried:    {result['advisories']['queriedPackages']}")
    print(f"  OSV packages matched:    {result['advisories']['matchedPackages']}")
    print(f"  Advisory matches:        {summary['advisoryMatches']}")
    if result.get("v2"):
        print(f"  Fresh v2 test dataset:   {result['v2']['path']}")
        print(f"  v2 parity:               {'PASS' if result['v2']['validation']['ok'] else 'FAIL'}")
    print(f"  Full report:             {Path(result['workDatabase']).parent / 'local-sigmascope-test-report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
