#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("omega_build_catalog", HERE / "build_catalog.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def candidate(*, blob="blob-good"):
    return MOD.SourceCandidate(
        id="test",
        name="Test source",
        url="https://example.invalid/repo.json",
        description="test",
        origin="github-discovery",
        repository="example/repo",
        path="repo.json",
        git_blob_sha=blob,
        git_blob_fresh=True,
    )


def main():
    sample = '''[
      // comment
      {"Name":"A","InternalName":"A","DalamudApiLevel":"15",},
    ]'''
    parsed = MOD.tolerant_loads(sample)
    plugins = MOD.extract_plugin_array(parsed)
    check(len(plugins) == 1, "tolerant parser")
    check(MOD.normalize_url("https://example.invalid/repo.json/") == "https://example.invalid/repo.json", "url normalization")
    check(len(MOD.sha256_text("x")) == 64, "sha256")

    try:
        MOD.extract_plugin_array({"Name": "single manifest", "InternalName": "NotARepo"})
    except ValueError:
        pass
    else:
        raise AssertionError("single plugin manifest must not become a repository")

    bad_doc, bad = MOD.load_known_bad(Path("/definitely/not/present.json"))
    check(bad_doc["schemaVersion"] == 1 and not bad, "empty known-bad default")

    now = "2026-08-13T00:00:00Z"
    bad_map = {}
    added = MOD.merge_bad_entry(bad_map, "ab" * 32, candidate(blob="blob-bad"), "not a repository", now)
    check(added and len(bad_map) == 1, "new deterministic bad hash is recorded")
    check(next(iter(bad_map.values()))["gitBlobSha"] == "blob-bad", "GitHub blob SHA is retained")
    check(not MOD.merge_bad_entry(bad_map, "ab" * 32, candidate(blob="blob-bad"), "not a repository", now), "known bad hash is updated, not duplicated")

    old_fetch = MOD.fetch
    MOD.fetch = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("fetch should not run for known bad blob"))
    try:
        result = MOD.evaluate_source(candidate(blob="blob-bad"), 1.0, 1024, {}, {"blob-bad"})
        check(result["status"] == "known-bad-git-blob", "known-bad-git-blob pre-download classification")
    finally:
        MOD.fetch = old_fetch

    stale_blob_source = candidate(blob="blob-bad")
    stale_blob_source = MOD.SourceCandidate(
        stale_blob_source.id, stale_blob_source.name, stale_blob_source.url, stale_blob_source.description,
        origin=stale_blob_source.origin, repository=stale_blob_source.repository, path=stale_blob_source.path,
        git_blob_sha=stale_blob_source.git_blob_sha, git_blob_fresh=False)
    MOD.fetch = lambda *args, **kwargs: {
        "status": "fetched",
        "manifest": '[{"Name":"Changed","InternalName":"Changed","DalamudApiLevel":15}]',
        "sha256": MOD.sha256_text('[{"Name":"Changed","InternalName":"Changed","DalamudApiLevel":15}]'),
        "etag": "",
        "lastModified": "",
    }
    try:
        reconsidered = MOD.evaluate_source(stale_blob_source, 1.0, 4096, {}, {"blob-bad"})
        check(reconsidered["status"] == "valid", "stale discovery blob must not pre-skip changed HEAD content")
    finally:
        MOD.fetch = old_fetch

    invalid = b'{"Name":"single manifest","InternalName":"NotARepo"}'
    invalid_hash = MOD.sha256_bytes(invalid)
    MOD.fetch = lambda *args, **kwargs: {"status": "fetched", "manifest": invalid.decode(), "sha256": invalid_hash, "etag": "", "lastModified": ""}
    try:
        result = MOD.evaluate_source(candidate(blob="blob-new"), 1.0, 1024, {}, set())
        check(result["status"] == "new-bad-hash", "new-bad-hash deterministic invalid classification")
    finally:
        MOD.fetch = old_fetch

    # Previous release bundles are validated locally and reused for conditional requests.
    with tempfile.TemporaryDirectory(prefix="omega-catalog-test-") as temp_dir:
        seed_path = Path(temp_dir) / "omega-catalog-db.zip"
        seed_manifest = '[{"Name":"Seeded","InternalName":"Seeded","DalamudApiLevel":15}]'
        seed_record = {
            "SchemaVersion": 1,
            "Url": "https://example.invalid/seeded.json",
            "ETag": '"seed-etag"',
            "LastModified": "Wed, 13 Aug 2026 10:00:00 GMT",
            "ContentSha256": MOD.sha256_text(seed_manifest),
            "FetchedAtUtc": "2026-08-12T00:00:00Z",
            "CheckedAtUtc": "2026-08-12T00:00:00Z",
            "ManifestJson": seed_manifest,
        }
        with zipfile.ZipFile(seed_path, "w") as zf:
            zf.writestr("catalog-db/seed.json", json.dumps(seed_record))
        seeds = MOD.load_seed_bundle(seed_path)
        check(len(seeds) == 1, "seed bundle round-trip")
        previous = seeds["https://example.invalid/seeded.json"]

        MOD.fetch = lambda *args, **kwargs: {"status": "not-modified", "etag": '"seed-etag"', "lastModified": seed_record["LastModified"]}
        try:
            unchanged = MOD.evaluate_source(
                MOD.SourceCandidate("seed", "Seed", seed_record["Url"], "seed"),
                1.0,
                4096,
                {},
                set(),
                previous,
                "2026-08-13T00:00:00Z",
            )
            check(unchanged["status"] == "not-modified", "seed drives conditional not-modified reuse")
            check(unchanged["record"]["CheckedAtUtc"] == "2026-08-13T00:00:00Z", "304 advances checked timestamp")
        finally:
            MOD.fetch = old_fetch

    valid = b'[{"Name":"Valid","InternalName":"Valid","DalamudApiLevel":15}]'
    valid_hash = MOD.sha256_bytes(valid)
    MOD.fetch = lambda *args, **kwargs: {"status": "fetched", "manifest": valid.decode(), "sha256": valid_hash, "etag": '"etag"', "lastModified": ""}
    try:
        result = MOD.evaluate_source(candidate(blob="blob-changed"), 1.0, 4096, {invalid_hash: {"reason": "old content"}}, set())
        check(result["status"] == "valid" and result["plugins"] == 1, "changed content is reconsidered and accepted")
    finally:
        MOD.fetch = old_fetch

    print("Omega catalog pipeline self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
