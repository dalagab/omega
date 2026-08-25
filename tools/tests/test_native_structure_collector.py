from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import common  # noqa: F401
import collector_evidence_adapter
import collector_evidence_audit
import collector_results
import definitions_snapshot
import native_structure_collector
import observation_inventory
import security_evidence_v2
import srl
import srl_evidence_replay
from test_rule_reprojection import RuleReprojectionTests


def elf64_fixture() -> bytes:
    size = 0x380
    data = bytearray(size)
    data[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    phoff = 64
    phentsize = 56
    phnum = 5
    header = struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0x401000, phoff, 0, 0, 64, phentsize, phnum, 64, 0, 0)
    data[16:16+len(header)] = header
    ph = []
    ph.append(struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, size, size, 0x1000))
    ph.append(struct.pack("<IIQQQQQQ", 3, 4, 0x200, 0x400200, 0, 28, 28, 1))
    ph.append(struct.pack("<IIQQQQQQ", 2, 6, 0x220, 0x400220, 0, 16*7, 16*7, 8))
    ph.append(struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16))
    ph.append(struct.pack("<IIQQQQQQ", 0x6474E552, 4, 0x340, 0x400340, 0, 0x20, 0x20, 1))
    for i, item in enumerate(ph):
        data[phoff+i*phentsize:phoff+(i+1)*phentsize] = item
    data[0x200:0x200+28] = b"/lib64/ld-linux-x86-64.so.2\0"
    strings = b"\0libc.so.6\0$ORIGIN/lib\0"
    data[0x300:0x300+len(strings)] = strings
    dyn = [
        (5, 0x400300), (10, len(strings)), (1, 1), (29, 11), (24, 0), (0x6FFFFFFB, 1), (0, 0),
    ]
    for i, (tag, value) in enumerate(dyn):
        data[0x220+i*16:0x220+(i+1)*16] = struct.pack("<qQ", tag, value)
    return bytes(data)


def macho64_fixture() -> bytes:
    commands = []
    name = b"/usr/lib/libSystem.B.dylib\0"
    dylib_size = (24 + len(name) + 7) & ~7
    cmd = bytearray(dylib_size)
    struct.pack_into("<IIIIII", cmd, 0, 0xC, dylib_size, 24, 0, 0, 0)
    cmd[24:24+len(name)] = name
    commands.append(bytes(cmd))
    rpath = b"@loader_path/Frameworks\0"
    rpath_size = (12 + len(rpath) + 7) & ~7
    cmd = bytearray(rpath_size)
    struct.pack_into("<III", cmd, 0, 0x8000001C, rpath_size, 12)
    cmd[12:12+len(rpath)] = rpath
    commands.append(bytes(cmd))
    commands.append(struct.pack("<IIII", 0x1D, 16, 0x200, 128))
    commands.append(struct.pack("<IIQQ", 0x80000028, 24, 0x1234, 0))
    seg = bytearray(72)
    struct.pack_into("<II", seg, 0, 0x19, 72)
    seg[8:24] = b"__TEXT" + bytes(10)
    struct.pack_into("<QQQQ", seg, 24, 0x100000000, 0x1000, 0, 0x1000)
    struct.pack_into("<iiII", seg, 56, 7, 5, 0, 0)
    commands.append(bytes(seg))
    body = b"".join(commands)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, len(commands), len(body), 0x200000, 0)
    return header + body + bytes(0x300)


class NativeStructureCollectorTests(unittest.TestCase):
    def request(self, observation: str) -> dict:
        return {
            "observation": observation,
            "subject": {"type": "variant", "variantId": 1, "artifactSha256": "a" * 64},
            "reason": "Collect exact native structure evidence.",
            "requestedBy": {"componentId": "omega.analysis-broker", "policyId": "fixture.native"},
        }

    def test_elf_parser_retains_dependency_loader_and_hardening_structure(self) -> None:
        raw = elf64_fixture()
        row = native_structure_collector.parse_elf(raw, "lib/native.so", "a" * 64)
        self.assertEqual("x86-64", row["architecture"])
        self.assertEqual(64, row["bitness"])
        self.assertEqual(["libc.so.6"], row["neededLibraries"])
        self.assertEqual(["$ORIGIN/lib"], row["runpaths"])
        self.assertTrue(row["pie"])
        self.assertTrue(row["relro"])
        self.assertTrue(row["bindNow"])
        self.assertFalse(row["executableStack"])
        self.assertEqual(0, row["writableExecutableSegmentCount"])

    def test_macho_parser_retains_dylib_rpath_signature_presence_and_segment_protection(self) -> None:
        raw = macho64_fixture()
        rows = native_structure_collector.parse_macho(raw, "native/helper.dylib", "a" * 64)
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual("x86-64", row["architecture"])
        self.assertIn("/usr/lib/libSystem.B.dylib", row["dylibs"])
        self.assertIn("@loader_path/Frameworks", row["rpaths"])
        self.assertTrue(row["codeSignaturePresent"])
        self.assertEqual(128, row["codeSignatureSize"])
        self.assertEqual(0x1234, row["entryOffset"])
        self.assertEqual(0, row["writableExecutableSegmentCount"])

    def test_native_collector_is_part_of_frozen_worker_bundle(self) -> None:
        files = definitions_snapshot.worker_bundle_files(common.ROOT)
        self.assertIn("tools/security/native_structure_collector.py", files)
        self.assertIn("tools/security/collector_results.py", files)

    def test_generic_result_ingests_to_evidence_inventory_and_srl(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omega-native-structure-") as td:
            root = Path(td)
            helper = RuleReprojectionTests("test_compatible_retained_observations_reproject_without_legacy_findings")
            current = helper.evidence(root)
            row = native_structure_collector.parse_elf(elf64_fixture(), "lib/native.so", "a" * 64)
            result = collector_results.build_result(
                self.request("elfBinaryStructure"), collector_id=native_structure_collector.COLLECTOR_ID,
                collections={"elfBinaryStructure": [row]}, work_item_id="work-native",
                generated_at_utc="2026-08-25T20:00:00Z",
            )
            result_path = root / "result.json"
            result_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            candidate = root / "candidate"
            ingestion = collector_evidence_adapter.ingest(current, candidate, result_path)
            self.assertEqual(["elfBinaryStructure"], ingestion["observations"])
            self.assertTrue(collector_evidence_audit.audit(current, candidate, result_path)["ok"])
            inventory = observation_inventory.build_inventory(candidate, generated_at="2026-08-25T20:01:00Z")
            matches = [item for item in inventory["records"] if item["observation"] == "elfBinaryStructure"]
            self.assertEqual(1, len(matches))
            self.assertEqual(native_structure_collector.COLLECTOR_ID, matches[0]["collectorId"])
            _entry, payload = next(iter(security_evidence_v2.iter_variant_entries(candidate)))
            analysis_path = str((payload.get("analysis") or {}).get("path") or "")
            observations = srl_evidence_replay._load_observations(candidate, analysis_path, ["elfBinaryStructure"], variant_payload=payload)
            ruleset = srl.compile_ruleset({
                "schema": "omega.sigmascope.ruleset.v1",
                "rules": [{
                    "schema": "omega.sigmascope.rule.v1", "id": "fixture.elf.runpath", "kind": "observation", "status": "experimental",
                    "requires": ["elfBinaryStructure"],
                    "selectors": {"runpath": {"collection": "elfBinaryStructure", "where": {"runpaths": {"contains": "$ORIGIN/lib"}}}},
                    "condition": "runpath", "emit": {"fact": "fixture.elf-relative-runpath", "title": "ELF uses relative runpath", "confidence": "high"},
                }],
            })
            evaluation = srl.evaluate_ruleset(ruleset, observations, observation_contract=payload["observations"])
            self.assertIn("fixture.elf-relative-runpath", evaluation["facts"])

    def test_result_contract_is_tamper_detecting(self) -> None:
        row = native_structure_collector.parse_elf(elf64_fixture(), "lib/native.so", "a" * 64)
        result = collector_results.build_result(
            self.request("elfBinaryStructure"), collector_id=native_structure_collector.COLLECTOR_ID,
            collections={"elfBinaryStructure": [row]}, generated_at_utc="2026-08-25T20:00:00Z",
        )
        self.assertEqual("complete", collector_results.validate_result(result)["status"])
        altered = json.loads(json.dumps(result))
        altered["collections"]["elfBinaryStructure"]["rows"][0]["neededLibraries"] = ["evil.so"]
        with self.assertRaisesRegex(ValueError, "does not reproduce"):
            collector_results.validate_result(altered)


if __name__ == "__main__":
    unittest.main()
