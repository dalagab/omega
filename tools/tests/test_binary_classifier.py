from __future__ import annotations

import io
import struct
import unittest
import zipfile

import common
import security_binary_classifier
import sigmascope


def native_pe(*, dll: bool = True, writable_executable: bool = False, certificate_table: bool = False) -> bytes:
    data = bytearray(0x1000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe:pe + 4] = b"PE\0\0"
    characteristics = 0x0002 | (0x2000 if dll else 0)
    struct.pack_into("<HHIIIHH", data, pe + 4, 0x8664, 1, 0x65A1B2C3, 0, 0, 0xF0, characteristics)
    optional = pe + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<H", data, optional + 68, 3)  # console subsystem
    struct.pack_into("<H", data, optional + 70, 0x0140)
    directories = optional + 112
    struct.pack_into("<II", data, directories + 8, 0x1100, 40)  # import directory
    if certificate_table:
        struct.pack_into("<II", data, directories + 4 * 8, 0x900, 0x40)  # security directory uses file offsets
    section = optional + 0xF0
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x800, 0x1000, 0x800, 0x400)
    struct.pack_into("<I", data, section + 36, 0xE0000040 if writable_executable else 0x40000040)
    # IMAGE_IMPORT_DESCRIPTOR at RVA 0x1100 -> file 0x500.
    struct.pack_into("<IIIII", data, 0x500, 0x1200, 0, 0, 0x1300, 0)
    # OriginalFirstThunk at RVA 0x1200 -> 0x600.
    struct.pack_into("<QQ", data, 0x600, 0x1400, 0)
    data[0x700:0x700 + len(b"kernel32.dll\0")] = b"kernel32.dll\0"
    struct.pack_into("<H", data, 0x800, 0)
    data[0x802:0x802 + len(b"CreateRemoteThread\0")] = b"CreateRemoteThread\0"
    return bytes(data)


class BinaryClassifierTests(unittest.TestCase):
    def test_native_pe_classifies_architecture_role_and_imports(self) -> None:
        payload = native_pe()
        result = security_binary_classifier.classify_binary(payload, "native/helper.dll")
        self.assertEqual("pe", result["format"])
        self.assertEqual("native-pe", result["kind"])
        self.assertEqual("library", result["role"])
        self.assertEqual("x86-64", result["architecture"])
        self.assertEqual(64, result["bitness"])
        self.assertEqual("kernel32.dll", result["imports"][0]["library"])
        self.assertIn("CreateRemoteThread", result["imports"][0]["functions"])

    def test_native_pe_imports_feed_sigmascope_static_evidence(self) -> None:
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("native/helper.dll", native_pe())
        hits: dict[str, list[str]] = {}
        from collections import defaultdict
        rule_hits = defaultdict(list)
        intel = sigmascope.empty_dependency_intelligence("artifact")
        package = sigmascope.scan_archive(archive_bytes.getvalue(), rule_hits, intel)
        sigmascope.finalize_intelligence(intel)
        self.assertEqual(2, package["binaryClassificationContractVersion"])
        native = next(item for item in package["binaryClassifications"] if item["path"] == "native/helper.dll")
        self.assertEqual("native-pe", native["kind"])
        self.assertTrue(any(item.get("library") == "kernel32.dll" and item.get("entryPoint") == "CreateRemoteThread" for item in intel["nativeImports"]))
        self.assertIn("memory.remote-thread", rule_hits)
        self.assertTrue(any(item.get("permissionId") == "native.interop" and item.get("confidence") == "VeryHigh" for item in intel["permissionCandidates"]))

    def test_native_pe_records_structural_security_characteristics_without_overclaiming(self) -> None:
        result = security_binary_classifier.classify_binary(
            native_pe(writable_executable=True, certificate_table=True), "native/helper.dll"
        )
        self.assertEqual("omega.sigmascope.binary-classification.v2", result["schema"])
        self.assertTrue(result["mitigations"]["dynamicBase"])
        self.assertTrue(result["mitigations"]["nxCompat"])
        self.assertTrue(result["certificateTable"]["present"])
        self.assertTrue(result["certificateTable"]["inBounds"])
        self.assertFalse(result["certificateTable"]["verified"])
        self.assertIn(".rdata", result["writableExecutableSections"])
        self.assertGreaterEqual(result["sections"][0]["entropy"], 0.0)

    def test_writable_executable_pe_section_becomes_bounded_caution_evidence(self) -> None:
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("native/helper.dll", native_pe(writable_executable=True))
        from collections import defaultdict
        rule_hits = defaultdict(list)
        intel = sigmascope.empty_dependency_intelligence("artifact")
        package = sigmascope.scan_archive(archive_bytes.getvalue(), rule_hits, intel)
        findings, capabilities = sigmascope.finding_payload(rule_hits, package)
        self.assertTrue(any(item["ruleId"] == "native.pe.writable-executable-section" for item in findings))
        self.assertIn("Writable+executable native section", capabilities)

    def test_elf_and_macho_are_distinguished_from_non_code(self) -> None:
        elf = bytearray(64)
        elf[:4] = b"\x7fELF"
        elf[4] = 2
        elf[5] = 1
        struct.pack_into("<H", elf, 16, 3)
        struct.pack_into("<H", elf, 18, 62)
        result = security_binary_classifier.classify_binary(bytes(elf), "libfixture.so")
        self.assertEqual(("elf", "native-elf", "library", "x86-64"), (result["format"], result["kind"], result["role"], result["architecture"]))

        macho = bytearray(32)
        macho[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", macho, 4, 0x01000007)
        struct.pack_into("<I", macho, 12, 6)
        result = security_binary_classifier.classify_binary(bytes(macho), "libfixture.dylib")
        self.assertEqual(("mach-o", "native-mach-o", "library", 64), (result["format"], result["kind"], result["role"], result["bitness"]))

        result = security_binary_classifier.classify_binary(b"plain text", "README.txt")
        self.assertEqual("non-code-or-unknown", result["kind"])


if __name__ == "__main__":
    unittest.main()
