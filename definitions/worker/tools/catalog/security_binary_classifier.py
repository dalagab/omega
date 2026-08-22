"""Bounded static binary classifier for SigmaScope artifact payloads.

The classifier never loads or executes binaries. It identifies PE/CLR, ELF and Mach-O
containers and extracts a deliberately bounded amount of structural metadata. Native PE
imports are parsed from the import table so existing SigmaScope rule/permission logic can
reason about concrete imported APIs instead of treating every non-CLR DLL as an opaque
blob.

Version 2 adds PE security/loader characteristics, certificate-table presence, bounded
section entropy and writable+executable section identification. These are structural
signals only: certificate-table presence is *not* treated as signature verification and
entropy is never treated as a malware verdict.
"""
from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Any

SCHEMA = "omega.sigmascope.binary-classification.v2"
MAX_PE_SECTIONS = 96
MAX_PE_IMPORT_LIBRARIES = 256
MAX_PE_IMPORT_FUNCTIONS = 4096
MAX_STRING = 512
MAX_SECTION_ENTROPY_BYTES = 2 * 1024 * 1024

PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "arm64",
}
PE_SUBSYSTEMS = {
    0: "unknown",
    1: "native",
    2: "windows-gui",
    3: "windows-console",
    7: "posix-console",
    9: "windows-ce-gui",
    10: "efi-application",
    11: "efi-boot-service-driver",
    12: "efi-runtime-driver",
    13: "efi-rom",
    14: "xbox",
    16: "windows-boot-application",
}
PE_DLL_CHARACTERISTICS = {
    "highEntropyVa": 0x0020,
    "dynamicBase": 0x0040,
    "forceIntegrity": 0x0080,
    "nxCompat": 0x0100,
    "noSeh": 0x0400,
    "appContainer": 0x1000,
    "guardCf": 0x4000,
    "terminalServerAware": 0x8000,
}
ELF_MACHINES = {3: "x86", 40: "arm", 62: "x86-64", 183: "arm64", 243: "riscv"}
MACH_FILE_TYPES = {1: "object", 2: "executable", 6: "library", 8: "bundle"}


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("binary structure exceeds available bytes")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("binary structure exceeds available bytes")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("binary structure exceeds available bytes")
    return struct.unpack_from("<Q", data, offset)[0]


def _cstring(data: bytes, offset: int, *, limit: int = MAX_STRING) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", "replace")


def _rva_to_offset(rva: int, sections: list[dict[str, int]]) -> int | None:
    if rva <= 0:
        return None
    for section in sections:
        start = int(section["virtualAddress"])
        size = max(int(section["virtualSize"]), int(section["rawSize"]))
        if start <= rva < start + size:
            delta = rva - start
            if delta >= int(section["rawSize"]):
                return None
            return int(section["rawPointer"]) + delta
    return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    value = 0.0
    for count in counts:
        if not count:
            continue
        probability = count / total
        value -= probability * math.log2(probability)
    return round(value, 3)


def _pe_imports(data: bytes, rva: int, sections: list[dict[str, int]], pointer_size: int) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    descriptor = _rva_to_offset(rva, sections)
    if descriptor is None:
        return imports
    function_count = 0
    ordinal_mask = 0x8000000000000000 if pointer_size == 8 else 0x80000000
    value_mask = 0x7FFFFFFFFFFFFFFF if pointer_size == 8 else 0x7FFFFFFF
    for _ in range(MAX_PE_IMPORT_LIBRARIES):
        if descriptor + 20 > len(data):
            break
        original_first_thunk = _u32(data, descriptor)
        name_rva = _u32(data, descriptor + 12)
        first_thunk = _u32(data, descriptor + 16)
        if not any(data[descriptor:descriptor + 20]):
            break
        descriptor += 20
        name_offset = _rva_to_offset(name_rva, sections)
        library = _cstring(data, name_offset) if name_offset is not None else ""
        if not library:
            continue
        functions: list[str] = []
        thunk_rva = original_first_thunk or first_thunk
        thunk = _rva_to_offset(thunk_rva, sections)
        while thunk is not None and thunk + pointer_size <= len(data) and function_count < MAX_PE_IMPORT_FUNCTIONS:
            value = _u64(data, thunk) if pointer_size == 8 else _u32(data, thunk)
            if value == 0:
                break
            thunk += pointer_size
            function_count += 1
            if value & ordinal_mask:
                functions.append(f"#{value & 0xFFFF}")
                continue
            name_pointer = _rva_to_offset(int(value & value_mask), sections)
            if name_pointer is None or name_pointer + 2 > len(data):
                continue
            name = _cstring(data, name_pointer + 2)
            if name:
                functions.append(name)
        imports.append({"library": library, "functions": functions})
        if function_count >= MAX_PE_IMPORT_FUNCTIONS:
            break
    return imports


def _classify_pe(data: bytes, path: str) -> dict[str, Any] | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    machine = _u16(data, pe_offset + 4)
    section_count = _u16(data, pe_offset + 6)
    timestamp = _u32(data, pe_offset + 8)
    characteristics = _u16(data, pe_offset + 22)
    optional_size = _u16(data, pe_offset + 20)
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 72:
        raise ValueError("truncated PE optional header")
    magic = _u16(data, optional)
    if magic == 0x10B:
        pointer_size, directory_offset = 4, optional + 96
        bitness = 32
        image_base = _u32(data, optional + 28)
    elif magic == 0x20B:
        pointer_size, directory_offset = 8, optional + 112
        bitness = 64
        image_base = _u64(data, optional + 24)
    else:
        raise ValueError(f"unsupported PE optional-header magic 0x{magic:04x}")
    entry_point_rva = _u32(data, optional + 16)
    size_of_image = _u32(data, optional + 56)
    checksum = _u32(data, optional + 64)
    subsystem = _u16(data, optional + 68)
    dll_characteristics = _u16(data, optional + 70)
    section_table = optional + optional_size
    sections: list[dict[str, Any]] = []
    writable_executable_sections: list[str] = []
    high_entropy_sections: list[str] = []
    for index in range(min(section_count, MAX_PE_SECTIONS)):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise ValueError("truncated PE section table")
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = _u32(data, offset + 8)
        virtual_address = _u32(data, offset + 12)
        raw_size = _u32(data, offset + 16)
        raw_pointer = _u32(data, offset + 20)
        section_characteristics = _u32(data, offset + 36)
        executable = bool(section_characteristics & 0x20000000)
        readable = bool(section_characteristics & 0x40000000)
        writable = bool(section_characteristics & 0x80000000)
        sample = b""
        if raw_size and raw_pointer < len(data):
            available = min(raw_size, MAX_SECTION_ENTROPY_BYTES, len(data) - raw_pointer)
            if available > 0:
                sample = data[raw_pointer:raw_pointer + available]
        entropy = _entropy(sample)
        if executable and writable:
            writable_executable_sections.append(name or f"section-{index}")
        if raw_size >= 1024 and entropy >= 7.2:
            high_entropy_sections.append(name or f"section-{index}")
        sections.append({
            "name": name,
            "virtualSize": virtual_size,
            "virtualAddress": virtual_address,
            "rawSize": raw_size,
            "rawPointer": raw_pointer,
            "characteristics": f"0x{section_characteristics:08x}",
            "executable": executable,
            "readable": readable,
            "writable": writable,
            "entropy": entropy,
            "entropyBytesExamined": len(sample),
        })
    import_rva = _u32(data, directory_offset + 8) if directory_offset + 16 <= optional + optional_size else 0
    security_offset = _u32(data, directory_offset + 4 * 8) if directory_offset + 5 * 8 <= optional + optional_size else 0
    security_size = _u32(data, directory_offset + 4 * 8 + 4) if directory_offset + 5 * 8 <= optional + optional_size else 0
    cli_rva = _u32(data, directory_offset + 14 * 8) if directory_offset + 15 * 8 <= optional + optional_size else 0
    cli_size = _u32(data, directory_offset + 14 * 8 + 4) if directory_offset + 15 * 8 <= optional + optional_size else 0
    is_dll = bool(characteristics & 0x2000)
    imports = _pe_imports(data, import_rva, sections, pointer_size) if import_rva else []
    mitigations = {name: bool(dll_characteristics & flag) for name, flag in PE_DLL_CHARACTERISTICS.items()}
    certificate_in_bounds = bool(security_offset and security_size and security_offset < len(data) and security_offset + security_size <= len(data))
    return {
        "schema": SCHEMA,
        "path": path,
        "format": "pe",
        "kind": "managed-pe" if cli_rva and cli_size else "native-pe",
        "role": "library" if is_dll else "executable",
        "architecture": PE_MACHINES.get(machine, f"machine-0x{machine:04x}"),
        "bitness": bitness,
        "machine": f"0x{machine:04x}",
        "subsystem": PE_SUBSYSTEMS.get(subsystem, f"subsystem-{subsystem}"),
        "characteristics": f"0x{characteristics:04x}",
        "dllCharacteristics": f"0x{dll_characteristics:04x}",
        "coffTimestamp": timestamp,
        "entryPointRva": entry_point_rva,
        "imageBase": image_base,
        "sizeOfImage": size_of_image,
        "checksum": checksum,
        "managedCliHeader": bool(cli_rva and cli_size),
        "mitigations": mitigations,
        "certificateTable": {
            "present": bool(security_offset and security_size),
            "fileOffset": security_offset,
            "size": security_size,
            "inBounds": certificate_in_bounds,
            "verified": False,
            "note": "PE certificate-table presence only; Authenticode trust is not verified by this parser.",
        },
        "sections": sections,
        "sectionCount": section_count,
        "sectionsTruncated": section_count > MAX_PE_SECTIONS,
        "writableExecutableSections": writable_executable_sections,
        "highEntropySections": high_entropy_sections,
        "imports": imports,
        "importLibraryCount": len(imports),
        "importFunctionCount": sum(len(item["functions"]) for item in imports),
        "importsTruncated": len(imports) >= MAX_PE_IMPORT_LIBRARIES or sum(len(item["functions"]) for item in imports) >= MAX_PE_IMPORT_FUNCTIONS,
    }


def _classify_elf(data: bytes, path: str) -> dict[str, Any] | None:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    elf_class = data[4]
    endian_code = data[5]
    if elf_class not in {1, 2} or endian_code not in {1, 2}:
        raise ValueError("unsupported ELF class/endianness")
    endian = "<" if endian_code == 1 else ">"
    e_type = struct.unpack_from(endian + "H", data, 16)[0]
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    role = {1: "object", 2: "executable", 3: "library", 4: "core"}.get(e_type, f"type-{e_type}")
    return {
        "schema": SCHEMA, "path": path,
        "format": "elf", "kind": "native-elf", "role": role,
        "architecture": ELF_MACHINES.get(machine, f"machine-{machine}"),
        "bitness": 32 if elf_class == 1 else 64,
        "endianness": "little" if endian_code == 1 else "big",
        "machine": machine,
    }


def _classify_macho(data: bytes, path: str) -> dict[str, Any] | None:
    if len(data) < 16:
        return None
    raw = data[:4]
    magics = {
        b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64),
    }
    config = magics.get(raw)
    if config is None:
        if raw in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
            return {"schema": SCHEMA, "path": path, "format": "mach-o-fat", "kind": "native-mach-o", "role": "universal", "architecture": "multiple", "bitness": 0}
        return None
    endian, bitness = config
    cpu_type = struct.unpack_from(endian + "I", data, 4)[0]
    file_type = struct.unpack_from(endian + "I", data, 12)[0]
    return {
        "schema": SCHEMA, "path": path,
        "format": "mach-o", "kind": "native-mach-o", "role": MACH_FILE_TYPES.get(file_type, f"type-{file_type}"),
        "architecture": f"cpu-0x{cpu_type:08x}", "bitness": bitness,
    }


def classify_binary(data: bytes, path: str = "artifact", *, sha256: str = "") -> dict[str, Any]:
    """Classify one bounded binary sample; malformed recognized formats fail closed."""
    result = _classify_pe(data, path) or _classify_elf(data, path) or _classify_macho(data, path)
    if result is None:
        result = {
            "schema": SCHEMA, "path": path,
            "format": "unknown", "kind": "non-code-or-unknown", "role": "payload",
            "architecture": "", "bitness": 0,
        }
    result["sha256"] = str(sha256 or hashlib.sha256(data).hexdigest()).strip().lower()
    result["bytesExamined"] = len(data)
    result["filename"] = Path(path).name
    return result
