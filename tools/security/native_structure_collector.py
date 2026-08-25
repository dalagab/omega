#!/usr/bin/env python3
"""Bounded ELF/Mach-O structural observation collector for SigmaScope.

The collector downloads one exact artifact already bound in Security Evidence v2, verifies
its SHA-256, safely walks a ZIP (or standalone native binary), and parses ELF/Mach-O
metadata without loading or executing the binary. It emits neutral structural observations
through ``omega.collector-result.v1``; it never produces a trust or malware verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any, Mapping
import zipfile

SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SCRIPT_DIR.parent / "catalog"
for item in (SCRIPT_DIR, CATALOG_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import analysis_broker  # noqa: E402
import collector_contracts  # noqa: E402
import collector_results  # noqa: E402
import security_evidence_v2  # noqa: E402
import sigmascope  # noqa: E402

COLLECTOR_ID = "omega.collector.sigmascope.native-structure"
TARGET_SCHEMA = "omega.native-structure.analysis-target.v1"
ELF_OBSERVATION = "elfBinaryStructure"
MACHO_OBSERVATION = "machOBinaryStructure"
SUPPORTED_OBSERVATIONS = {ELF_OBSERVATION, MACHO_OBSERVATION}
MAX_NATIVE_FILES = 2_048
MAX_NATIVE_FILE_BYTES = 128 * 1024 * 1024
MAX_PROGRAM_HEADERS = 512
MAX_SECTION_HEADERS = 4_096
MAX_DYNAMIC_ENTRIES = 8_192
MAX_SYMBOLS = 20_000
MAX_LOAD_COMMANDS = 4_096
MAX_STRING_ITEMS = 4_096
MAX_TEXT = 8_192

ELF_MACHINES = {3: "x86", 40: "arm", 62: "x86-64", 183: "arm64", 243: "riscv"}
MACH_CPU = {
    7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "arm64",
    18: "powerpc", 0x01000012: "powerpc64",
}
MACH_FILE_TYPES = {1: "object", 2: "executable", 3: "fvmlib", 4: "core", 5: "preload", 6: "library", 7: "dylinker", 8: "bundle", 9: "dylib-stub", 10: "dsym", 11: "kext"}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _find_variant(evidence_root: Path, variant_id: int) -> dict[str, Any]:
    matches = []
    for _entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        if int(payload.get("variantId") or 0) == variant_id:
            matches.append(payload)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one current Evidence-v2 variant {variant_id}, found {len(matches)}")
    return matches[0]


def resolve_request(evidence_root: Path, request_value: Mapping[str, Any], *, work_item_id: str = "") -> dict[str, Any]:
    request = analysis_broker.compile_request(request_value)
    observation = str(request.get("observation") or "")
    if observation not in SUPPORTED_OBSERVATIONS:
        raise ValueError(f"native-structure collector does not provide {observation!r}")
    if COLLECTOR_ID not in collector_contracts.providers_for(observation, include_planned=False):
        raise ValueError(f"native-structure collector is not active for {observation}")
    subject = request.get("subject") if isinstance(request.get("subject"), Mapping) else {}
    variant_id = int(subject.get("variantId") or 0)
    artifact_sha = str(subject.get("artifactSha256") or "").strip().lower()
    if variant_id <= 0 or len(artifact_sha) != 64:
        raise ValueError(f"{observation} requests require exact subject.variantId + subject.artifactSha256")
    payload = _find_variant(evidence_root.resolve(), variant_id)
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    current_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()
    if current_sha != artifact_sha:
        raise ValueError(f"request artifact does not match current Evidence-v2 variant: request={artifact_sha}, evidence={current_sha}")
    report = current.get("report_json") if isinstance(current.get("report_json"), Mapping) else {}
    manifest = report.get("manifestObservation") if isinstance(report.get("manifestObservation"), Mapping) else {}
    artifact_url = str(manifest.get("downloadUrl") or report.get("artifactUrl") or "").strip()
    if not artifact_url:
        raise ValueError("current Evidence-v2 variant does not retain an artifact download URL")
    sigmascope.validate_public_https_url(artifact_url)
    return {
        "schema": TARGET_SCHEMA,
        "request": request,
        "workItemId": str(work_item_id or "")[:256],
        "observation": observation,
        "variantId": variant_id,
        "artifactSha256": artifact_sha,
        "artifactUrl": artifact_url,
    }


def _bounded_append(values: list[str], value: str) -> None:
    text = str(value or "").replace("\x00", "").strip()
    if text and text not in values and len(values) < MAX_STRING_ITEMS:
        values.append(text[:MAX_TEXT])


def _read_cstring(data: bytes, offset: int, limit: int = MAX_TEXT) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("utf-8", "replace")


def _elf_unpack(data: bytes, endian: str, bits: int, offset: int, fmt32: str, fmt64: str) -> tuple[Any, ...]:
    fmt = endian + (fmt64 if bits == 64 else fmt32)
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("ELF structure exceeds available bytes")
    return struct.unpack_from(fmt, data, offset)


def parse_elf(data: bytes, logical_path: str, artifact_sha256: str) -> dict[str, Any]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF binary")
    elf_class, endian_code = data[4], data[5]
    if elf_class not in {1, 2} or endian_code not in {1, 2}:
        raise ValueError("unsupported ELF class/endianness")
    bits = 32 if elf_class == 1 else 64
    endian = "<" if endian_code == 1 else ">"
    if bits == 64:
        header_fmt = endian + "HHIQQQIHHHHHH"
    else:
        header_fmt = endian + "HHIIIIIHHHHHH"
    header_size = struct.calcsize(header_fmt)
    if 16 + header_size > len(data):
        raise ValueError("truncated ELF header")
    (e_type, machine, _version, entry, phoff, shoff, _flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(header_fmt, data, 16)
    role = {1: "object", 2: "executable", 3: "shared-object", 4: "core"}.get(e_type, f"type-{e_type}")

    program_headers: list[dict[str, int]] = []
    interpreter = ""
    has_relro = False
    executable_stack = False
    writable_executable_segments = 0
    dynamic_offset = dynamic_size = 0
    for index in range(min(phnum, MAX_PROGRAM_HEADERS)):
        off = phoff + index * phentsize
        if phentsize <= 0 or off + phentsize > len(data):
            raise ValueError("truncated ELF program-header table")
        if bits == 64:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = _elf_unpack(data, endian, bits, off, "", "IIQQQQQQ")
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, _p_align = _elf_unpack(data, endian, bits, off, "IIIIIIII", "")
        program_headers.append({"type": int(p_type), "offset": int(p_offset), "vaddr": int(p_vaddr), "filesz": int(p_filesz), "memsz": int(p_memsz), "flags": int(p_flags)})
        if p_type == 3 and p_offset < len(data):  # PT_INTERP
            interpreter = _read_cstring(data, int(p_offset), min(MAX_TEXT, int(p_filesz) or MAX_TEXT))
        elif p_type == 2:  # PT_DYNAMIC
            dynamic_offset, dynamic_size = int(p_offset), int(p_filesz)
        elif p_type == 0x6474E552:  # PT_GNU_RELRO
            has_relro = True
        elif p_type == 0x6474E551:  # PT_GNU_STACK
            executable_stack = bool(int(p_flags) & 0x1)
        if (int(p_flags) & 0x3) == 0x3:  # PF_X + PF_W
            writable_executable_segments += 1

    def vaddr_to_offset(address: int) -> int | None:
        for ph in program_headers:
            if ph["type"] != 1:  # PT_LOAD
                continue
            start, size = ph["vaddr"], max(ph["filesz"], ph["memsz"])
            if start <= address < start + size:
                delta = address - start
                if delta >= ph["filesz"]:
                    return None
                return ph["offset"] + delta
        return None

    needed_offsets: list[int] = []
    rpath_offset = runpath_offset = None
    strtab_va = 0
    strsz = 0
    bind_now = False
    if dynamic_offset and dynamic_size:
        entry_size = 16 if bits == 64 else 8
        count = min(dynamic_size // entry_size, MAX_DYNAMIC_ENTRIES)
        for index in range(int(count)):
            off = dynamic_offset + index * entry_size
            if off + entry_size > len(data):
                break
            tag, value = _elf_unpack(data, endian, bits, off, "iI", "qQ")
            tag, value = int(tag), int(value)
            if tag == 0:
                break
            if tag == 1:
                needed_offsets.append(value)
            elif tag == 5:
                strtab_va = value
            elif tag == 10:
                strsz = value
            elif tag == 15:
                rpath_offset = value
            elif tag == 29:
                runpath_offset = value
            elif tag == 24:
                bind_now = True
            elif tag == 30 and value & 0x8:  # DF_BIND_NOW
                bind_now = True
            elif tag == 0x6FFFFFFB and value & 0x1:  # DF_1_NOW
                bind_now = True
    strtab_offset = vaddr_to_offset(strtab_va) if strtab_va else None
    needed: list[str] = []
    rpaths: list[str] = []
    runpaths: list[str] = []
    if strtab_offset is not None:
        for off in needed_offsets:
            _bounded_append(needed, _read_cstring(data, strtab_offset + off))
        if rpath_offset is not None:
            for item in _read_cstring(data, strtab_offset + int(rpath_offset)).split(":"):
                _bounded_append(rpaths, item)
        if runpath_offset is not None:
            for item in _read_cstring(data, strtab_offset + int(runpath_offset)).split(":"):
                _bounded_append(runpaths, item)

    # Section/symbol metadata is optional in stripped binaries. Parse only bounded tables.
    section_names = b""
    sections: list[dict[str, int]] = []
    if shoff and shentsize and shnum and shnum <= MAX_SECTION_HEADERS:
        raw_sections: list[tuple[int, int, int, int, int, int, int, int, int, int]] = []
        for index in range(shnum):
            off = shoff + index * shentsize
            values = _elf_unpack(data, endian, bits, off, "IIIIIIIIII", "IIQQQQIIQQ")
            raw_sections.append(tuple(int(v) for v in values))
        if 0 <= shstrndx < len(raw_sections):
            sh = raw_sections[shstrndx]
            sh_offset, sh_size = sh[4], sh[5]
            if sh_offset + sh_size <= len(data):
                section_names = data[sh_offset:sh_offset + sh_size]
        for sh in raw_sections:
            name_off, sh_type, _flags, _addr, sh_offset, sh_size, link, _info, _align, entsize = sh
            name = _read_cstring(section_names, name_off) if section_names else ""
            sections.append({"name": name, "type": sh_type, "offset": sh_offset, "size": sh_size, "link": link, "entsize": entsize})

    imported_symbols: list[str] = []
    exported_symbols: list[str] = []
    dynamic_symbol_count = 0
    for section in sections:
        if section["type"] != 11 or not section["entsize"]:  # SHT_DYNSYM
            continue
        if not (0 <= section["link"] < len(sections)):
            continue
        strings = sections[section["link"]]
        if strings["offset"] + strings["size"] > len(data):
            continue
        string_data = data[strings["offset"]:strings["offset"] + strings["size"]]
        count = min(section["size"] // section["entsize"], MAX_SYMBOLS)
        dynamic_symbol_count += int(count)
        for index in range(int(count)):
            off = section["offset"] + index * section["entsize"]
            if bits == 64:
                name_off, info, _other, shndx, _value, _size = _elf_unpack(data, endian, bits, off, "", "IBBHQQ")
            else:
                name_off, _value, _size, info, _other, shndx = _elf_unpack(data, endian, bits, off, "IIIBBH", "")
            name = _read_cstring(string_data, int(name_off))
            if not name:
                continue
            binding = int(info) >> 4
            if int(shndx) == 0:
                _bounded_append(imported_symbols, name)
            elif binding in {1, 2}:
                _bounded_append(exported_symbols, name)

    section_name_set = {section["name"] for section in sections if section["name"]}
    stripped = bool(sections) and ".symtab" not in section_name_set
    pie = bool(e_type == 3 and interpreter)
    row = {
        "artifactSha256": artifact_sha256,
        "path": logical_path,
        "fileSha256": hashlib.sha256(data).hexdigest(),
        "architecture": ELF_MACHINES.get(machine, f"machine-{machine}"),
        "bitness": bits,
        "endianness": "little" if endian == "<" else "big",
        "role": role,
        "entryPoint": int(entry),
        "interpreter": interpreter,
        "neededLibraries": needed,
        "rpaths": rpaths,
        "runpaths": runpaths,
        "pie": pie,
        "relro": has_relro,
        "bindNow": bind_now,
        "executableStack": executable_stack,
        "writableExecutableSegmentCount": writable_executable_segments,
        "programHeaderCount": int(phnum),
        "sectionHeaderCount": int(shnum),
        "truncated": bool(phnum > MAX_PROGRAM_HEADERS or shnum > MAX_SECTION_HEADERS or len(needed_offsets) >= MAX_DYNAMIC_ENTRIES or dynamic_symbol_count >= MAX_SYMBOLS),
    }
    if sections:
        row.update({
            "stripped": stripped,
            "dynamicSymbolCount": dynamic_symbol_count,
            "importedSymbols": imported_symbols,
            "exportedSymbols": exported_symbols,
        })
    return collector_results.validate_observation_row(ELF_OBSERVATION, row)


def _mach_version(value: int) -> str:
    return f"{(value >> 16) & 0xffff}.{(value >> 8) & 0xff}.{value & 0xff}"


def _mach_thin(data: bytes, logical_path: str, artifact_sha256: str, *, slice_label: str = "") -> dict[str, Any]:
    magics = {
        b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64),
    }
    config = magics.get(data[:4])
    if config is None:
        raise ValueError("not a thin Mach-O binary")
    endian, bits = config
    header_fmt = endian + ("IIIIIII" if bits == 32 else "IIIIIIII")
    header_size = struct.calcsize(header_fmt)
    if header_size > len(data):
        raise ValueError("truncated Mach-O header")
    values = struct.unpack_from(header_fmt, data, 0)
    _magic, cpu_type, _cpu_subtype, file_type, ncmds, sizeofcmds, flags = values[:7]
    header_bytes = 28 if bits == 32 else 32
    if ncmds > MAX_LOAD_COMMANDS or header_bytes + sizeofcmds > len(data):
        raise ValueError("Mach-O load command table exceeds bounded parser limits")
    dylibs: list[str] = []
    rpaths: list[str] = []
    uuid = ""
    code_signature_present = False
    code_signature_size = 0
    entry_offset = 0
    min_os = ""
    sdk_version = ""
    encrypted = False
    writable_executable_segments = 0
    offset = header_bytes
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise ValueError("truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            raise ValueError("invalid Mach-O load command size")
        base_cmd = cmd & 0x7FFFFFFF
        if base_cmd in {0xC, 0x18, 0x1F, 0x20, 0x23}:  # LC_*_DYLIB
            if cmdsize >= 24:
                name_off = struct.unpack_from(endian + "I", data, offset + 8)[0]
                if 0 < name_off < cmdsize:
                    _bounded_append(dylibs, _read_cstring(data, offset + name_off, cmdsize - name_off))
        elif base_cmd == 0x1C:  # LC_RPATH
            if cmdsize >= 12:
                path_off = struct.unpack_from(endian + "I", data, offset + 8)[0]
                if 0 < path_off < cmdsize:
                    _bounded_append(rpaths, _read_cstring(data, offset + path_off, cmdsize - path_off))
        elif base_cmd == 0x1B and cmdsize >= 24:  # LC_UUID
            uuid = data[offset + 8:offset + 24].hex()
        elif base_cmd == 0x1D and cmdsize >= 16:  # LC_CODE_SIGNATURE
            _dataoff, datasize = struct.unpack_from(endian + "II", data, offset + 8)
            code_signature_present = bool(datasize)
            code_signature_size = int(datasize)
        elif base_cmd == 0x28 and cmdsize >= 24:  # LC_MAIN
            entry_offset = int(struct.unpack_from(endian + "Q", data, offset + 8)[0])
        elif base_cmd in {0x24, 0x25, 0x2F, 0x30} and cmdsize >= 16:  # *_VERSION_MIN_*
            version, sdk = struct.unpack_from(endian + "II", data, offset + 8)
            min_os, sdk_version = _mach_version(version), _mach_version(sdk)
        elif base_cmd == 0x32 and cmdsize >= 24:  # LC_BUILD_VERSION
            _platform, minos, sdk, _ntools = struct.unpack_from(endian + "IIII", data, offset + 8)
            min_os, sdk_version = _mach_version(minos), _mach_version(sdk)
        elif base_cmd in {0x21, 0x2C} and cmdsize >= 20:  # LC_ENCRYPTION_INFO(_64)
            cryptid = struct.unpack_from(endian + "I", data, offset + 16)[0]
            encrypted = encrypted or bool(cryptid)
        elif base_cmd in {0x1, 0x19}:  # LC_SEGMENT(_64)
            if base_cmd == 0x19 and cmdsize >= 72:
                maxprot, initprot = struct.unpack_from(endian + "ii", data, offset + 56)
            elif base_cmd == 0x1 and cmdsize >= 56:
                maxprot, initprot = struct.unpack_from(endian + "ii", data, offset + 40)
            else:
                maxprot = initprot = 0
            # Report the concrete initial mapping, not the broader maximum protection ceiling.
            if (int(initprot) & 0x6) == 0x6:  # VM_PROT_WRITE + VM_PROT_EXECUTE
                writable_executable_segments += 1
        offset += cmdsize
    row = {
        "artifactSha256": artifact_sha256,
        "path": logical_path,
        "fileSha256": hashlib.sha256(data).hexdigest(),
        "format": "mach-o",
        "architecture": MACH_CPU.get(cpu_type, f"cpu-0x{cpu_type:08x}"),
        "bitness": bits,
        "role": MACH_FILE_TYPES.get(file_type, f"type-{file_type}"),
        "slice": slice_label,
        "dylibs": dylibs,
        "rpaths": rpaths,
        "codeSignaturePresent": code_signature_present,
        "codeSignatureSize": code_signature_size,
        "uuid": uuid,
        "entryOffset": entry_offset,
        "minOs": min_os,
        "sdkVersion": sdk_version,
        "encrypted": encrypted,
        "writableExecutableSegmentCount": writable_executable_segments,
        "loadCommandCount": int(ncmds),
        "flags": f"0x{int(flags):08x}",
        "truncated": False,
    }
    return collector_results.validate_observation_row(MACHO_OBSERVATION, {k: v for k, v in row.items() if v != ""})


def parse_macho(data: bytes, logical_path: str, artifact_sha256: str) -> list[dict[str, Any]]:
    if len(data) < 4:
        raise ValueError("not a Mach-O binary")
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return [_mach_thin(data, logical_path, artifact_sha256)]
    fat_magics = {
        b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\fe\xca": ("<", True),
    }
    config = fat_magics.get(data[:4])
    if config is None or len(data) < 8:
        raise ValueError("not a Mach-O/fat binary")
    endian, fat64 = config
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if count > 64:
        raise ValueError("Mach-O fat binary contains too many slices")
    entry_size = 32 if fat64 else 20
    rows: list[dict[str, Any]] = []
    for index in range(count):
        off = 8 + index * entry_size
        if off + entry_size > len(data):
            raise ValueError("truncated Mach-O fat architecture table")
        if fat64:
            cpu, _sub, slice_offset, slice_size, _align, _reserved = struct.unpack_from(endian + "IIQQII", data, off)
        else:
            cpu, _sub, slice_offset, slice_size, _align = struct.unpack_from(endian + "IIIII", data, off)
        if slice_size <= 0 or slice_offset + slice_size > len(data):
            raise ValueError("Mach-O fat slice exceeds available bytes")
        label = MACH_CPU.get(cpu, f"cpu-0x{cpu:08x}")
        rows.append(_mach_thin(data[slice_offset:slice_offset + slice_size], logical_path, artifact_sha256, slice_label=label))
    return rows


def _archive_native_members(data: bytes) -> list[tuple[str, bytes]]:
    def recognized(prefix: bytes) -> bool:
        return prefix.startswith(b"\x7fELF") or prefix[:4] in {
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
        }
    if not data.startswith(b"PK"):
        if not recognized(data[:4]):
            return []
        if len(data) > MAX_NATIVE_FILE_BYTES:
            raise ValueError(f"standalone native binary exceeds {MAX_NATIVE_FILE_BYTES} byte limit")
        return [("artifact", data)]
    results: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > sigmascope.MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Archive has {len(infos)} entries; limit is {sigmascope.MAX_ARCHIVE_ENTRIES}")
        seen: set[str] = set()
        total = 0
        for info in infos:
            if not sigmascope.safe_member_name(info.filename):
                raise ValueError(f"Unsafe archive path: {info.filename}")
            normalized = sigmascope.normalized_archive_member_name(info.filename)
            if normalized in seen:
                raise ValueError(f"Archive contains a duplicate normalized path: {info.filename}")
            seen.add(normalized)
            if sigmascope.archive_member_is_symlink(info):
                raise ValueError(f"Archive contains a symbolic-link entry: {info.filename}")
            if info.flag_bits & 0x1:
                raise ValueError(f"Encrypted archive entries are not inspected: {info.filename}")
            total += max(0, info.file_size)
        if total > sigmascope.MAX_ARCHIVE_UNCOMPRESSED:
            raise ValueError("Archive exceeds uncompressed size limit")
        for info in infos:
            if info.is_dir() or info.file_size <= 0:
                continue
            if info.compress_size > 0 and info.file_size / info.compress_size > 500:
                raise ValueError(f"Suspicious compression ratio: {info.filename}")
            with archive.open(info) as stream:
                prefix = stream.read(4)
                if not recognized(prefix):
                    continue
                if info.file_size > MAX_NATIVE_FILE_BYTES:
                    raise ValueError(f"native member exceeds {MAX_NATIVE_FILE_BYTES} byte limit: {info.filename}")
                raw = prefix + stream.read(MAX_NATIVE_FILE_BYTES + 1)
                if len(raw) != info.file_size:
                    raise ValueError(f"native member size changed while reading: {info.filename}")
            results.append((info.filename.replace("\\", "/"), raw))
            if len(results) > MAX_NATIVE_FILES:
                raise ValueError(f"Archive contains more than {MAX_NATIVE_FILES} native binaries")
    return results


def collect(target: Mapping[str, Any], *, github_token: str = "") -> dict[str, Any]:
    if str(target.get("schema") or "") != TARGET_SCHEMA:
        raise ValueError(f"target schema must be {TARGET_SCHEMA}")
    request = target.get("request") if isinstance(target.get("request"), Mapping) else {}
    observation = str(target.get("observation") or request.get("observation") or "")
    if observation not in SUPPORTED_OBSERVATIONS:
        raise ValueError(f"unsupported native structure observation: {observation!r}")
    expected_sha = str(target.get("artifactSha256") or "").strip().lower()
    artifact, _final_url = sigmascope.request_bytes(str(target.get("artifactUrl") or ""), sigmascope.MAX_ARTIFACT_BYTES, token=github_token)
    actual_sha = hashlib.sha256(artifact).hexdigest()
    if actual_sha != expected_sha:
        raise RuntimeError(f"downloaded artifact SHA-256 mismatch: expected={expected_sha}, actual={actual_sha}")
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for logical_path, raw in _archive_native_members(artifact):
        try:
            if observation == ELF_OBSERVATION and raw.startswith(b"\x7fELF"):
                rows.append(parse_elf(raw, logical_path, expected_sha))
            elif observation == MACHO_OBSERVATION and raw[:4] in {
                b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\fe\xca", b"\xca\xfe\xba\bf", b"\xbf\xba\fe\xca",
            }:
                rows.extend(parse_macho(raw, logical_path, expected_sha))
        except Exception as exc:
            errors.append(f"{logical_path}: {type(exc).__name__}: {exc}"[:2000])
    return collector_results.build_result(
        request,
        collector_id=COLLECTOR_ID,
        collections={observation: rows},
        work_item_id=str(target.get("workItemId") or ""),
        status="partial" if errors else "complete",
        errors=errors,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect bounded ELF/Mach-O structural observations without executing native files")
    sub = parser.add_subparsers(dest="command", required=True)
    p_resolve = sub.add_parser("resolve")
    p_resolve.add_argument("--evidence-root", type=Path, required=True)
    p_resolve.add_argument("--request", type=Path, required=True)
    p_resolve.add_argument("--work-item-id", default="")
    p_resolve.add_argument("--output", type=Path, required=True)
    p_collect = sub.add_parser("collect")
    p_collect.add_argument("--target", type=Path, required=True)
    p_collect.add_argument("--output", type=Path, required=True)
    p_collect.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    args = parser.parse_args()
    if args.command == "resolve":
        result = resolve_request(args.evidence_root, _load(args.request), work_item_id=args.work_item_id)
    else:
        result = collect(_load(args.target), github_token=args.github_token)
    _write(args.output, result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
