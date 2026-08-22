#!/usr/bin/env python3
"""Incrementally enrich an Omega catalog with static plugin evidence using Sigmascope.

Sigmascope treats plugin packages and source archives as hostile input. It never
executes plugin code, never loads managed assemblies, and never extracts plugin
archives into the runner workspace. Results are evidence-based capabilities and
risk indicators, not a claim that a plugin is safe or malicious.

Dependency intelligence is intentionally conservative: imports, declared packages,
Dalamud services, IPC provider/consumer channels, native imports and bundled binaries are recorded as
evidence and mapped to *permission candidates*. Managed PE/.NET metadata and bounded
CIL method bodies are parsed statically to record assembly references, symbols and
compiled call sites. Hard, soft and optional dependency semantics are preserved; a
bounded local reachability graph links lifecycle/callback roots to local method calls.
Current dependency rows are resolved against the Omega catalog and normalized shared
components, with conservative version-compatibility and component-divergence analysis.
Immutable scan lineage captures dependency and permission drift between completed
scans, while source declarations can be compared with compiled-artifact observations
without claiming reproducible source-to-binary verification. Production hardening
includes bounded evidence collections, redirect and ZIP pathological-input guards,
catalog-scale graph/advisory limits, deterministic projection health checks, and an
explicit batch wall-clock budget. A reachable static call path is stronger evidence
than a loose reference, but it still does not prove that a runtime branch actually
executes.
"""
from __future__ import annotations

from contextlib import closing
import argparse
import base64
import copy
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import io
import ipaddress
import json
import os
import posixpath
import re
import socket
import sqlite3
import struct
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from typing import Iterable
from catalog_revisions import read_meta as read_catalog_meta, update_candidate_revisions
from security_endpoint_inventory import endpoint_candidates, endpoint_findings, endpoint_summary
from security_hash_consensus import canonicalize_current_security_by_artifact, propagate_source_provenance_by_artifact, refresh_cross_source_hash_findings
from security_path_access import external_hard_coded_paths
from security_secondary_engines import scan_artifact_bytes as scan_secondary_security_artifact
from security_binary_classifier import classify_binary
from security_component_summary import build_component_summary
from source_resolution import github_repository_url, public_repository_url, source_candidate_records, source_candidates, source_override_key
from public_git_source import MAX_GIT_TREE_ENTRIES, PublicGitSource
from plugin_profile import observe_profile
from capability_registry import legacy_capability_ids, load_registry
from behavior_consistency import refresh_behavior_consistency
from artifact_source_model import (
    MANIFEST_OBSERVATION_SCHEMA, attribution_from_source_result, attribution_key, basis_json, manifest_observation_contract, repository_key, source_revision_key,
)


SIGMASCOPE_NAME = "Sigmascope"
SIGMASCOPE_VERSION = "2.15.0"
# Persisted SQLite columns and v1/v2 JSON contracts retain the historical scanner_version name.
SCANNER_VERSION = SIGMASCOPE_VERSION
ARTIFACT_ANALYSIS_SCHEMA = "omega.sigmascope.artifact-analysis.v1"
SOURCE_ANALYSIS_SCHEMA = "omega.sigmascope.source-analysis.v1"
SIGMASCOPE_LEDGER_SCHEMA = "omega.security-scan-ledger.v1"
SECURITY_LEDGER_SCHEMA = SIGMASCOPE_LEDGER_SCHEMA
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 16_384
MAX_ARCHIVE_UNCOMPRESSED = 512 * 1024 * 1024
MAX_ENTRY_SCAN_BYTES = 16 * 1024 * 1024
MAX_TEXT_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_TEXT_TOTAL = 24 * 1024 * 1024
MAX_MANAGED_METADATA_ROWS = 500_000
MAX_MANAGED_ASSEMBLY_REFS = 2_048
MAX_MANAGED_TYPE_REFS = 10_000
MAX_MANAGED_MEMBER_REFS = 20_000
MAX_MANAGED_PINVOKES = 2_048
MAX_MANAGED_METHOD_BODIES = 30_000
MAX_MANAGED_CALL_SITES = 20_000
MAX_MANAGED_IL_BYTES_PER_METHOD = 1 * 1024 * 1024
MAX_MANAGED_IL_BYTES_TOTAL = 16 * 1024 * 1024
MAX_MANAGED_IL_INSTRUCTIONS_PER_METHOD = 250_000
MAX_MANAGED_SWITCH_TARGETS = 65_536
MAX_MANAGED_REACHABILITY_ROOTS = 512
MAX_MANAGED_REACHABLE_METHODS = 20_000
MAX_MANAGED_REACHABILITY_DEPTH = 64
MAX_DRIFT_EVENTS_PER_SCAN = 4096
MAX_DEPENDENCY_RECORDS_PER_SCAN = 20_000
MAX_IMPORT_RECORDS_PER_SCAN = 20_000
MAX_DALAMUD_SERVICE_RECORDS_PER_SCAN = 4_096
MAX_IPC_RECORDS_PER_SCAN = 4_096
MAX_NATIVE_IMPORT_RECORDS_PER_SCAN = 4_096
MAX_MANAGED_ASSEMBLY_RECORDS_PER_SCAN = 4_096
MAX_MANAGED_SYMBOL_RECORDS_PER_SCAN = 40_000
MAX_MANAGED_CALL_RECORDS_PER_SCAN = 20_000
MAX_MANAGED_REACHABILITY_RECORDS_PER_SCAN = 20_000
MAX_PERMISSION_CANDIDATES_PER_SCAN = 4_096
MAX_SOURCE_FILE_RECORDS_PER_SCAN = 2_048
MAX_NETWORK_ENDPOINT_RECORDS_PER_SCAN = 1_024
MAX_STATIC_PATTERN_MATCH_RECORDS_PER_SCAN = 4_096
MAX_CURRENT_DEPENDENCY_ROWS = 2_000_000
MAX_CURRENT_IPC_ENDPOINT_ROWS = 500_000
MAX_ADVISORIES = 100_000
MAX_ADVISORY_MATCHES = 250_000
DEFAULT_MAX_BATCH_SECONDS = 4_200
MAX_SCAN_REPORT_PLUGINS = 2_000
USER_AGENT = f"Omega-Sigmascope/{SIGMASCOPE_VERSION}"
SEVERITY_RANK = {"none": 0, "informational": 1, "caution": 2, "high": 3, "critical": 4}

INTELLIGENCE_LIST_LIMITS = {
    "dependencies": MAX_DEPENDENCY_RECORDS_PER_SCAN,
    "imports": MAX_IMPORT_RECORDS_PER_SCAN,
    "dalamudServices": MAX_DALAMUD_SERVICE_RECORDS_PER_SCAN,
    "ipcIntegrations": MAX_IPC_RECORDS_PER_SCAN,
    "nativeImports": MAX_NATIVE_IMPORT_RECORDS_PER_SCAN,
    "managedAssemblies": MAX_MANAGED_ASSEMBLY_RECORDS_PER_SCAN,
    "managedSymbols": MAX_MANAGED_SYMBOL_RECORDS_PER_SCAN,
    "managedCallSites": MAX_MANAGED_CALL_RECORDS_PER_SCAN,
    "managedReachability": MAX_MANAGED_REACHABILITY_RECORDS_PER_SCAN,
    "permissionCandidates": MAX_PERMISSION_CANDIDATES_PER_SCAN,
    "sourceFiles": MAX_SOURCE_FILE_RECORDS_PER_SCAN,
    "networkEndpoints": MAX_NETWORK_ENDPOINT_RECORDS_PER_SCAN,
    "staticPatternMatches": MAX_STATIC_PATTERN_MATCH_RECORDS_PER_SCAN,
}

PLATFORM_ASSEMBLY_PREFIXES = ("system.", "microsoft.win32.")
PLATFORM_ASSEMBLY_NAMES = {"mscorlib", "netstandard", "system", "windowsbase", "presentationcore", "presentationframework"}


@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    capability: str
    patterns: tuple[str, ...]


RULES = (
    Rule("network.http", "informational", "network", "Network access", "References HTTP/network client APIs.", "Network access", ("System.Net.Http.HttpClient", "WebRequest", "HttpWebRequest", "DownloadString", "DownloadData", "DownloadFile")),
    Rule("network.socket", "caution", "network", "Raw socket access", "References TCP/UDP/socket APIs that can open arbitrary network connections.", "Raw sockets", ("System.Net.Sockets", "TcpClient", "UdpClient", "Socket.Connect", "SocketAsyncEventArgs")),
    Rule("filesystem.write", "informational", "filesystem", "Filesystem write access", "References APIs commonly used to create, modify, move, or delete files.", "Filesystem write", ("WriteAllText", "WriteAllBytes", "FileStream", "FileMode.Create", "File.Delete", "File.Move", "Directory.CreateDirectory", "Directory.Delete")),
    Rule("filesystem.external-path", "caution", "filesystem", "Hard-coded external file path", "References filesystem APIs together with an absolute path outside known FFXIV and Dalamud locations. Static analysis cannot prove the path is opened at runtime.", "Hard-coded external file access", ()),
    Rule("process.launch", "caution", "process", "Process execution", "References APIs that can launch external programs or shell commands.", "Process execution", ("System.Diagnostics.Process", "Process.Start", "ProcessStartInfo", "CreateProcess", "ShellExecute")),
    Rule("shell.powershell", "high", "process", "Shell or PowerShell invocation", "Contains indicators for invoking command shells or PowerShell.", "Shell/PowerShell", ("powershell.exe", "pwsh.exe", "cmd.exe", "-EncodedCommand", "System.Management.Automation")),
    Rule("registry.access", "caution", "system", "Windows Registry access", "References Windows Registry APIs.", "Registry access", ("Microsoft.Win32.Registry", "RegistryKey", "RegOpenKey", "RegSetValue")),
    Rule("native.pinvoke", "caution", "native", "Unmanaged/native API access", "References P/Invoke or dynamic native library loading.", "Native/PInvoke", ("DllImportAttribute", "System.Runtime.InteropServices.DllImport", "NativeLibrary.Load", "LoadLibrary", "GetProcAddress")),
    Rule("dynamic.assembly", "caution", "dynamic-code", "Dynamic assembly loading", "References APIs that can load code dynamically at runtime.", "Dynamic code loading", ("Assembly.Load", "Assembly.LoadFrom", "Assembly.LoadFile", "AssemblyLoadContext", "Reflection.Emit")),
    Rule("memory.process", "high", "memory", "Cross-process memory access", "References APIs used to open another process or read/write its memory.", "Process memory access", ("OpenProcess", "ReadProcessMemory", "WriteProcessMemory", "VirtualAllocEx", "VirtualProtectEx")),
    Rule("memory.remote-thread", "high", "memory", "Remote thread creation", "References APIs commonly used to start execution in another process.", "Remote thread creation", ("CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC")),
    Rule("game.hooking", "caution", "game-memory", "Game memory/signature hooking", "References Dalamud/game hooking or signature-scanning facilities that can alter behavior inside the game process.", "Game memory/hooks", ("Dalamud.Hooking", "SignatureScanner", "SigScanner", "Hook<", "HookFromAddress", "CreateHook")),
    Rule("local.listener", "caution", "network", "Local server/listener", "References APIs that can listen for inbound local/network connections.", "Local server/listener", ("HttpListener", "TcpListener", "Kestrel", "WebApplication.CreateBuilder")),
    Rule("clipboard", "informational", "privacy", "Clipboard access", "References APIs that can read or modify clipboard contents.", "Clipboard access", ("System.Windows.Forms.Clipboard", "TextCopy.ClipboardService", "SDL_GetClipboardText", "SDL_SetClipboardText")),
    Rule("credential.api", "high", "privacy", "Credential or protected-data access", "References credential-manager, protected-data, or password-vault APIs. This is capability evidence, not proof of credential collection.", "Credential/protected-data access", ("CredentialManager", "PasswordVault", "Windows.Security.Credentials", "ProtectedData.Unprotect", "CryptUnprotectData", "CredRead")),
)

SOURCE_SUFFIXES = {
    ".cs", ".csproj", ".props", ".targets", ".sln", ".json", ".xml",
    ".yml", ".yaml", ".ps1", ".cmd", ".bat", ".config",
}
BINARY_SUFFIXES = {".dll", ".exe", ".so", ".dylib"}
PROJECT_XML_SUFFIXES = {".csproj", ".props", ".targets"}
DEPENDENCY_JSON_NAMES = {"packages.lock.json", "project.assets.json", "global.json"}

DALAMUD_SERVICES = {
    "IAddonLifecycle", "IBuddyList", "IChatGui", "IClientState", "ICommandManager",
    "ICondition", "IContextMenu", "IDataManager", "IDtrBar", "IDutyState",
    "IFateTable", "IFlyTextGui", "IFramework", "IGameConfig", "IGameGui",
    "IGameInteropProvider", "IGameLifecycle", "IGamepadState", "IJobGauges",
    "IKeyState", "INotificationManager", "IObjectTable", "IPartyList", "IPluginLog",
    "ISigScanner", "ITargetManager", "ITextureProvider", "ITitleScreenMenu",
    "IToastGui",
}

# Import/service/dependency evidence can indicate access, but it cannot prove a
# call actually occurs. Keep these as candidates until symbol/call scanning exists.
IMPORT_PERMISSION_MAP = (
    ("System.Net", "network.outbound", "Medium", "Medium", "Network namespaces are imported."),
    ("System.IO", "filesystem.read", "Low", "Low", "Filesystem namespaces are imported."),
    ("System.IO", "filesystem.write", "Medium", "Low", "Filesystem namespaces are imported; write use is not yet proven."),
    ("System.Diagnostics", "process.inspect", "Medium", "Low", "Diagnostics/process namespaces are imported."),
    ("System.Diagnostics", "process.execute", "High", "Low", "Diagnostics/process namespaces are imported; execution is not yet proven."),
    ("System.Runtime.InteropServices", "native.interop", "High", "Medium", "Interop namespaces are imported."),
    ("FFXIVClientStructs", "game.memory.read", "High", "Medium", "FFXIVClientStructs is imported."),
    ("Dalamud.Hooking", "game.memory.read", "High", "Medium", "Dalamud hooking APIs are imported."),
    ("Dalamud.Game.ClientState.Keys", "game.input.read", "Medium", "Medium", "Dalamud key-state APIs are imported."),
    ("Dalamud.Game.Addon", "game.ui.read", "Medium", "Medium", "Dalamud addon APIs are imported."),
)

SERVICE_PERMISSION_MAP = {
    "IClientState": ("game.state.read", "Low", "High"),
    "IDataManager": ("game.state.read", "Low", "High"),
    "IObjectTable": ("game.state.read", "Medium", "High"),
    "ICondition": ("game.state.read", "Low", "High"),
    "ITargetManager": ("game.state.read", "Medium", "High"),
    "IPartyList": ("game.state.read", "Medium", "High"),
    "IBuddyList": ("game.state.read", "Medium", "High"),
    "IKeyState": ("game.input.read", "Medium", "High"),
    "IGameGui": ("game.ui.read", "Medium", "High"),
    "IAddonLifecycle": ("game.ui.read", "Medium", "High"),
    "IChatGui": ("game.chat.read", "Medium", "Medium"),
    "ISigScanner": ("game.memory.read", "High", "High"),
    "IGameInteropProvider": ("game.memory.read", "High", "High"),
}

PACKAGE_PERMISSION_MAP = {
    "ffxivclientstructs": ("game.memory.read", "High", "High", "FFXIVClientStructs package/reference is declared."),
}


@dataclasses.dataclass(frozen=True)
class AutomationCallRule:
    capability_id: str
    label: str
    severity: str
    automation_level: str
    type_patterns: tuple[str, ...] = ()
    member_names: tuple[str, ...] = ()
    native_entries: tuple[str, ...] = ()
    description: str = ""


# These rules intentionally describe *capability evidence*. A matching call site is not proof that
# a branch executes during ordinary play. Reachability from a plugin lifecycle/callback root raises
# confidence because the call is connected to code Omega can statically trace from an entry point.
AUTOMATION_CALL_RULES: tuple[AutomationCallRule, ...] = (
    AutomationCallRule(
        "game.ui.callback", "Game UI callback/control", "caution", "ui-automation",
        ("AtkUnitBase", "Dalamud.Game.Addon", "Dalamud.Utility.Signatures.Callback", "Callback"),
        ("FireCallback", "ReceiveEvent", "SendAction", "Invoke", "Fire"),
        description="Invokes game-addon callback or event mechanisms that can drive game UI state.",
    ),
    AutomationCallRule(
        "game.ui.synthetic_click", "Synthetic game UI interaction", "caution", "ui-automation",
        ("Click", "AddonSelect", "SelectString", "SelectIconString", "SelectYesno"),
        ("Click", "Select", "Invoke", "Fire", "Execute"),
        description="Invokes code associated with synthetic clicks or selection dialogs.",
    ),
    AutomationCallRule(
        "game.character.target", "Character target control", "caution", "character-automation",
        ("ITargetManager", "TargetManager", "TargetSystem"),
        ("set_Target", "set_FocusTarget", "SetTarget", "SetFocusTarget", "Target"),
        description="References a target-setting API rather than only reading the current target.",
    ),
    AutomationCallRule(
        "game.character.execute_action", "Character action execution", "high", "full-gameplay-automation",
        ("ActionManager",),
        ("UseAction", "UseActionLocation", "UseActionOnLocation", "UseActionOnTarget"),
        description="Invokes game action-execution APIs that can perform combat, crafting, gathering, or other character actions.",
    ),
    AutomationCallRule(
        "game.character.interact", "World/NPC interaction control", "caution", "character-automation",
        ("TargetSystem", "GameObject", "Interaction"),
        ("InteractWithObject", "Interact", "Use", "ExecuteInteraction"),
        description="Invokes an interaction mechanism capable of activating an NPC, object, or other world target.",
    ),
    AutomationCallRule(
        "game.character.teleport", "Teleport/travel control", "caution", "character-automation",
        ("Telepo", "Teleport", "AgentTeleport"),
        ("Teleport", "TeleportWithTickets", "ExecuteTeleport", "SelectDestination"),
        description="Invokes teleport or travel-control functionality.",
    ),
    AutomationCallRule(
        "game.character.move", "Character movement control", "high", "full-gameplay-automation",
        ("MoveController", "MovementController", "PlayerMove", "Navmesh", "Navigation"),
        ("Move", "SetMovement", "MoveTo", "Pathfind", "PathfindAndMoveTo", "Stop", "StopMoving"),
        description="Invokes movement or navigation functionality capable of moving the player character.",
    ),
    AutomationCallRule(
        "game.camera.control", "Camera control", "caution", "character-automation",
        ("Camera", "CameraManager"),
        ("set_", "SetCamera", "SetPosition", "SetRotation", "SetYaw", "SetPitch"),
        description="References camera-mutating functionality.",
    ),
    AutomationCallRule(
        "game.ui.inventory_control", "Inventory UI/control", "caution", "ui-automation",
        ("InventoryManager", "AgentInventory", "InventoryItem"),
        ("MoveItemSlot", "DiscardItem", "UseItem", "MoveItem", "Execute", "HandleAction"),
        description="Invokes inventory-mutating or inventory-action functionality.",
    ),
    AutomationCallRule(
        "game.ui.vendor_control", "Vendor/shop automation", "caution", "ui-automation",
        ("Shop", "Vendor", "AgentShop"),
        ("Buy", "Sell", "Purchase", "Execute", "HandleAction"),
        description="Invokes vendor/shop functionality capable of buying or selling items.",
    ),
    AutomationCallRule(
        "game.ui.retainer_control", "Retainer automation", "caution", "ui-automation",
        ("Retainer", "AgentRetainer"),
        ("Entrust", "Withdraw", "Sell", "Execute", "HandleAction", "Select"),
        description="Invokes retainer-management functionality.",
    ),
    AutomationCallRule(
        "input.keyboard.inject", "Keyboard input injection", "high", "full-gameplay-automation",
        native_entries=("SendInput", "keybd_event"),
        description="Calls a native keyboard/input injection API.",
    ),
    AutomationCallRule(
        "input.mouse.inject", "Mouse input injection", "high", "full-gameplay-automation",
        native_entries=("SendInput", "mouse_event"),
        description="Calls a native mouse/input injection API.",
    ),
)


# IPC names are not standardized, so this stays deliberately bounded and explicit. These patterns
# mark known automation-oriented channels as *indirect* capability evidence; they do not claim that
# the provider is installed or that a particular IPC call is exercised at runtime.
IPC_AUTOMATION_HINTS: tuple[tuple[tuple[str, ...], tuple[tuple[str, str, str], ...]], ...] = (
    (("vnavmesh", "navmesh", "navigation"), (("game.character.move", "Character movement via IPC", "full-gameplay-automation"),)),
    (("yesalready", "textadvance", "click"), (("game.ui.synthetic_click", "Game UI automation via IPC", "ui-automation"),)),
    (("autoretainer",), (("game.ui.retainer_control", "Retainer automation via IPC", "ui-automation"),)),
    (("artisan",), (("game.character.execute_action", "Crafting/action automation via IPC", "full-gameplay-automation"),)),
    (("lifestream", "teleport"), (("game.character.teleport", "Teleport/travel control via IPC", "character-automation"),)),
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not path.is_absolute() and ".." not in path.parts and not re.match(r"^[A-Za-z]:", normalized)


def validate_public_https_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS downloads are scanned")
    host = (parsed.hostname or "").strip().lower()
    if not host or host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Artifact URL must use a public Internet host")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError(f"Artifact host could not be resolved: {host}") from exc
    if not addresses:
        raise ValueError(f"Artifact host could not be resolved: {host}")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError(f"Artifact URL resolves to a non-public address: {address}")
    return parsed


class ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validate every redirect before urllib opens the redirected connection."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        validate_public_https_url(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            old_host = (urllib.parse.urlparse(req.full_url).hostname or "").casefold()
            new_host = (urllib.parse.urlparse(newurl).hostname or "").casefold()
            if old_host != new_host:
                redirected.remove_header("Authorization")
                redirected.unredirected_hdrs.pop("Authorization", None)
                redirected.unredirected_hdrs.pop("authorization", None)
        return redirected


def request_bytes(url: str, max_bytes: int, token: str = "") -> tuple[bytes, str]:
    parsed = validate_public_https_url(url)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/octet-stream"}
    if token and parsed.hostname and parsed.hostname.lower() in {"api.github.com", "github.com"}:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(ValidatingRedirectHandler())
    with opener.open(request, timeout=30) as response:
        validate_public_https_url(response.geturl())
        length = response.headers.get("Content-Length")
        if length and int(length) > max_bytes:
            raise ValueError(f"Download exceeds {max_bytes} byte limit")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Download exceeds {max_bytes} byte limit")
        return data, response.geturl()


def decoded_views(data: bytes) -> str:
    chunks: list[str] = []
    ascii_strings = re.findall(rb"[\x20-\x7e]{5,}", data)
    chunks.extend(x.decode("ascii", "ignore") for x in ascii_strings)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){5,}", data)
    chunks.extend(x.decode("utf-16le", "ignore") for x in utf16_strings)
    return "\n".join(chunks)




MANAGED_TYPE_PERMISSION_MAP = (
    ("System.Net.Http.HttpClient", "network.outbound", "Medium", "High", "Managed metadata references HttpClient."),
    ("System.Net.Sockets.", "network.raw", "High", "High", "Managed metadata references raw socket types."),
    ("Microsoft.Win32.Registry", "registry.access", "High", "High", "Managed metadata references Windows Registry types."),
    ("System.Runtime.InteropServices.NativeLibrary", "native.interop", "High", "High", "Managed metadata references dynamic native-library APIs."),
    ("System.Reflection.Assembly", "dynamic.code", "High", "Medium", "Managed metadata references reflection assembly-loading APIs."),
    ("System.Runtime.Loader.AssemblyLoadContext", "dynamic.code", "High", "Medium", "Managed metadata references AssemblyLoadContext."),
    ("Dalamud.Hooking.", "game.memory.read", "High", "High", "Managed metadata references Dalamud hooking types."),
    ("FFXIVClientStructs.", "game.memory.read", "High", "High", "Managed metadata references FFXIVClientStructs types."),
)

MANAGED_MEMBER_PERMISSION_MAP = (
    ("System.Net.Http.HttpClient", None, "network.outbound", "Medium", "High", "Managed metadata contains an HttpClient member reference."),
    ("System.Net.Sockets.", None, "network.raw", "High", "High", "Managed metadata contains a socket member reference."),
    ("System.IO.File", {"WriteAllText", "WriteAllBytes", "AppendAllText", "AppendAllLines", "Delete", "Move", "Copy", "Create"}, "filesystem.write", "Medium", "High", "Managed metadata references a filesystem-mutating File API."),
    ("System.IO.Directory", {"CreateDirectory", "Delete", "Move"}, "filesystem.write", "Medium", "High", "Managed metadata references a filesystem-mutating Directory API."),
    ("System.IO.File", {"ReadAllText", "ReadAllBytes", "ReadAllLines", "OpenRead", "Exists"}, "filesystem.read", "Low", "High", "Managed metadata references a filesystem-read File API."),
    ("System.Diagnostics.Process", {"Start"}, "process.execute", "High", "High", "Managed metadata references Process.Start."),
    ("System.Diagnostics.Process", None, "process.inspect", "Medium", "Medium", "Managed metadata references Process APIs."),
    ("Microsoft.Win32.Registry", None, "registry.access", "High", "High", "Managed metadata references Windows Registry members."),
    ("System.Runtime.InteropServices.NativeLibrary", None, "native.interop", "High", "High", "Managed metadata references NativeLibrary members."),
    ("System.Reflection.Assembly", {"Load", "LoadFrom", "LoadFile", "LoadModule"}, "dynamic.code", "High", "High", "Managed metadata references dynamic assembly-loading members."),
    ("System.Runtime.Loader.AssemblyLoadContext", None, "dynamic.code", "High", "Medium", "Managed metadata references AssemblyLoadContext members."),
)

# ECMA-335 metadata tables used by ordinary managed assemblies. Sigmascope
# parses these bytes directly; it never invokes the CLR, reflection, Assembly.Load,
# dnlib, Mono.Cecil, or any plugin-supplied code.
_CODED_INDEX_TABLES = {
    "TypeDefOrRef": ((2, 1, 27), 2),
    "HasConstant": ((4, 8, 23), 2),
    "HasCustomAttribute": ((6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43), 5),
    "HasFieldMarshal": ((4, 8), 1),
    "HasDeclSecurity": ((2, 6, 32), 2),
    "MemberRefParent": ((2, 1, 26, 6, 27), 3),
    "HasSemantics": ((20, 23), 1),
    "MethodDefOrRef": ((6, 10), 1),
    "MemberForwarded": ((4, 6), 1),
    "Implementation": ((38, 35, 39), 2),
    "CustomAttributeType": ((6, 10), 3),
    "ResolutionScope": ((0, 26, 35, 1), 2),
    "TypeOrMethodDef": ((2, 6), 1),
}


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("managed metadata read exceeds artifact bounds")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("managed metadata read exceeds artifact bounds")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("managed metadata read exceeds artifact bounds")
    return struct.unpack_from("<Q", data, offset)[0]


def _read_index(data: bytes, offset: int, size: int) -> tuple[int, int]:
    if size == 2:
        return _u16(data, offset), offset + 2
    if size == 4:
        return _u32(data, offset), offset + 4
    raise ValueError(f"unsupported metadata index size: {size}")


def _table_index_size(row_counts: dict[int, int], table_id: int) -> int:
    return 4 if row_counts.get(table_id, 0) >= 0x10000 else 2


def _coded_index_size(row_counts: dict[int, int], name: str) -> int:
    tables, tag_bits = _CODED_INDEX_TABLES[name]
    limit = 1 << (16 - tag_bits)
    return 4 if max((row_counts.get(table_id, 0) for table_id in tables), default=0) >= limit else 2


def _metadata_row_size(table_id: int, row_counts: dict[int, int], string_size: int, guid_size: int, blob_size: int) -> int:
    t = lambda table: _table_index_size(row_counts, table)
    c = lambda name: _coded_index_size(row_counts, name)
    sizes = {
        0: 2 + string_size + guid_size * 3,
        1: c("ResolutionScope") + string_size * 2,
        2: 4 + string_size * 2 + c("TypeDefOrRef") + t(4) + t(6),
        3: t(4),
        4: 2 + string_size + blob_size,
        5: t(6),
        6: 8 + string_size + blob_size + t(8),
        7: t(8),
        8: 4 + string_size,
        9: t(2) + c("TypeDefOrRef"),
        10: c("MemberRefParent") + string_size + blob_size,
        11: 2 + c("HasConstant") + blob_size,
        12: c("HasCustomAttribute") + c("CustomAttributeType") + blob_size,
        13: c("HasFieldMarshal") + blob_size,
        14: 2 + c("HasDeclSecurity") + blob_size,
        15: 6 + t(2),
        16: 4 + t(4),
        17: blob_size,
        18: t(2) + t(20),
        19: t(20),
        20: 2 + string_size + c("TypeDefOrRef"),
        21: t(2) + t(23),
        22: t(23),
        23: 2 + string_size + blob_size,
        24: 2 + t(6) + c("HasSemantics"),
        25: t(2) + c("MethodDefOrRef") * 2,
        26: string_size,
        27: blob_size,
        28: 2 + c("MemberForwarded") + string_size + t(26),
        29: 4 + t(4),
        30: 8,
        31: 4,
        32: 16 + blob_size + string_size * 2,
        33: 4,
        34: 12,
        35: 12 + blob_size * 2 + string_size * 2,
        36: 4 + t(35),
        37: 12 + t(35),
        38: 4 + string_size + blob_size,
        39: 8 + string_size * 2 + c("Implementation"),
        40: 8 + string_size + c("Implementation"),
        41: t(2) * 2,
        42: 4 + c("TypeOrMethodDef") + string_size,
        43: c("MethodDefOrRef") + blob_size,
        44: t(42) + c("TypeDefOrRef"),
    }
    if table_id not in sizes:
        raise ValueError(f"unsupported managed metadata table {table_id}")
    return sizes[table_id]


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int:
    for virtual_address, virtual_size, raw_pointer, raw_size in sections:
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size:
                raise ValueError("managed metadata RVA points outside section raw data")
            return raw_pointer + delta
    raise ValueError(f"managed metadata RVA 0x{rva:x} does not map to a section")


def _metadata_string(strings: bytes, index: int) -> str:
    if index <= 0:
        return ""
    if index >= len(strings):
        return ""
    end = strings.find(b"\0", index)
    if end < 0:
        end = len(strings)
    return strings[index:end].decode("utf-8", "replace")


def _decode_coded(value: int, name: str) -> tuple[int | None, int]:
    tables, tag_bits = _CODED_INDEX_TABLES[name]
    tag = value & ((1 << tag_bits) - 1)
    row = value >> tag_bits
    if name == "CustomAttributeType":
        # ECMA-335 reserves tags 0,1 and uses 2=MethodDef, 3=MemberRef.
        table = {2: 6, 3: 10}.get(tag)
        return table, row
    table = tables[tag] if tag < len(tables) else None
    return table, row


def _version_text(major: int, minor: int, build: int, revision: int) -> str:
    return f"{major}.{minor}.{build}.{revision}"


def _metadata_token_text(table_id: int, row: int) -> str:
    return f"0x{table_id:02x}{row:06x}"


_IL_OPERAND_1 = frozenset(range(0x0E, 0x14)) | frozenset(range(0x2B, 0x38)) | {0x1F, 0xDE, 0xFE12, 0xFE19}
_IL_OPERAND_2 = {0xFE09, 0xFE0A, 0xFE0B, 0xFE0C, 0xFE0D, 0xFE0E}
_IL_OPERAND_4 = (
    {
        0x20, 0x22, 0x27, 0x28, 0x29, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
        0x79, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F,
        0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0, 0xDD,
        0xFE06, 0xFE07, 0xFE15, 0xFE16, 0xFE1C,
    }
    | set(range(0x38, 0x45))
)
_IL_OPERAND_8 = {0x21, 0x23}


def _il_operand_length(code: bytes, cursor: int, opcode: int) -> int:
    """Return CIL operand length after the opcode; bounded switch decoding is special."""
    if opcode == 0x45:  # switch
        if cursor + 4 > len(code):
            raise ValueError("truncated CIL switch count")
        count = struct.unpack_from("<I", code, cursor)[0]
        if count > MAX_MANAGED_SWITCH_TARGETS:
            raise ValueError("CIL switch target count exceeds Sigmascope limit")
        size = 4 + count * 4
        if cursor + size > len(code):
            raise ValueError("truncated CIL switch targets")
        return size

    if opcode in _IL_OPERAND_1:
        return 1
    if opcode in _IL_OPERAND_2:
        return 2
    if opcode in _IL_OPERAND_4:
        return 4
    if opcode in _IL_OPERAND_8:
        return 8
    return 0


_IL_METHOD_TOKEN_OPCODES = {
    0x27: "jmp",
    0x28: "call",
    0x29: "calli",
    0x6F: "callvirt",
    0x73: "newobj",
    0xFE06: "ldftn",
    0xFE07: "ldvirtftn",
}


def _read_method_body(data: bytes, rva: int, sections: list[tuple[int, int, int, int]]) -> tuple[bytes, int]:
    body = _rva_to_offset(rva, sections)
    if body < 0 or body >= len(data):
        raise ValueError("CIL method RVA points outside retained assembly bytes")
    first = data[body]
    fmt = first & 0x03
    if fmt == 0x02:  # tiny
        code_size = first >> 2
        header_size = 1
    elif fmt == 0x03:  # fat
        flags_and_size = _u16(data, body)
        header_dwords = (flags_and_size >> 12) & 0x0F
        if header_dwords < 3:
            raise ValueError("invalid fat CIL method header size")
        header_size = header_dwords * 4
        if body + header_size > len(data):
            raise ValueError("truncated fat CIL method header")
        code_size = _u32(data, body + 4)
    else:
        raise ValueError("unsupported or invalid CIL method header")
    if code_size > MAX_MANAGED_IL_BYTES_PER_METHOD:
        raise ValueError("CIL method body exceeds per-method Sigmascope limit")
    code_start = body + header_size
    code_end = code_start + code_size
    if code_end > len(data):
        raise ValueError("truncated CIL method body")
    return data[code_start:code_end], header_size


def _decode_cil_calls(code: bytes, source: dict, resolve_token) -> tuple[list[dict], int]:
    calls: list[dict] = []
    cursor = 0
    instructions = 0
    while cursor < len(code):
        if instructions >= MAX_MANAGED_IL_INSTRUCTIONS_PER_METHOD:
            raise ValueError("CIL instruction count exceeds per-method Sigmascope limit")
        instruction_offset = cursor
        first = code[cursor]
        cursor += 1
        opcode = first
        if first == 0xFE:
            if cursor >= len(code):
                raise ValueError("truncated two-byte CIL opcode")
            opcode = 0xFE00 | code[cursor]
            cursor += 1
        operand_start = cursor
        operand_length = _il_operand_length(code, cursor, opcode)
        if cursor + operand_length > len(code):
            raise ValueError("truncated CIL instruction operand")
        if opcode in _IL_METHOD_TOKEN_OPCODES:
            opname = _IL_METHOD_TOKEN_OPCODES[opcode]
            if operand_length != 4:
                raise ValueError(f"unexpected {opname} operand size")
            token = struct.unpack_from("<I", code, operand_start)[0]
            target = resolve_token(token, opname)
            item = {
                "sourceMethodToken": _metadata_token_text(6, int(source.get("row") or 0)),
                "sourceDeclaringType": str(source.get("declaringType") or ""),
                "sourceMethodName": str(source.get("name") or ""),
                "ilOffset": instruction_offset,
                "opcode": opname,
                "targetToken": f"0x{token:08x}",
                **target,
            }
            calls.append(item)
        cursor += operand_length
        instructions += 1
    return calls, instructions


def parse_managed_pe(data: bytes, path: str = "artifact") -> dict | None:
    """Parse CLR/ECMA-335 metadata and bounded CIL without loading/executing the assembly."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    number_of_sections = _u16(data, pe_offset + 6)
    optional_size = _u16(data, pe_offset + 20)
    optional = pe_offset + 24
    if optional + optional_size > len(data):
        raise ValueError("truncated PE optional header")
    magic = _u16(data, optional)
    if magic == 0x10B:
        data_directories = optional + 96
    elif magic == 0x20B:
        data_directories = optional + 112
    else:
        return None
    if data_directories + (15 * 8) > optional + optional_size:
        return None
    cli_rva = _u32(data, data_directories + 14 * 8)
    cli_size = _u32(data, data_directories + 14 * 8 + 4)
    if not cli_rva or cli_size < 0x48:
        return None

    sections: list[tuple[int, int, int, int]] = []
    section_offset = optional + optional_size
    for index in range(number_of_sections):
        item = section_offset + index * 40
        if item + 40 > len(data):
            raise ValueError("truncated PE section table")
        virtual_size = _u32(data, item + 8)
        virtual_address = _u32(data, item + 12)
        raw_size = _u32(data, item + 16)
        raw_pointer = _u32(data, item + 20)
        sections.append((virtual_address, virtual_size, raw_pointer, raw_size))

    cli = _rva_to_offset(cli_rva, sections)
    metadata_rva = _u32(data, cli + 8)
    metadata_size = _u32(data, cli + 12)
    metadata = _rva_to_offset(metadata_rva, sections)
    metadata_limit = metadata + metadata_size
    if metadata_size < 16 or metadata_limit > len(data) or _u32(data, metadata) != 0x424A5342:
        raise ValueError("CLR header points to invalid metadata root")

    version_length = _u32(data, metadata + 12)
    version_start = metadata + 16
    version_end = version_start + version_length
    if version_end > metadata_limit:
        raise ValueError("truncated CLR metadata version string")
    metadata_version = data[version_start:version_end].rstrip(b"\0").decode("ascii", "replace")
    stream_cursor = (version_end + 3) & ~3
    if stream_cursor + 4 > metadata_limit:
        raise ValueError("truncated CLR metadata stream header")
    stream_count = _u16(data, stream_cursor + 2)
    stream_cursor += 4
    streams: dict[str, tuple[int, int]] = {}
    for _ in range(stream_count):
        if stream_cursor + 8 > metadata_limit:
            raise ValueError("truncated CLR metadata stream descriptor")
        rel_offset = _u32(data, stream_cursor)
        size = _u32(data, stream_cursor + 4)
        name_start = stream_cursor + 8
        name_end = data.find(b"\0", name_start, min(metadata_limit, name_start + 32))
        if name_end < 0:
            raise ValueError("unterminated CLR metadata stream name")
        name = data[name_start:name_end].decode("ascii", "replace")
        stream_cursor = (name_end + 4) & ~3
        absolute = metadata + rel_offset
        if absolute < metadata or absolute + size > metadata_limit:
            raise ValueError(f"CLR metadata stream {name} exceeds artifact bounds")
        streams[name] = (absolute, size)

    tables_stream = streams.get("#~") or streams.get("#-")
    strings_stream = streams.get("#Strings")
    if not tables_stream or not strings_stream:
        raise ValueError("managed assembly has no #~/#- tables or #Strings stream")
    strings = data[strings_stream[0]:strings_stream[0] + strings_stream[1]]
    tables = tables_stream[0]
    if tables + 24 > len(data):
        raise ValueError("truncated managed metadata tables header")
    heap_sizes = data[tables + 6]
    valid_mask = _u64(data, tables + 8)
    row_counts: dict[int, int] = {}
    cursor = tables + 24
    for table_id in range(64):
        if valid_mask & (1 << table_id):
            row_counts[table_id] = _u32(data, cursor)
            cursor += 4
    if sum(row_counts.values()) > MAX_MANAGED_METADATA_ROWS:
        raise ValueError("managed metadata row count exceeds Sigmascope limit")
    string_size = 4 if (heap_sizes & 0x01) else 2
    guid_size = 4 if (heap_sizes & 0x02) else 2
    blob_size = 4 if (heap_sizes & 0x04) else 2
    table_offsets: dict[int, int] = {}
    table_cursor = cursor
    for table_id in range(64):
        rows = row_counts.get(table_id, 0)
        if not rows:
            continue
        table_offsets[table_id] = table_cursor
        row_size = _metadata_row_size(table_id, row_counts, string_size, guid_size, blob_size)
        table_cursor += row_size * rows
        if table_cursor > tables_stream[0] + tables_stream[1] or table_cursor > len(data):
            raise ValueError(f"managed metadata table {table_id} exceeds table stream bounds")

    assembly_refs: list[dict] = []
    if row_counts.get(35):
        row_size = _metadata_row_size(35, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, min(row_counts[35], MAX_MANAGED_ASSEMBLY_REFS) + 1):
            pos = table_offsets[35] + (row_index - 1) * row_size
            major, minor, build, revision = (_u16(data, pos), _u16(data, pos + 2), _u16(data, pos + 4), _u16(data, pos + 6))
            pos += 12
            _, pos = _read_index(data, pos, blob_size)
            name_index, pos = _read_index(data, pos, string_size)
            culture_index, pos = _read_index(data, pos, string_size)
            _, pos = _read_index(data, pos, blob_size)
            assembly_refs.append({"row": row_index, "name": _metadata_string(strings, name_index), "version": _version_text(major, minor, build, revision), "culture": _metadata_string(strings, culture_index)})
    assembly_ref_by_row = {item["row"]: item for item in assembly_refs}

    module_refs: dict[int, str] = {}
    if row_counts.get(26):
        row_size = _metadata_row_size(26, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, row_counts[26] + 1):
            pos = table_offsets[26] + (row_index - 1) * row_size
            name_index, _ = _read_index(data, pos, string_size)
            module_refs[row_index] = _metadata_string(strings, name_index)

    type_defs: dict[int, dict] = {}
    if row_counts.get(2):
        row_size = _metadata_row_size(2, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, row_counts[2] + 1):
            pos = table_offsets[2] + (row_index - 1) * row_size
            pos += 4
            name_index, pos = _read_index(data, pos, string_size)
            namespace_index, pos = _read_index(data, pos, string_size)
            _, pos = _read_index(data, pos, _coded_index_size(row_counts, "TypeDefOrRef"))
            _, pos = _read_index(data, pos, _table_index_size(row_counts, 4))
            method_list, _ = _read_index(data, pos, _table_index_size(row_counts, 6))
            name, namespace = _metadata_string(strings, name_index), _metadata_string(strings, namespace_index)
            type_defs[row_index] = {"row": row_index, "fullName": f"{namespace}.{name}".strip("."), "methodList": method_list}

    type_refs: list[dict] = []
    type_ref_by_row: dict[int, dict] = {}
    if row_counts.get(1):
        row_size = _metadata_row_size(1, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, min(row_counts[1], MAX_MANAGED_TYPE_REFS) + 1):
            pos = table_offsets[1] + (row_index - 1) * row_size
            scope_value, pos = _read_index(data, pos, _coded_index_size(row_counts, "ResolutionScope"))
            name_index, pos = _read_index(data, pos, string_size)
            namespace_index, _ = _read_index(data, pos, string_size)
            name, namespace = _metadata_string(strings, name_index), _metadata_string(strings, namespace_index)
            scope_table, scope_row = _decode_coded(scope_value, "ResolutionScope")
            assembly_ref = assembly_ref_by_row.get(scope_row, {}) if scope_table == 35 else {}
            assembly_name = str(assembly_ref.get("name") or "")
            item = {"row": row_index, "namespace": namespace, "name": name, "fullName": f"{namespace}.{name}".strip("."), "assemblyName": assembly_name}
            type_refs.append(item)
            type_ref_by_row[row_index] = item

    implemented_interfaces: list[dict] = []
    if row_counts.get(9):
        row_size = _metadata_row_size(9, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, row_counts[9] + 1):
            pos = table_offsets[9] + (row_index - 1) * row_size
            class_row, pos = _read_index(data, pos, _table_index_size(row_counts, 2))
            interface_value, _ = _read_index(data, pos, _coded_index_size(row_counts, "TypeDefOrRef"))
            interface_table, interface_row = _decode_coded(interface_value, "TypeDefOrRef")
            interface_name, interface_assembly = "", ""
            if interface_table == 1:
                ref = type_ref_by_row.get(interface_row, {})
                interface_name = str(ref.get("fullName") or "")
                interface_assembly = str(ref.get("assemblyName") or "")
            elif interface_table == 2:
                interface_name = str((type_defs.get(interface_row) or {}).get("fullName") or "")
            implemented_interfaces.append({
                "row": row_index,
                "typeRow": class_row,
                "typeName": str((type_defs.get(class_row) or {}).get("fullName") or ""),
                "interfaceName": interface_name,
                "interfaceAssemblyName": interface_assembly,
            })

    method_defs: dict[int, dict] = {}
    if row_counts.get(6):
        row_size = _metadata_row_size(6, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, row_counts[6] + 1):
            pos = table_offsets[6] + (row_index - 1) * row_size
            rva = _u32(data, pos)
            impl_flags = _u16(data, pos + 4)
            flags = _u16(data, pos + 6)
            pos += 8
            name_index, pos = _read_index(data, pos, string_size)
            _, pos = _read_index(data, pos, blob_size)
            _, _ = _read_index(data, pos, _table_index_size(row_counts, 8))
            method_defs[row_index] = {"row": row_index, "rva": rva, "implFlags": impl_flags, "flags": flags, "name": _metadata_string(strings, name_index), "declaringType": ""}

    if method_defs and type_defs:
        ordered_types = [type_defs[key] for key in sorted(type_defs)]
        method_limit = row_counts.get(6, 0) + 1
        for index, type_item in enumerate(ordered_types):
            start_row = int(type_item.get("methodList") or 0)
            end_row = int(ordered_types[index + 1].get("methodList") or method_limit) if index + 1 < len(ordered_types) else method_limit
            if start_row <= 0:
                continue
            for method_row in range(start_row, min(end_row, method_limit)):
                if method_row in method_defs:
                    method_defs[method_row]["declaringType"] = str(type_item.get("fullName") or "")

    member_refs: list[dict] = []
    member_ref_by_row: dict[int, dict] = {}
    if row_counts.get(10):
        row_size = _metadata_row_size(10, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, min(row_counts[10], MAX_MANAGED_MEMBER_REFS) + 1):
            pos = table_offsets[10] + (row_index - 1) * row_size
            parent_value, pos = _read_index(data, pos, _coded_index_size(row_counts, "MemberRefParent"))
            name_index, pos = _read_index(data, pos, string_size)
            _, _ = _read_index(data, pos, blob_size)
            parent_table, parent_row = _decode_coded(parent_value, "MemberRefParent")
            declaring_type, assembly_name = "", ""
            if parent_table == 1:
                type_item = type_ref_by_row.get(parent_row, {})
                declaring_type = str(type_item.get("fullName") or "")
                assembly_name = str(type_item.get("assemblyName") or "")
            elif parent_table == 2:
                declaring_type = str((type_defs.get(parent_row) or {}).get("fullName") or "")
            elif parent_table == 26:
                declaring_type = module_refs.get(parent_row, "")
            elif parent_table == 6:
                declaring_type = f"<MethodDef:{(method_defs.get(parent_row) or {}).get('name', parent_row)}>"
            item = {"row": row_index, "declaringType": declaring_type, "name": _metadata_string(strings, name_index), "assemblyName": assembly_name}
            member_refs.append(item)
            member_ref_by_row[row_index] = item

    method_specs: dict[int, tuple[int | None, int]] = {}
    if row_counts.get(43):
        row_size = _metadata_row_size(43, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, row_counts[43] + 1):
            pos = table_offsets[43] + (row_index - 1) * row_size
            method_value, pos = _read_index(data, pos, _coded_index_size(row_counts, "MethodDefOrRef"))
            _, _ = _read_index(data, pos, blob_size)
            method_specs[row_index] = _decode_coded(method_value, "MethodDefOrRef")

    assembly_name, assembly_version = Path(path).stem, ""
    if row_counts.get(32):
        pos = table_offsets[32] + 4
        major, minor, build, revision = (_u16(data, pos), _u16(data, pos + 2), _u16(data, pos + 4), _u16(data, pos + 6))
        pos += 12
        _, pos = _read_index(data, pos, blob_size)
        name_index, pos = _read_index(data, pos, string_size)
        assembly_name = _metadata_string(strings, name_index) or assembly_name
        assembly_version = _version_text(major, minor, build, revision)

    pinvokes: list[dict] = []
    pinvoke_by_method: dict[int, dict] = {}
    if row_counts.get(28):
        row_size = _metadata_row_size(28, row_counts, string_size, guid_size, blob_size)
        for row_index in range(1, min(row_counts[28], MAX_MANAGED_PINVOKES) + 1):
            pos = table_offsets[28] + (row_index - 1) * row_size + 2
            forwarded_value, pos = _read_index(data, pos, _coded_index_size(row_counts, "MemberForwarded"))
            import_name_index, pos = _read_index(data, pos, string_size)
            module_row, _ = _read_index(data, pos, _table_index_size(row_counts, 26))
            forwarded_table, forwarded_row = _decode_coded(forwarded_value, "MemberForwarded")
            managed_name = str((method_defs.get(forwarded_row) or {}).get("name") or "") if forwarded_table == 6 else ""
            item = {"row": row_index, "library": module_refs.get(module_row, ""), "entryPoint": _metadata_string(strings, import_name_index), "managedName": managed_name, "methodRow": forwarded_row if forwarded_table == 6 else 0}
            pinvokes.append(item)
            if forwarded_table == 6 and forwarded_row:
                pinvoke_by_method[forwarded_row] = item

    def resolve_method_token(token: int, opcode_name: str) -> dict:
        table_id = (token >> 24) & 0xFF
        row = token & 0x00FFFFFF
        via_method_spec = False
        if table_id == 43:
            base_table, base_row = method_specs.get(row, (None, 0))
            if base_table is None or base_row <= 0:
                return {"targetKind": "unresolved-method-spec", "targetDeclaringType": "", "targetName": "", "targetAssemblyName": "", "targetNativeLibrary": "", "targetNativeEntryPoint": "", "targetMethodToken": ""}
            table_id, row = int(base_table), int(base_row)
            via_method_spec = True
        if opcode_name == "calli":
            return {"targetKind": "standalone-signature", "targetDeclaringType": "", "targetName": "calli", "targetAssemblyName": "", "targetNativeLibrary": "", "targetNativeEntryPoint": "", "targetMethodToken": ""}
        if table_id == 10:
            item = member_ref_by_row.get(row, {})
            return {
                "targetKind": "method-spec/member-reference" if via_method_spec else "member-reference",
                "targetDeclaringType": str(item.get("declaringType") or ""),
                "targetName": str(item.get("name") or ""),
                "targetAssemblyName": str(item.get("assemblyName") or ""),
                "targetNativeLibrary": "", "targetNativeEntryPoint": "", "targetMethodToken": "",
            }
        if table_id == 6:
            item = method_defs.get(row, {})
            native = pinvoke_by_method.get(row, {})
            return {
                "targetKind": "method-spec/pinvoke-method" if (via_method_spec and native) else "method-spec/method-definition" if via_method_spec else "pinvoke-method" if native else "method-definition",
                "targetDeclaringType": str(item.get("declaringType") or ""),
                "targetName": str(item.get("name") or ""),
                "targetAssemblyName": assembly_name,
                "targetNativeLibrary": str(native.get("library") or ""),
                "targetNativeEntryPoint": str(native.get("entryPoint") or ""),
                "targetMethodToken": _metadata_token_text(6, row),
            }
        return {"targetKind": f"metadata-table-{table_id}", "targetDeclaringType": "", "targetName": "", "targetAssemblyName": "", "targetNativeLibrary": "", "targetNativeEntryPoint": "", "targetMethodToken": ""}

    call_sites: list[dict] = []
    il_summary = {"methodBodies": 0, "bytesScanned": 0, "instructions": 0, "callSites": 0, "errors": 0, "errorSamples": [], "truncated": False}
    methods_with_bodies = [item for item in method_defs.values() if int(item.get("rva") or 0) != 0]
    if len(methods_with_bodies) > MAX_MANAGED_METHOD_BODIES:
        methods_with_bodies = methods_with_bodies[:MAX_MANAGED_METHOD_BODIES]
        il_summary["truncated"] = True
    for method in methods_with_bodies:
        if il_summary["bytesScanned"] >= MAX_MANAGED_IL_BYTES_TOTAL or len(call_sites) >= MAX_MANAGED_CALL_SITES:
            il_summary["truncated"] = True
            break
        try:
            code, _header_size = _read_method_body(data, int(method["rva"]), sections)
            if il_summary["bytesScanned"] + len(code) > MAX_MANAGED_IL_BYTES_TOTAL:
                il_summary["truncated"] = True
                break
            method_calls, instruction_count = _decode_cil_calls(code, method, resolve_method_token)
            remaining = MAX_MANAGED_CALL_SITES - len(call_sites)
            if len(method_calls) > remaining:
                method_calls = method_calls[:remaining]
                il_summary["truncated"] = True
            call_sites.extend(method_calls)
            il_summary["methodBodies"] += 1
            il_summary["bytesScanned"] += len(code)
            il_summary["instructions"] += instruction_count
            if len(call_sites) >= MAX_MANAGED_CALL_SITES:
                il_summary["truncated"] = True
                break
        except ValueError as exc:
            il_summary["errors"] += 1
            if len(il_summary["errorSamples"]) < 8:
                il_summary["errorSamples"].append({
                    "methodToken": _metadata_token_text(6, int(method.get("row") or 0)),
                    "methodName": str(method.get("name") or ""),
                    "error": str(exc)[:240],
                })
    il_summary["callSites"] = len(call_sites)

    plugin_types = {
        str(item.get("typeName") or "")
        for item in implemented_interfaces
        if str(item.get("interfaceName") or "").endswith(".IDalamudPlugin")
        or str(item.get("interfaceName") or "") == "IDalamudPlugin"
    }
    callback_root_names = {
        "Draw", "OnDraw", "Update", "OnUpdate", "FrameworkUpdate", "OnFrameworkUpdate",
        "OnCommand", "OpenConfigUi", "OpenMainUi", "OnLogin", "OnLogout",
        "OnTerritoryChanged", "OnConditionChange", "OnChatMessage", "OnFrameworkTick",
        "OnAddonEvent", "OnToast", "OnDutyStarted", "OnDutyCompleted",
    }
    roots: list[dict] = []
    for method in method_defs.values():
        declaring = str(method.get("declaringType") or "")
        name = str(method.get("name") or "")
        root_kind, confidence = "", ""
        if declaring in plugin_types and name == ".ctor":
            root_kind, confidence = "plugin-constructor", "High"
        elif declaring in plugin_types and name == "Dispose":
            root_kind, confidence = "plugin-lifecycle", "High"
        elif name in callback_root_names:
            root_kind, confidence = "callback-name", "Medium"
        elif name == ".ctor" and (declaring == "Plugin" or declaring.endswith(".Plugin")):
            root_kind, confidence = "plugin-name-constructor", "Medium"
        if root_kind:
            roots.append({
                "methodToken": _metadata_token_text(6, int(method.get("row") or 0)),
                "declaringType": declaring, "methodName": name,
                "rootKind": root_kind, "confidence": confidence,
            })
        if len(roots) >= MAX_MANAGED_REACHABILITY_ROOTS:
            break

    method_by_token = {
        _metadata_token_text(6, int(method.get("row") or 0)): method
        for method in method_defs.values()
    }
    outgoing: dict[str, list[dict]] = defaultdict(list)
    for call in call_sites:
        outgoing[str(call.get("sourceMethodToken") or "")].append(call)

    reachability: list[dict] = []
    reachable_source_tokens: set[str] = set()
    for root in roots:
        root_token = str(root["methodToken"])
        queue = deque([(root_token, 0, "", -1)])
        seen: set[str] = set()
        while queue and len(reachability) < MAX_MANAGED_REACHABLE_METHODS:
            token, depth, via_token, via_offset = queue.popleft()
            if token in seen or depth > MAX_MANAGED_REACHABILITY_DEPTH:
                continue
            seen.add(token)
            method = method_by_token.get(token, {})
            reachability.append({
                "rootMethodToken": root_token,
                "rootDeclaringType": str(root.get("declaringType") or ""),
                "rootMethodName": str(root.get("methodName") or ""),
                "rootKind": str(root.get("rootKind") or ""),
                "rootConfidence": str(root.get("confidence") or ""),
                "methodToken": token,
                "methodDeclaringType": str(method.get("declaringType") or ""),
                "methodName": str(method.get("name") or ""),
                "depth": depth,
                "viaMethodToken": via_token,
                "viaIlOffset": via_offset,
            })
            reachable_source_tokens.add(token)
            if depth >= MAX_MANAGED_REACHABILITY_DEPTH:
                continue
            for call in outgoing.get(token, []):
                target_token = str(call.get("targetMethodToken") or "")
                if target_token and target_token in method_by_token and target_token not in seen:
                    queue.append((target_token, depth + 1, token, int(call.get("ilOffset") or 0)))
        if len(reachability) >= MAX_MANAGED_REACHABLE_METHODS:
            break

    il_summary["reachabilityRoots"] = len(roots)
    il_summary["reachableMethods"] = len({str(item.get("methodToken") or "") for item in reachability})
    il_summary["reachableCallSites"] = sum(1 for call in call_sites if str(call.get("sourceMethodToken") or "") in reachable_source_tokens)
    il_summary["reachabilityTruncated"] = len(reachability) >= MAX_MANAGED_REACHABLE_METHODS

    return {
        "path": path,
        "sha256": sha256_bytes(data),
        "assemblyName": assembly_name,
        "assemblyVersion": assembly_version,
        "metadataVersion": metadata_version,
        "assemblyReferences": assembly_refs,
        "typeReferences": type_refs,
        "memberReferences": member_refs,
        "pinvokes": pinvokes,
        "implementedInterfaces": implemented_interfaces,
        "methodDefinitions": [
            {"row": int(item.get("row") or 0), "methodToken": _metadata_token_text(6, int(item.get("row") or 0)),
             "declaringType": str(item.get("declaringType") or ""), "name": str(item.get("name") or ""),
             "hasBody": bool(int(item.get("rva") or 0))}
            for item in method_defs.values()
        ],
        "callSites": call_sites,
        "reachability": reachability,
        "il": il_summary,
        "parseStatus": "complete",
        "tableCounts": {
            "assemblyReferences": row_counts.get(35, 0),
            "typeReferences": row_counts.get(1, 0),
            "memberReferences": row_counts.get(10, 0),
            "pinvokes": row_counts.get(28, 0),
            "methodDefinitions": row_counts.get(6, 0),
            "methodSpecifications": row_counts.get(43, 0),
        },
        "truncated": bool(
            row_counts.get(35, 0) > MAX_MANAGED_ASSEMBLY_REFS or
            row_counts.get(1, 0) > MAX_MANAGED_TYPE_REFS or
            row_counts.get(10, 0) > MAX_MANAGED_MEMBER_REFS or
            row_counts.get(28, 0) > MAX_MANAGED_PINVOKES or
            il_summary["truncated"]
        ),
        "error": "",
    }

def add_managed_symbol(intel: dict, path: str, symbol_kind: str, declaring_type: str, name: str, assembly_name: str, evidence: str) -> None:
    item = {
        "origin": intel["origin"], "path": path, "kind": symbol_kind,
        "declaringType": declaring_type, "name": name, "assemblyName": assembly_name,
        "evidence": [evidence] if evidence else [],
    }
    _append_intel(intel, "managedSymbols", item, ("origin", "path", "kind", "declaringType", "name", "assemblyName"))


def add_managed_call_site(intel: dict, path: str, call: dict, hits: dict[str, list[str]]) -> None:
    item = {
        "origin": intel["origin"], "path": path,
        "sourceMethodToken": str(call.get("sourceMethodToken") or ""),
        "sourceDeclaringType": str(call.get("sourceDeclaringType") or ""),
        "sourceMethodName": str(call.get("sourceMethodName") or ""),
        "ilOffset": int(call.get("ilOffset") or 0), "opcode": str(call.get("opcode") or ""),
        "targetToken": str(call.get("targetToken") or ""), "targetKind": str(call.get("targetKind") or ""),
        "targetDeclaringType": str(call.get("targetDeclaringType") or ""), "targetName": str(call.get("targetName") or ""),
        "targetAssemblyName": str(call.get("targetAssemblyName") or ""),
        "targetNativeLibrary": str(call.get("targetNativeLibrary") or ""),
        "targetNativeEntryPoint": str(call.get("targetNativeEntryPoint") or ""),
        "targetMethodToken": str(call.get("targetMethodToken") or ""),
        "evidence": [],
    }
    source = f"{item['sourceDeclaringType']}.{item['sourceMethodName']}".strip(".") or item["sourceMethodToken"]
    target = f"{item['targetDeclaringType']}.{item['targetName']}".strip(".")
    if item["targetNativeLibrary"]:
        target = f"{target} -> {item['targetNativeLibrary']}!{item['targetNativeEntryPoint']}".strip()
    evidence = f"il:{path}:{source}+0x{item['ilOffset']:x}: {item['opcode']} {target or item['targetToken']}"
    item["evidence"] = [evidence]
    _append_intel(intel, "managedCallSites", item, ("origin", "path", "sourceMethodToken", "ilOffset", "opcode", "targetToken"))

    if target:
        add_rule_hits(target, evidence, hits, intel)
    declaring = item["targetDeclaringType"]
    name = item["targetName"]
    for prefix, names, permission_id, risk, _confidence, _reason in MANAGED_MEMBER_PERMISSION_MAP:
        matches_type = declaring == prefix or (prefix.endswith(".") and declaring.startswith(prefix))
        if matches_type and (names is None or name in names):
            add_permission_candidate(
                intel, permission_id, risk, "VeryHigh",
                f"Compiled IL {item['opcode']} instruction targets {declaring}.{name}.", evidence,
            )
    if item["targetNativeLibrary"]:
        add_permission_candidate(
            intel, "native.interop", "High", "VeryHigh",
            "Compiled IL directly targets a method mapped to a native P/Invoke entry point.", evidence,
        )


def apply_managed_metadata(intel: dict, metadata: dict, hits: dict[str, list[str]]) -> None:
    path = str(metadata.get("path") or "artifact")
    summary = {
        "origin": intel["origin"], "path": path, "sha256": str(metadata.get("sha256") or ""),
        "assemblyName": str(metadata.get("assemblyName") or ""), "assemblyVersion": str(metadata.get("assemblyVersion") or ""),
        "metadataVersion": str(metadata.get("metadataVersion") or ""), "parseStatus": str(metadata.get("parseStatus") or "complete"),
        "referenceCount": int((metadata.get("tableCounts") or {}).get("assemblyReferences", len(metadata.get("assemblyReferences") or []))),
        "typeReferenceCount": int((metadata.get("tableCounts") or {}).get("typeReferences", len(metadata.get("typeReferences") or []))),
        "memberReferenceCount": int((metadata.get("tableCounts") or {}).get("memberReferences", len(metadata.get("memberReferences") or []))),
        "nativeImportCount": int((metadata.get("tableCounts") or {}).get("pinvokes", len(metadata.get("pinvokes") or []))),
        "methodBodyCount": int((metadata.get("il") or {}).get("methodBodies", 0)),
        "ilBytesScanned": int((metadata.get("il") or {}).get("bytesScanned", 0)),
        "callSiteCount": int((metadata.get("il") or {}).get("callSites", len(metadata.get("callSites") or []))),
        "ilParseErrors": int((metadata.get("il") or {}).get("errors", 0)),
        "reachabilityRootCount": int((metadata.get("il") or {}).get("reachabilityRoots", 0)),
        "reachableMethodCount": int((metadata.get("il") or {}).get("reachableMethods", 0)),
        "reachableCallSiteCount": int((metadata.get("il") or {}).get("reachableCallSites", 0)),
        "reachabilityTruncated": bool((metadata.get("il") or {}).get("reachabilityTruncated", False)),
        "ilTruncated": bool((metadata.get("il") or {}).get("truncated", False)),
        "truncated": bool(metadata.get("truncated")),
        "error": str(metadata.get("error") or ""),
    }
    _append_intel(intel, "managedAssemblies", summary, ("origin", "path", "sha256"))

    for reference in metadata.get("assemblyReferences") or []:
        name = str(reference.get("name") or "")
        version = str(reference.get("version") or "")
        add_dependency(intel, "managed-assembly-reference", name, version, path, "analyzed", f"metadata:{path}: AssemblyRef {name} {version}".strip(), "observed", resolved_version=version)
        add_managed_symbol(intel, path, "assembly-reference", "", name, name, f"metadata:{path}: AssemblyRef")

    for type_ref in metadata.get("typeReferences") or []:
        full_name = str(type_ref.get("fullName") or "")
        assembly_name = str(type_ref.get("assemblyName") or "")
        add_managed_symbol(intel, path, "type-reference", full_name, "", assembly_name, f"metadata:{path}: TypeRef {full_name}")
        add_rule_hits(full_name, f"metadata:{path}", hits, intel)
        for prefix, permission_id, risk, confidence, reason in MANAGED_TYPE_PERMISSION_MAP:
            if full_name == prefix or full_name.startswith(prefix):
                add_permission_candidate(intel, permission_id, risk, confidence, reason, f"metadata:{path}: {full_name}")

    for member in metadata.get("memberReferences") or []:
        declaring = str(member.get("declaringType") or "")
        name = str(member.get("name") or "")
        assembly_name = str(member.get("assemblyName") or "")
        symbol = f"{declaring}.{name}".strip(".")
        add_managed_symbol(intel, path, "member-reference", declaring, name, assembly_name, f"metadata:{path}: MemberRef {symbol}")
        add_rule_hits(symbol, f"metadata:{path}", hits, intel)
        for prefix, names, permission_id, risk, confidence, reason in MANAGED_MEMBER_PERMISSION_MAP:
            matches_type = declaring == prefix or (prefix.endswith(".") and declaring.startswith(prefix))
            if matches_type and (names is None or name in names):
                add_permission_candidate(intel, permission_id, risk, confidence, reason, f"metadata:{path}: {symbol}")

    for pinvoke in metadata.get("pinvokes") or []:
        library = str(pinvoke.get("library") or "")
        entry_point = str(pinvoke.get("entryPoint") or "")
        managed_name = str(pinvoke.get("managedName") or "")
        _append_intel(intel, "nativeImports", {"origin": intel["origin"], "library": library, "path": path, "entryPoint": entry_point, "managedName": managed_name}, ("origin", "library", "path", "entryPoint"))
        add_dependency(intel, "native-import", library, "", path, "analyzed", f"metadata:{path}: P/Invoke {library}!{entry_point}", "observed")
        add_managed_symbol(intel, path, "pinvoke", library, entry_point or managed_name, "", f"metadata:{path}: ImplMap")
        add_permission_candidate(intel, "native.interop", "High", "High", "Managed metadata contains a P/Invoke map.", f"metadata:{path}: {library}!{entry_point}")
        add_rule_hits(f"DllImportAttribute {library} {entry_point}", f"metadata:{path}", hits, intel)

    for call in metadata.get("callSites") or []:
        add_managed_call_site(intel, path, call, hits)

    for reach in metadata.get("reachability") or []:
        item = {
            "origin": intel["origin"], "path": path,
            "rootMethodToken": str(reach.get("rootMethodToken") or ""),
            "rootDeclaringType": str(reach.get("rootDeclaringType") or ""),
            "rootMethodName": str(reach.get("rootMethodName") or ""),
            "rootKind": str(reach.get("rootKind") or ""),
            "rootConfidence": str(reach.get("rootConfidence") or ""),
            "methodToken": str(reach.get("methodToken") or ""),
            "methodDeclaringType": str(reach.get("methodDeclaringType") or ""),
            "methodName": str(reach.get("methodName") or ""),
            "depth": int(reach.get("depth") or 0),
            "viaMethodToken": str(reach.get("viaMethodToken") or ""),
            "viaIlOffset": int(reach.get("viaIlOffset") if reach.get("viaIlOffset") is not None else -1),
        }
        item["evidence"] = [
            f"reachability:{path}:{item['rootMethodToken']} -> {item['methodToken']} depth={item['depth']} ({item['rootKind']})"
        ]
        _append_intel(intel, "managedReachability", item, ("origin", "path", "rootMethodToken", "methodToken"))


def record_managed_metadata_error(intel: dict, path: str, sha256: str, error: str) -> None:
    summary = {
        "origin": intel["origin"], "path": path, "sha256": sha256,
        "assemblyName": Path(path).stem, "assemblyVersion": "", "metadataVersion": "",
        "parseStatus": "error", "referenceCount": 0, "typeReferenceCount": 0,
        "memberReferenceCount": 0, "nativeImportCount": 0, "methodBodyCount": 0,
        "ilBytesScanned": 0, "callSiteCount": 0, "ilParseErrors": 0,
        "reachabilityRootCount": 0, "reachableMethodCount": 0, "reachableCallSiteCount": 0, "reachabilityTruncated": False,
        "ilTruncated": False,
        "truncated": False,
        "error": error[:500],
    }
    _append_intel(intel, "managedAssemblies", summary, ("origin", "path", "sha256"))
    add_dependency(intel, "managed-assembly", Path(path).name, "", path, "not-analyzed", f"metadata:{path}: parse failed: {error[:180]}", "bundled")


def add_rule_hits(
    text: str,
    evidence_label: str,
    hits: dict[str, list[str]],
    intel: dict | None = None,
) -> None:
    """Record legacy rule hits and the low-level literal observations behind them.

    ``hits`` remains the 2.14-compatible projection input.  ``staticPatternMatches``
    is the Phase-7 retained observation seam: it records the exact case-insensitive
    literal that was present plus where it was observed, but does not record the
    legacy rule ID or any finding/severity conclusion.  SRL can therefore derive
    stable primitive facts from retained observations without recursively consuming
    current findings.
    """
    lowered = text.lower()
    for rule in RULES:
        matched = [p for p in rule.patterns if p.lower() in lowered]
        if not matched:
            continue
        existing = hits[rule.rule_id]
        for pattern in matched[:3]:
            evidence = f"{evidence_label}: {pattern}"
            if evidence not in existing and len(existing) < 8:
                existing.append(evidence)
            if intel is not None:
                _append_intel(
                    intel,
                    "staticPatternMatches",
                    {
                        "origin": str(intel.get("origin") or ""),
                        "pattern": pattern,
                        "evidenceLabel": evidence_label,
                        "evidence": [evidence],
                    },
                    ("origin", "pattern", "evidenceLabel"),
                )


def add_external_path_hits(text: str, evidence_label: str, hits: dict[str, list[str]]) -> None:
    existing = hits["filesystem.external-path"]
    for path in external_hard_coded_paths(text):
        evidence = f"{evidence_label}: {path}"
        if evidence not in existing and len(existing) < 8:
            existing.append(evidence)


def add_network_endpoints(
    intel: dict, text: str, evidence_label: str, *, origin_type: str | None = None, confidence: str | None = None,
) -> None:
    for endpoint in endpoint_candidates(text, evidence_label, origin_type=origin_type, confidence=confidence):
        endpoint["origin"] = intel["origin"]
        _append_intel(intel, "networkEndpoints", endpoint, ("origin", "originType", "url"))


def empty_dependency_intelligence(origin: str) -> dict:
    return {
        "schema": "omega.plugin-security.dependencies.v2",
        "origin": origin,
        "staticPatternMatchContractVersion": 1,
        "imports": [],
        "dependencies": [],
        "dalamudServices": [],
        "ipcIntegrations": [],
        "nativeImports": [],
        "managedAssemblies": [],
        "managedSymbols": [],
        "managedCallSites": [],
        "managedReachability": [],
        "permissionCandidates": [],
        "sourceFiles": [],
        "networkEndpoints": [],
        "staticPatternMatches": [],
        "endpointSummary": {},
        "componentSummary": {},
        "limits": {"truncated": False, "droppedByCollection": {}},
        "coverage": {"total": 0, "known": 0, "analyzed": 0, "notAnalyzed": 0, "binaryOnly": 0, "externalPlugin": 0, "dynamicallyDownloaded": 0,
                     "requirements": {"required": 0, "soft": 0, "optional": 0, "bundled": 0, "observed": 0, "unknown": 0}},
        "fingerprints": {
            "sourceArchiveSha256": "",
            "relevantSourceSha256": "",
            "projectDependencySha256": "",
        },
    }


def _append_intel(intel: dict, collection: str, item: dict, keys: tuple[str, ...]) -> None:
    """Deduplicate in O(1) average time, then enforce a hard collection ceiling.

    Truncation is explicit in the scan payload so a bounded scan is never
    mistaken for a complete dependency inventory. Internal identity maps are
    discarded by finalize_intelligence and are never persisted.
    """
    items = intel[collection]
    identity = tuple(str(item.get(key, "")).casefold() for key in keys)
    identity_maps = intel.setdefault("_identityMaps", {})
    collection_map = identity_maps.setdefault(collection, {})
    existing_index = collection_map.get(identity)
    if existing_index is not None and 0 <= int(existing_index) < len(items):
        existing = items[int(existing_index)]
        if "evidence" in item:
            merged = list(existing.get("evidence") or [])
            for evidence in item.get("evidence") or []:
                if evidence not in merged and len(merged) < 8:
                    merged.append(evidence)
            existing["evidence"] = merged
        return
    limit = INTELLIGENCE_LIST_LIMITS.get(collection)
    if limit is not None and len(items) >= limit:
        limits = intel.setdefault("limits", {"truncated": False, "droppedByCollection": {}})
        limits["truncated"] = True
        dropped = limits.setdefault("droppedByCollection", {})
        dropped[collection] = int(dropped.get(collection, 0)) + 1
        return
    collection_map[identity] = len(items)
    items.append(item)


def add_import(intel: dict, namespace: str, path: str) -> None:
    namespace = namespace.strip().rstrip(";")
    if not namespace:
        return
    _append_intel(intel, "imports", {"origin": intel["origin"], "namespace": namespace, "path": path}, ("origin", "namespace", "path"))
    for prefix, permission_id, risk, confidence, reason in IMPORT_PERMISSION_MAP:
        if namespace == prefix or namespace.startswith(prefix + "."):
            add_permission_candidate(intel, permission_id, risk, confidence, reason, f"{path}: using {namespace}")


def add_dependency(intel: dict, kind: str, name: str, version: str, path: str, status: str, evidence: str = "", requirement: str = "observed", version_requirement: str = "", resolved_version: str = "", relationship: str = "", relationship_confidence: str = "", relationship_evidence: list[str] | None = None) -> None:
    name = (name or "").strip()
    if not name:
        return
    item = {
        "origin": intel["origin"],
        "kind": kind,
        "name": name,
        "version": (version or "").strip(),
        "versionRequirement": (version_requirement or "").strip(),
        "resolvedVersion": (resolved_version or "").strip(),
        "path": path,
        "status": status,
        "requirement": requirement if requirement in {"required", "soft", "optional", "bundled", "observed", "unknown"} else "unknown",
        "relationship": relationship if relationship in {"required", "feature", "optional", "unknown", ""} else "unknown",
        "relationshipConfidence": relationship_confidence if relationship_confidence in {"VeryHigh", "High", "Medium", "Low", ""} else "Low",
        "relationshipEvidence": list(relationship_evidence or [])[:6],
        "evidence": [evidence] if evidence else [],
    }
    _append_intel(intel, "dependencies", item, ("origin", "kind", "name", "version", "versionRequirement", "resolvedVersion", "path", "requirement", "relationship"))
    package_key = name.lower().replace(".dll", "")
    if package_key in PACKAGE_PERMISSION_MAP:
        permission_id, risk, confidence, reason = PACKAGE_PERMISSION_MAP[package_key]
        add_permission_candidate(intel, permission_id, risk, confidence, reason, evidence or f"{path}: {name}")


def add_permission_candidate(intel: dict, permission_id: str, risk: str, confidence: str, reason: str, evidence: str) -> None:
    item = {
        "origin": intel["origin"],
        "permissionId": permission_id,
        "risk": risk,
        "confidence": confidence,
        "reason": reason,
        "evidence": [evidence] if evidence else [],
    }
    _append_intel(intel, "permissionCandidates", item, ("origin", "permissionId", "risk", "confidence", "reason"))


def add_dalamud_service(intel: dict, service: str, path: str) -> None:
    if service not in DALAMUD_SERVICES:
        return
    _append_intel(intel, "dalamudServices", {"origin": intel["origin"], "service": service, "path": path}, ("origin", "service", "path"))
    mapped = SERVICE_PERMISSION_MAP.get(service)
    if mapped:
        permission_id, risk, confidence = mapped
        add_permission_candidate(intel, permission_id, risk, confidence, f"Dalamud service {service} is referenced.", f"{path}: {service}")


def scan_project_xml(path: str, text: str, intel: dict) -> None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1]
        attrs = {k.rsplit("}", 1)[-1]: v for k, v in elem.attrib.items()}
        if tag == "PackageReference":
            name = attrs.get("Include") or attrs.get("Update") or ""
            version = attrs.get("Version") or ""
            if not version:
                for child in elem:
                    if child.tag.rsplit("}", 1)[-1] == "Version" and child.text:
                        version = child.text.strip()
                        break
            add_dependency(intel, "nuget", name, version, path, "known", f"{path}: PackageReference {name}", "optional" if attrs.get("Condition") else "required", version_requirement=version)
        elif tag == "ProjectReference":
            name = attrs.get("Include") or ""
            add_dependency(intel, "project-reference", name, "", path, "known", f"{path}: ProjectReference {name}", "optional" if attrs.get("Condition") else "required")
        elif tag == "Reference":
            name = (attrs.get("Include") or "").split(",", 1)[0].strip()
            if name:
                add_dependency(intel, "assembly-reference", name, "", path, "known", f"{path}: Reference {name}", "optional" if attrs.get("Condition") else "required")


def scan_dependency_json(path: str, text: str, intel: dict) -> None:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return
    lower_name = Path(path).name.lower()
    if lower_name == "packages.lock.json" and isinstance(doc, dict):
        for framework, packages in (doc.get("dependencies") or {}).items():
            if not isinstance(packages, dict):
                continue
            for name, payload in packages.items():
                version = ""
                requested = ""
                resolved = ""
                if isinstance(payload, dict):
                    requested = str(payload.get("requested") or "")
                    resolved = str(payload.get("resolved") or "")
                    version = resolved or requested
                add_dependency(intel, "nuget-lock", str(name), version, path, "known", f"{path}: {framework}/{name}", "required", version_requirement=requested, resolved_version=resolved)
    elif lower_name == "project.assets.json" and isinstance(doc, dict):
        libraries = doc.get("libraries") or {}
        if isinstance(libraries, dict):
            for key, payload in libraries.items():
                if "/" not in key:
                    continue
                name, version = key.split("/", 1)
                kind = "nuget-resolved"
                status = "known"
                if isinstance(payload, dict) and payload.get("type") == "project":
                    kind, status = "project-reference", "known"
                add_dependency(intel, kind, name, version, path, status, f"{path}: resolved {key}", "required", resolved_version=version)
    elif lower_name.endswith(".deps.json") and isinstance(doc, dict):
        # Published .NET applications commonly carry a runtime *.deps.json even when
        # project.assets.json/packages.lock.json are not present in the plugin ZIP.
        # The libraries map is therefore valuable artifact-side evidence of the exact
        # NuGet package versions that the built plugin was resolved against.  Restrict
        # this to entries explicitly marked as NuGet packages so project/runtime entries
        # are not accidentally turned into vulnerability lookups.
        libraries = doc.get("libraries") or {}
        if isinstance(libraries, dict):
            for key, payload in libraries.items():
                if "/" not in key or not isinstance(payload, dict):
                    continue
                if str(payload.get("type") or "").strip().casefold() != "package":
                    continue
                name, version = key.split("/", 1)
                name = name.strip()
                version = version.strip()
                if not name or not version:
                    continue
                add_dependency(
                    intel, "nuget-resolved", name, version, path, "known",
                    f"{path}: runtime dependency {key}", "required",
                    version_requirement=version, resolved_version=version,
                )
    if isinstance(doc, dict):
        plugin_dependency_keys = {
            "RequiredPlugins": "required",
            "LoadRequiredPlugins": "required",
            "DalamudPluginDependencies": "required",
            "PluginDependencies": "unknown",
            "OptionalPlugins": "soft",
            "SoftDependencies": "soft",
            "OptionalDependencies": "soft",
            "LoadOptionalPlugins": "soft",
            "DalamudOptionalPluginDependencies": "soft",
            "SoftPluginDependencies": "soft",
        }
        for key, default_requirement in plugin_dependency_keys.items():
            value = doc.get(key)
            if not isinstance(value, list):
                continue
            for item in value:
                requirement = default_requirement
                if isinstance(item, str):
                    name, version = item, ""
                elif isinstance(item, dict):
                    name = str(item.get("InternalName") or item.get("Name") or item.get("name") or "")
                    version = str(item.get("Version") or item.get("version") or "")
                    if item.get("SoftDependency") is True or item.get("Optional") is True or item.get("IsRequired") is False or item.get("Required") is False:
                        requirement = "soft"
                    elif item.get("IsRequired") is True or item.get("Required") is True:
                        requirement = "required"
                else:
                    continue
                add_dependency(intel, "external-plugin", name, version, path, "external-plugin", f"{path}: {key}", requirement, version_requirement=version)


def _source_method_name_near(text: str, position: int) -> str:
    """Best-effort containing method name for conservative IPC relationship inference."""
    prefix = text[max(0, position - 5000):position]
    pattern = re.compile(
        r"(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|unsafe|partial|new)\s+)*"
        r"(?:[A-Za-z_][\w<>,.?\[\]]*\s+)?(?P<name>[A-Za-z_]\w*)\s*\([^;{}]{0,500}\)\s*(?:=>|\{)"
    )
    controls = {"if", "for", "foreach", "while", "switch", "catch", "using", "lock"}
    matches = [match for match in pattern.finditer(prefix) if match.group("name").casefold() not in controls]
    return str(matches[-1].group("name") if matches else "")


def infer_ipc_consumer_relationship(text: str, start: int, end: int) -> dict:
    """Conservatively classify required / feature / optional / unknown IPC relationships.

    This is static evidence, not a runtime guarantee. High-confidence `required` is deliberately
    restricted to explicit/fatal startup evidence so Omega does not turn every subscriber into a
    mandatory dependency. Feature/optional classifications prefer explicit availability guards.
    """
    left = text[max(0, start - 900):start]
    right = text[end:min(len(text), end + 1300)]
    local = left + text[start:end] + right
    lower = local.casefold()
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    method = _source_method_name_near(text, start)
    method_lower = method.casefold()
    startup_names = {"initialize", "initialise", "init", "load", "start", "startup", "enable", "onload", "onenable"}
    startup = method_lower in startup_names or method_lower.endswith("plugin")

    evidence: list[str] = []
    explicit_required = bool(re.search(r"\b(required|mandatory|must[- ]?have|hard dependency)\b", lower))
    explicit_optional = bool(re.search(r"\b(optional|soft dependency|best effort)\b", lower))
    fatal = bool(re.search(r"\?\?\s*throw\b|throw\s+new\b|throw\s*;", right[:650], re.IGNORECASE))
    availability_guard = bool(re.search(
        r"\b(isvalid|isavailable|available|installed|isinstalled|pluginexists|pluginloaded|ispluginloaded|tryget|tryinvoke)\b|\?\.\s*(?:invoke|invokeaction|invokefunc)",
        lower,
    ))
    feature_gate = bool(re.search(r"\b(config|configuration|feature|integration|enable|enabled|setting|option)\b", lower))
    early_exit = bool(re.search(r"\breturn\b|\bcontinue\b|\bbreak\b", right[:850], re.IGNORECASE))
    direct_invoke = bool(re.search(r"\.\s*(?:Invoke|InvokeAction|InvokeFunc)\w*\s*\(", line + right[:220], re.IGNORECASE))

    if explicit_required and (startup or fatal or direct_invoke):
        evidence.append("explicit required/mandatory dependency marker")
        if startup:
            evidence.append(f"startup path: {method or 'initialization'}")
        if fatal:
            evidence.append("missing provider leads to an exception")
        return {"relationship": "required", "confidence": "VeryHigh" if fatal else "High", "evidence": evidence[:6]}
    if startup and fatal:
        return {"relationship": "required", "confidence": "VeryHigh", "evidence": [f"startup path: {method or 'initialization'}", "missing provider leads to an exception"]}
    if startup and direct_invoke and not availability_guard:
        return {"relationship": "required", "confidence": "High", "evidence": [f"startup path: {method or 'initialization'}", "IPC is invoked directly without an observed availability guard"]}
    if explicit_optional:
        evidence.append("explicit optional/soft dependency marker")
        if availability_guard:
            evidence.append("provider availability is checked")
        return {"relationship": "optional", "confidence": "High", "evidence": evidence[:6]}
    if availability_guard and feature_gate:
        evidence.extend(["provider availability is checked", "IPC use is behind a feature/configuration gate"])
        if early_exit:
            evidence.append("missing provider exits only the guarded path")
        return {"relationship": "feature", "confidence": "High" if early_exit else "Medium", "evidence": evidence[:6]}
    if availability_guard:
        evidence.append("provider availability is checked before/around IPC use")
        if early_exit:
            evidence.append("missing provider can leave the guarded path without aborting plugin startup")
        return {"relationship": "optional", "confidence": "High" if early_exit else "Medium", "evidence": evidence[:6]}
    if startup:
        return {"relationship": "required", "confidence": "Medium", "evidence": [f"subscriber is acquired from startup-like path: {method or 'initialization'}"]}
    if feature_gate:
        return {"relationship": "feature", "confidence": "Medium", "evidence": ["IPC use appears in feature/integration/configuration context"]}
    return {"relationship": "unknown", "confidence": "Low", "evidence": ["subscriber observed without enough control-flow evidence to classify necessity"]}


def scan_source_text(path: str, raw: bytes, text: str, intel: dict, hits: dict[str, list[str]]) -> None:
    evidence_label = f"source:{path}" if intel["origin"] == "source" else f"artifact:{path}"
    add_rule_hits(text, evidence_label, hits, intel)
    add_external_path_hits(text, evidence_label, hits)
    add_network_endpoints(intel, text, evidence_label)
    _append_intel(intel, "sourceFiles", {"origin": intel["origin"], "path": path, "sha256": sha256_bytes(raw), "bytes": len(raw)}, ("origin", "path", "sha256"))

    using_re = re.compile(r"(?m)^\s*(?:global\s+)?using\s+(?:static\s+)?(?:(?:[A-Za-z_]\w*)\s*=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;")
    for match in using_re.finditer(text):
        add_import(intel, match.group(1), path)

    for service in DALAMUD_SERVICES:
        if re.search(rf"\b{re.escape(service)}\b", text):
            add_dalamud_service(intel, service, path)

    for match in re.finditer(r"\bDllImport(?:Attribute)?\s*\(\s*[\"']([^\"']+)[\"']", text):
        library = match.group(1).strip()
        _append_intel(intel, "nativeImports", {"origin": intel["origin"], "library": library, "path": path}, ("origin", "library", "path"))
        add_dependency(intel, "native-import", library, "", path, "not-analyzed", f"{path}: DllImport({library})")
        add_permission_candidate(intel, "native.interop", "High", "High", "A DllImport native library is declared.", f"{path}: {library}")

    # Dalamud deliberately exposes separate provider/subscriber APIs. Preserve that direction so
    # Omega can build provider -> consumer IPC edges instead of treating every channel reference
    # as an external dependency. Generic type text is evidence only; channel identity remains the
    # exact registration string used by Dalamud.
    ipc_re = re.compile(
        r"\bGetIpc(?P<role>Subscriber|Provider)\s*(?:<(?P<signature>[^()\n]{0,1024})>)?\s*\(\s*[\"'](?P<channel>[^\"']+)[\"']"
    )
    for match in ipc_re.finditer(text):
        channel = match.group("channel").strip()
        api_role = match.group("role")
        role = "provider" if api_role == "Provider" else "consumer"
        signature = re.sub(r"\s+", "", match.group("signature") or "")[:512]
        status = "provider-handle" if role == "provider" else "external-plugin"
        relationship = infer_ipc_consumer_relationship(text, match.start(), match.end()) if role == "consumer" else {
            "relationship": "", "confidence": "", "evidence": []
        }
        _append_intel(
            intel,
            "ipcIntegrations",
            {
                "origin": intel["origin"],
                "role": role,
                "channel": channel,
                "signature": signature,
                "path": path,
                "status": status,
                "relationship": relationship["relationship"],
                "relationshipConfidence": relationship["confidence"],
                "relationshipEvidence": relationship["evidence"],
            },
            ("origin", "role", "channel", "signature", "path"),
        )
        if role == "consumer":
            add_dependency(
                intel, "ipc", channel, "", path, "external-plugin", f"{path}: IPC subscriber {channel}", "soft",
                relationship=relationship["relationship"], relationship_confidence=relationship["confidence"],
                relationship_evidence=relationship["evidence"],
            )

    suffix = Path(path).suffix.lower()
    if suffix in PROJECT_XML_SUFFIXES:
        scan_project_xml(path, text, intel)
    if suffix == ".json":
        scan_dependency_json(path, text, intel)


def finalize_intelligence(intel: dict) -> dict:
    source_files = sorted(intel["sourceFiles"], key=lambda x: x["path"].lower())
    source_hash = hashlib.sha256()
    project_hash = hashlib.sha256()
    for item in source_files:
        source_hash.update(item["path"].encode("utf-8", "surrogatepass"))
        source_hash.update(b"\0")
        source_hash.update(item["sha256"].encode("ascii"))
        source_hash.update(b"\n")
        if Path(item["path"]).suffix.lower() in PROJECT_XML_SUFFIXES or Path(item["path"]).name.lower() in DEPENDENCY_JSON_NAMES:
            project_hash.update(item["path"].encode("utf-8", "surrogatepass"))
            project_hash.update(b"\0")
            project_hash.update(item["sha256"].encode("ascii"))
            project_hash.update(b"\n")
    intel["sourceFiles"] = source_files
    intel["networkEndpoints"].sort(key=lambda x: (x["host"], x["url"], x["origin"]))
    intel["imports"].sort(key=lambda x: (x["namespace"].lower(), x["path"].lower()))
    intel["dependencies"].sort(key=lambda x: (x.get("requirement", "observed"), x["kind"], x["name"].lower(), x["version"], x["path"].lower()))
    intel["dalamudServices"].sort(key=lambda x: (x["service"], x["path"].lower()))
    intel["ipcIntegrations"].sort(key=lambda x: (str(x.get("role") or "consumer"), x["channel"].lower(), x["path"].lower()))
    intel["nativeImports"].sort(key=lambda x: (x["library"].lower(), x["path"].lower()))
    intel["managedAssemblies"].sort(key=lambda x: (x["path"].lower(), x["assemblyName"].lower()))
    intel["managedSymbols"].sort(key=lambda x: (x["path"].lower(), x["kind"], x["declaringType"].lower(), x["name"].lower()))
    intel["managedCallSites"].sort(key=lambda x: (x["path"].lower(), x["sourceMethodToken"], int(x["ilOffset"]), x["opcode"], x["targetToken"]))
    intel["managedReachability"].sort(key=lambda x: (x["path"].lower(), x["rootMethodToken"], int(x["depth"]), x["methodToken"]))
    intel["permissionCandidates"].sort(key=lambda x: (x["permissionId"], x["confidence"], x["risk"]))
    intel["staticPatternMatches"].sort(key=lambda x: (str(x.get("pattern") or "").casefold(), str(x.get("origin") or ""), str(x.get("evidenceLabel") or "").casefold()))
    intel["componentSummary"] = build_component_summary(intel)
    coverage = {"total": len(intel["dependencies"]), "known": 0, "analyzed": 0, "notAnalyzed": 0, "binaryOnly": 0, "externalPlugin": 0, "dynamicallyDownloaded": 0,
                "requirements": {"required": 0, "soft": 0, "optional": 0, "bundled": 0, "observed": 0, "unknown": 0}}
    status_keys = {
        "known": "known",
        "analyzed": "analyzed",
        "not-analyzed": "notAnalyzed",
        "binary-only": "binaryOnly",
        "external-plugin": "externalPlugin",
        "dynamically-downloaded": "dynamicallyDownloaded",
    }
    for dependency in intel["dependencies"]:
        key = status_keys.get(str(dependency.get("status") or ""))
        if key:
            coverage[key] += 1
        requirement = str(dependency.get("requirement") or "observed")
        if requirement in coverage["requirements"]:
            coverage["requirements"][requirement] += 1
        else:
            coverage["requirements"]["unknown"] += 1
    intel["coverage"] = coverage
    intel["fingerprints"]["relevantSourceSha256"] = source_hash.hexdigest() if source_files else ""
    has_project_inputs = any(
        Path(item["path"]).suffix.lower() in PROJECT_XML_SUFFIXES or Path(item["path"]).name.lower() in DEPENDENCY_JSON_NAMES
        for item in source_files
    )
    intel["fingerprints"]["projectDependencySha256"] = project_hash.hexdigest() if has_project_inputs else ""
    intel.pop("_identityMaps", None)
    return intel


def normalized_archive_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return str(PurePosixPath(normalized)).casefold()


def archive_member_is_symlink(info: zipfile.ZipInfo) -> bool:
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    return (unix_mode & 0o170000) == 0o120000


def apply_binary_classification(intel: dict, classification: dict, hits: dict[str, list[str]]) -> None:
    """Project bounded native PE imports into existing dependency/rule evidence."""
    if str(classification.get("kind") or "") != "native-pe":
        return
    path = str(classification.get("path") or "artifact")
    for imported in classification.get("imports") or []:
        if not isinstance(imported, dict):
            continue
        library = str(imported.get("library") or "").strip()
        if not library:
            continue
        functions = [str(item or "").strip() for item in imported.get("functions") or [] if str(item or "").strip()]
        add_dependency(
            intel, "native-import", library, "", path, "analyzed",
            f"native-pe:{path}: import table {library}", "observed",
        )
        add_permission_candidate(
            intel, "native.interop", "High", "VeryHigh",
            "A bundled native PE has a statically parsed import table.", f"native-pe:{path}: {library}",
        )
        if not functions:
            _append_intel(
                intel, "nativeImports",
                {"origin": intel["origin"], "library": library, "path": path, "entryPoint": "", "managedName": ""},
                ("origin", "library", "path", "entryPoint"),
            )
            add_rule_hits(library, f"native-pe:{path}: import {library}", hits, intel)
            continue
        for function in functions:
            evidence = f"native-pe:{path}: import {library}!{function}"
            _append_intel(
                intel, "nativeImports",
                {"origin": intel["origin"], "library": library, "path": path, "entryPoint": function, "managedName": ""},
                ("origin", "library", "path", "entryPoint"),
            )
            add_rule_hits(f"{library} {function}", evidence, hits, intel)


def scan_archive(data: bytes, hits: dict[str, list[str]], intel: dict | None = None) -> dict:
    if intel is None:
        intel = empty_dependency_intelligence("artifact")
    metadata = {
        "archive": False,
        "files": 1,
        "uncompressedBytes": len(data),
        "bundledExecutables": [],
        "bundledManagedAssemblies": [],
        "bundledNativeLibraries": [],
        "binaryClassificationContractVersion": 2,
        "binaryClassifications": [],
        "binaryClassificationErrors": [],
        "managedMetadataErrors": [],
        "pluginManifests": [],
    }
    if not data.startswith(b"PK"):
        text = decoded_views(data[:MAX_ENTRY_SCAN_BYTES])
        add_rule_hits(text, "artifact", hits, intel)
        add_external_path_hits(text, "artifact", hits)
        # Binary URL strings are retained with low confidence rather than discarded.
        # Endpoint v2 explicitly records their origin, and certificate/source metadata
        # is filtered from concrete-destination findings later.
        if data.startswith((b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
            add_network_endpoints(intel, text, "artifact", origin_type="artifact-binary-string", confidence="Low")
        else:
            add_network_endpoints(intel, text, "artifact")
        if data.startswith((b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
            try:
                classification = classify_binary(data[:MAX_ENTRY_SCAN_BYTES], "artifact", sha256=sha256_bytes(data))
                metadata["binaryClassifications"].append(classification)
                apply_binary_classification(intel, classification, hits)
                if classification.get("role") == "library" and classification.get("kind") != "managed-pe":
                    metadata["bundledNativeLibraries"].append("artifact")
                elif classification.get("role") == "executable":
                    metadata["bundledExecutables"].append("artifact")
            except ValueError as exc:
                metadata["binaryClassificationErrors"].append({"path": "artifact", "error": str(exc)[:500]})
        if data.startswith(b"MZ"):
            if "artifact" not in metadata["bundledExecutables"] and not any(
                item.get("path") == "artifact" and item.get("role") == "library" for item in metadata["binaryClassifications"]
            ):
                metadata["bundledExecutables"].append("artifact")
            managed = None
            managed_error = ""
            try:
                managed = parse_managed_pe(data[:MAX_ENTRY_SCAN_BYTES], "artifact")
                if managed:
                    managed["sha256"] = sha256_bytes(data)
            except ValueError as exc:
                managed_error = str(exc)[:500]
                metadata["managedMetadataErrors"].append({"path": "artifact", "error": managed_error})
            if managed:
                metadata["bundledManagedAssemblies"].append("artifact")
                add_dependency(intel, "managed-executable", managed.get("assemblyName") or "artifact", managed.get("assemblyVersion") or "", "artifact", "analyzed", "standalone managed executable artifact", "bundled")
                apply_managed_metadata(intel, managed, hits)
            elif managed_error:
                record_managed_metadata_error(intel, "artifact", sha256_bytes(data), managed_error)
            else:
                add_dependency(intel, "executable", "artifact", "", "artifact", "binary-only", "standalone executable artifact", "bundled")
        return metadata

    metadata["archive"] = True
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Archive has {len(infos)} entries; limit is {MAX_ARCHIVE_ENTRIES}")
        seen_members: set[str] = set()
        for info in infos:
            if not safe_member_name(info.filename):
                raise ValueError(f"Unsafe archive path: {info.filename}")
            normalized_member = normalized_archive_member_name(info.filename)
            if normalized_member in seen_members:
                raise ValueError(f"Archive contains a duplicate normalized path: {info.filename}")
            seen_members.add(normalized_member)
            if archive_member_is_symlink(info):
                raise ValueError(f"Archive contains a symbolic-link entry: {info.filename}")
            if info.flag_bits & 0x1:
                raise ValueError(f"Encrypted archive entries are not scanned: {info.filename}")
        total = sum(max(0, info.file_size) for info in infos)
        if total > MAX_ARCHIVE_UNCOMPRESSED:
            raise ValueError("Archive exceeds uncompressed size limit")
        metadata["files"] = len(infos)
        metadata["uncompressedBytes"] = total
        for info in infos:
            if not safe_member_name(info.filename):
                raise ValueError(f"Unsafe archive path: {info.filename}")
            if info.file_size <= 0 or info.is_dir():
                continue
            if info.compress_size > 0 and info.file_size / info.compress_size > 500:
                raise ValueError(f"Suspicious compression ratio: {info.filename}")
            suffix = Path(info.filename).suffix.lower()
            if suffix not in BINARY_SUFFIXES | SOURCE_SUFFIXES:
                continue
            with archive.open(info) as stream:
                sample = stream.read(min(info.file_size, MAX_ENTRY_SCAN_BYTES))
                entry_hash = hashlib.sha256()
                entry_hash.update(sample)
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    entry_hash.update(chunk)
                entry_sha256 = entry_hash.hexdigest()

            classification = None
            if suffix in {".dll", ".exe", ".so", ".dylib"}:
                try:
                    classification = classify_binary(sample, info.filename, sha256=entry_sha256)
                    metadata["binaryClassifications"].append(classification)
                    apply_binary_classification(intel, classification, hits)
                except ValueError as exc:
                    metadata["binaryClassificationErrors"].append({"path": info.filename, "error": str(exc)[:500]})

            managed = None
            managed_error = ""
            if suffix in {".dll", ".exe"} and sample.startswith(b"MZ"):
                try:
                    managed = parse_managed_pe(sample, info.filename)
                    if managed:
                        managed["sha256"] = entry_sha256
                except ValueError as exc:
                    managed_error = str(exc)[:500]
                    metadata["managedMetadataErrors"].append({"path": info.filename, "error": managed_error})

            if suffix == ".exe":
                metadata["bundledExecutables"].append(info.filename)
                if managed:
                    metadata["bundledManagedAssemblies"].append(info.filename)
                    add_dependency(intel, "managed-executable", managed.get("assemblyName") or Path(info.filename).name, managed.get("assemblyVersion") or "", info.filename, "analyzed", f"metadata:{info.filename}: managed executable", "bundled", resolved_version=managed.get("assemblyVersion") or "")
                    apply_managed_metadata(intel, managed, hits)
                elif managed_error:
                    record_managed_metadata_error(intel, info.filename, entry_sha256, managed_error)
                else:
                    add_dependency(intel, "executable", Path(info.filename).name, "", info.filename, "binary-only", f"artifact:{info.filename}", "bundled")
            elif suffix in {".so", ".dylib"}:
                metadata["bundledNativeLibraries"].append(info.filename)
                add_dependency(intel, "native-library", Path(info.filename).name, "", info.filename, "binary-only", f"artifact:{info.filename}", "bundled")
                add_permission_candidate(intel, "native.interop", "High", "Medium", "A native library is bundled with the plugin artifact.", f"artifact:{info.filename}")
            elif suffix == ".dll":
                if managed:
                    metadata["bundledManagedAssemblies"].append(info.filename)
                    add_dependency(intel, "managed-assembly", managed.get("assemblyName") or Path(info.filename).name, managed.get("assemblyVersion") or "", info.filename, "analyzed", f"metadata:{info.filename}: CLR metadata parsed", "bundled", resolved_version=managed.get("assemblyVersion") or "")
                    apply_managed_metadata(intel, managed, hits)
                elif managed_error:
                    metadata["bundledManagedAssemblies"].append(info.filename)
                    record_managed_metadata_error(intel, info.filename, entry_sha256, managed_error)
                elif not info.filename.lower().endswith(".resources.dll"):
                    metadata["bundledNativeLibraries"].append(info.filename)
                    add_dependency(intel, "native-library", Path(info.filename).name, "", info.filename, "binary-only", f"artifact:{info.filename}", "bundled")
                    add_permission_candidate(intel, "native.interop", "High", "Medium", "A native library is bundled with the plugin artifact.", f"artifact:{info.filename}")

            if suffix in SOURCE_SUFFIXES:
                text = sample.decode("utf-8", "ignore")
                if suffix == ".json" and len(metadata["pluginManifests"]) < 32:
                    try:
                        manifest = json.loads(text)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        manifest = None
                    if isinstance(manifest, dict):
                        manifest_internal = str(manifest.get("InternalName") or manifest.get("internalName") or "").strip()
                        manifest_version = str(manifest.get("AssemblyVersion") or manifest.get("assemblyVersion") or manifest.get("TestingAssemblyVersion") or manifest.get("testingAssemblyVersion") or "").strip()
                        if manifest_internal and manifest_version:
                            metadata["pluginManifests"].append({
                                "path": info.filename,
                                "internalName": manifest_internal,
                                "assemblyVersion": manifest_version,
                                "repoUrl": str(manifest.get("RepoUrl") or manifest.get("repoUrl") or "").strip(),
                                "author": str(manifest.get("Author") or manifest.get("author") or "").strip(),
                            })
                scan_source_text(info.filename, sample, text, intel, hits)
            else:
                text = decoded_views(sample)
                add_rule_hits(text, f"artifact:{info.filename}", hits, intel)
                add_external_path_hits(text, f"artifact:{info.filename}", hits)
                # Preserve binary URL-shaped strings as low-confidence endpoint evidence.
                # Endpoint v2 keeps origin/confidence and filters certificate/source metadata
                # so these strings cannot masquerade as proven runtime destinations.
                add_network_endpoints(
                    intel, text, f"artifact:{info.filename}",
                    origin_type="artifact-binary-string", confidence="Low",
                )

    return metadata

def github_repo_parts(url: str) -> tuple[str, str] | None:
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return None
    parts = [x for x in parsed.path.split("/") if x]
    if len(parts) < 2:
        return None
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    return parts[0], repo


def _normalize_repo_path(base_dir: str, value: str) -> str:
    """Resolve an MSBuild-ish relative path without allowing it to escape the repository."""
    value = (value or "").strip().replace("\\", "/")
    if not value:
        return ""
    # Common MSBuild directory properties can be resolved safely for repository-local inputs.
    value = value.replace("$(MSBuildProjectDirectory)", base_dir or ".")
    value = value.replace("$(MSBuildThisFileDirectory)", (base_dir.rstrip("/") + "/") if base_dir else "")
    if "$(" in value:
        return ""
    resolved = posixpath.normpath(posixpath.join(base_dir, value))
    if resolved in {"", ".", ".."} or resolved.startswith("../"):
        return ""
    return resolved.lstrip("./")


def _xml_elements(text: str) -> list[ET.Element]:
    try:
        return list(ET.fromstring(text).iter())
    except ET.ParseError:
        return []


def _xml_tag_name(element: ET.Element) -> str:
    return str(element.tag).rsplit("}", 1)[-1]


def _project_references(project_path: str, text: str) -> list[str]:
    base_dir = str(PurePosixPath(project_path).parent)
    if base_dir == ".":
        base_dir = ""
    references: list[str] = []
    for element in _xml_elements(text):
        if _xml_tag_name(element) != "ProjectReference":
            continue
        target = _normalize_repo_path(base_dir, str(element.attrib.get("Include") or ""))
        if target and target.lower().endswith(".csproj") and target not in references:
            references.append(target)
    return references


def _project_identity_score(project_path: str, text: str, internal_name: str, plugin_name: str) -> tuple[int, list[str]]:
    """Score whether a project is the actual Dalamud plugin entry project.

    A repository can contain servers, websites and tooling beside the plugin.  Only
    projects with Dalamud/plugin build markers or a strong plugin identity match are
    eligible to become the critical source root.
    """
    lower = text.casefold()
    stem = PurePosixPath(project_path).stem
    normalized_stem = re.sub(r"[^a-z0-9]", "", stem.casefold())
    identities = [re.sub(r"[^a-z0-9]", "", x.casefold()) for x in (internal_name, plugin_name) if x]
    score = 0
    reasons: list[str] = []
    if "dalamud.net.sdk" in lower:
        score += 24
        reasons.append("Dalamud.NET.Sdk")
    if "dalamudpackager" in lower:
        score += 14
        reasons.append("DalamudPackager")
    if re.search(r"(?:package|reference)[^>]+(?:include|update)\s*=\s*[\"'][^\"']*dalamud", lower):
        score += 10
        reasons.append("Dalamud reference")
    if "ffxivclientstructs" in lower:
        score += 3
        reasons.append("FFXIVClientStructs")
    if "microsoft.net.sdk.web" in lower or "microsoft.aspnetcore" in lower:
        score -= 20
        reasons.append("web/server project")
    declared_identities = {
        re.sub(r"[^a-z0-9]", "", match.group(1).casefold())
        for match in re.finditer(r"<(?:AssemblyName|RootNamespace)>\s*([^<]+?)\s*</(?:AssemblyName|RootNamespace)>", text, re.IGNORECASE)
        if match.group(1).strip()
    }
    for identity in identities:
        if not identity:
            continue
        if normalized_stem == identity or identity in declared_identities:
            score += 16
            reasons.append("exact plugin identity")
            break
        if len(identity) >= 4 and (identity in normalized_stem or normalized_stem in identity):
            score += 8
            reasons.append("plugin identity match")
            break
    return score, reasons


def _solution_project_paths(solution_path: str, text: str) -> set[str]:
    base_dir = str(PurePosixPath(solution_path).parent)
    if base_dir == ".":
        base_dir = ""
    result: set[str] = set()
    for match in re.finditer(r'[\"\']([^\"\']+\.csproj)[\"\']', text, re.IGNORECASE):
        normalized = _normalize_repo_path(base_dir, match.group(1))
        if normalized:
            result.add(normalized)
    return result


def _path_under(path: str, root: str) -> bool:
    root = root.strip("/")
    path = path.strip("/")
    return not root or path == root or path.startswith(root + "/")


def _project_parent(project_path: str) -> str:
    parent = str(PurePosixPath(project_path).parent)
    return "" if parent == "." else parent.strip("/")


def _project_explicit_inputs(project_path: str, text: str, available_paths: set[str]) -> set[str]:
    """Resolve repository-local linked/imported source inputs from a project file."""
    base_dir = str(PurePosixPath(project_path).parent)
    if base_dir == ".":
        base_dir = ""
    selected: set[str] = set()
    eligible_tags = {"Compile", "Content", "None", "AdditionalFiles", "EmbeddedResource", "Import"}
    for element in _xml_elements(text):
        if _xml_tag_name(element) not in eligible_tags:
            continue
        include = str(element.attrib.get("Include") or element.attrib.get("Project") or "").strip()
        if not include:
            continue
        for candidate in include.split(";"):
            normalized = _normalize_repo_path(base_dir, candidate)
            if not normalized:
                continue
            if any(ch in normalized for ch in "*?["):
                pattern = normalized.casefold()
                for path in available_paths:
                    if fnmatch.fnmatchcase(path.casefold(), pattern):
                        selected.add(path)
            elif normalized in available_paths:
                selected.add(normalized)
    return selected


def select_plugin_source_scope(
    available_paths: set[str], descriptor_text: dict[str, str], internal_name: str = "", plugin_name: str = "",
) -> dict:
    """Select only source that can participate in the Dalamud plugin build graph.

    Sibling server/web/tool projects remain repository context. They are deliberately
    not allowed to contribute security findings, permission candidates, endpoint
    capabilities, dependency edges or automation classification for the plugin.
    """
    projects = sorted(path for path in available_paths if path.lower().endswith(".csproj"))
    solutions = sorted(path for path in available_paths if path.lower().endswith(".sln"))
    scores: list[tuple[int, str, list[str]]] = []
    for project in projects:
        score, reasons = _project_identity_score(project, descriptor_text.get(project, ""), internal_name, plugin_name)
        scores.append((score, project, reasons))
    scores.sort(key=lambda item: (-item[0], item[1].casefold()))

    primary = ""
    confidence = "none"
    source_identity_matched = False
    reason = "No confidently identifiable Dalamud plugin project was found; repository code is context-only."
    if scores:
        top_score, top_project, top_reasons = scores[0]
        second_score = scores[1][0] if len(scores) > 1 else -10_000
        strong_plugin_marker = any(x in top_reasons for x in ("Dalamud.NET.Sdk", "DalamudPackager", "Dalamud reference"))
        identity_match = any("plugin identity" in x for x in top_reasons)
        unambiguous = top_score > second_score or len(scores) == 1
        if unambiguous and ((strong_plugin_marker and top_score >= 10) or (identity_match and top_score >= 8)):
            primary = top_project
            source_identity_matched = identity_match
            confidence = "high" if strong_plugin_marker and identity_match else "medium"
            reason = "Selected the plugin entry project from Dalamud build markers and plugin identity."

    project_closure: set[str] = set()
    if primary:
        queue = deque([primary])
        while queue and len(project_closure) < 256:
            project = queue.popleft()
            if project in project_closure or project not in available_paths:
                continue
            project_closure.add(project)
            for reference in _project_references(project, descriptor_text.get(project, "")):
                if reference in available_paths and reference not in project_closure:
                    queue.append(reference)

    critical: set[str] = set(project_closure)
    project_roots = {_project_parent(path) for path in project_closure}
    all_project_roots = {path: _project_parent(path) for path in projects}
    excluded_project_roots = {root for project, root in all_project_roots.items() if project not in project_closure and root}

    if primary:
        for path in available_paths:
            if path in critical:
                continue
            if not any(_path_under(path, root) for root in project_roots):
                continue
            # A nested sibling project is a separate build unit unless the plugin references it.
            if any(_path_under(path, root) for root in excluded_project_roots):
                continue
            suffix = PurePosixPath(path).suffix.casefold()
            name = PurePosixPath(path).name.casefold()
            # SDK-style projects compile .cs beneath the project root by default.
            # Project/dependency declarations also affect the build. Repository scripts,
            # CI YAML, PowerShell and other operational files are context unless the
            # project explicitly Includes/Imports them below.
            if suffix not in {".cs", ".csproj", ".props", ".targets", ".json", ".config"} and name not in DEPENDENCY_JSON_NAMES:
                continue
            critical.add(path)

        for project in project_closure:
            critical.update(_project_explicit_inputs(project, descriptor_text.get(project, ""), available_paths))
            directory = str(PurePosixPath(project).parent)
            if directory == ".":
                directory = ""
            while True:
                for filename in ("Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props", "global.json", "NuGet.config"):
                    candidate = f"{directory}/{filename}".strip("/")
                    if candidate in available_paths:
                        critical.add(candidate)
                if not directory:
                    break
                directory = str(PurePosixPath(directory).parent)
                if directory == ".":
                    directory = ""

    relevant_solutions: list[str] = []
    if project_closure:
        for solution in solutions:
            members = _solution_project_paths(solution, descriptor_text.get(solution, ""))
            if members & project_closure:
                relevant_solutions.append(solution)

    context_projects = [path for path in projects if path not in project_closure]
    context_solutions = [path for path in solutions if path not in relevant_solutions]
    return {
        "schema": "omega.plugin-source-scope.v1",
        "mode": "plugin-build-graph" if primary else "repository-context-only",
        "confidence": confidence,
        "identityMatched": source_identity_matched,
        "primaryProject": primary,
        "projectFiles": sorted(project_closure, key=str.casefold),
        "solutionFiles": relevant_solutions,
        "contextProjects": context_projects[:128],
        "contextSolutions": context_solutions[:64],
        "criticalPaths": sorted(critical, key=str.casefold),
        "repositorySourceFiles": len(available_paths),
        "criticalSourceFiles": len(critical),
        "excludedSourceFiles": max(0, len(available_paths) - len(critical)),
        "reason": reason,
    }



def _source_ref_candidates(assembly_version: str, ref_hints: Iterable[str], default_branch: str) -> list[tuple[str, str]]:
    """Return deterministic Git refs, preferring immutable version tags."""
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(ref: str, kind: str) -> None:
        ref = str(ref or "").strip()
        key = ref.casefold()
        if not ref or key in seen or len(ref) > 256:
            return
        seen.add(key)
        ordered.append((ref, kind))

    version = str(assembly_version or "").strip()
    if version:
        add(version, "version-tag")
        if not version.casefold().startswith("v"):
            add(f"v{version}", "version-tag")
    for hint in ref_hints:
        add(str(hint or ""), "metadata-ref")
    add(default_branch, "default-branch")
    return ordered[:8]


def _source_manifest_match(
    paths: Iterable[str], read_file, internal_name: str, plugin_name: str, assembly_version: str,
) -> dict:
    """Find a bounded Dalamud manifest that ties a source tree to plugin identity/version."""
    internal = str(internal_name or "").strip().casefold()
    plugin = str(plugin_name or "").strip().casefold()
    version = str(assembly_version or "").strip().casefold()
    json_paths = [path for path in paths if Path(path).suffix.casefold() == ".json"]
    json_paths.sort(key=lambda path: (
        0 if internal and Path(path).stem.casefold() == internal else 1,
        0 if plugin and Path(path).stem.casefold() == plugin else 1,
        len(PurePosixPath(path).parts),
        path.casefold(),
    ))
    best = {
        "manifestPath": "", "internalName": "", "assemblyVersion": "", "repoUrl": "", "author": "",
        "identityMatched": False, "versionMatched": False,
    }
    best_score = -1
    for path in json_paths[:256]:
        try:
            raw = read_file(path)
            if not raw or len(raw) > MAX_TEXT_SOURCE_BYTES:
                continue
            doc = json.loads(raw.decode("utf-8-sig", "ignore"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError, UnicodeError):
            continue
        if not isinstance(doc, dict):
            continue
        manifest_internal = str(doc.get("InternalName") or doc.get("internalName") or "").strip()
        manifest_version = str(doc.get("AssemblyVersion") or doc.get("assemblyVersion") or "").strip()
        testing_version = str(doc.get("TestingAssemblyVersion") or doc.get("testingAssemblyVersion") or "").strip()
        name = str(doc.get("Name") or doc.get("name") or "").strip()
        if not manifest_internal and not manifest_version:
            continue
        identity_matched = bool(internal and manifest_internal.casefold() == internal)
        if not identity_matched and plugin and name:
            identity_matched = name.casefold() == plugin
        version_matched = bool(version and version in {manifest_version.casefold(), testing_version.casefold()})
        score = (4 if identity_matched else 0) + (4 if version_matched else 0)
        if score > best_score:
            best_score = score
            best = {
                "manifestPath": path,
                "internalName": manifest_internal,
                "assemblyVersion": manifest_version or testing_version,
                "repoUrl": str(doc.get("RepoUrl") or doc.get("repoUrl") or "").strip(),
                "author": str(doc.get("Author") or doc.get("author") or "").strip(),
                "identityMatched": identity_matched,
                "versionMatched": version_matched,
            }
        if identity_matched and (version_matched or not version):
            break
    return best


def _inspect_source_tree(
    source_entries: dict[str, int], read_file, hits: dict[str, list[str]], internal_name: str, plugin_name: str,
    assembly_version: str, *, analyze: bool = True,
) -> tuple[dict, dict, int, dict, dict]:
    """Inspect selected source blobs plus bounded developer profile metadata."""
    intel = empty_dependency_intelligence("source")
    descriptor_paths = [
        path for path in source_entries
        if Path(path).suffix.lower() in {".csproj", ".sln", ".props", ".targets"}
    ]
    identity_tokens = [
        re.sub(r"[^a-z0-9]+", "", value.casefold())
        for value in (internal_name, plugin_name)
        if str(value or "").strip()
    ]
    descriptor_paths.sort(key=lambda path: (
        0 if any(token and token in re.sub(r"[^a-z0-9]+", "", path.casefold()) for token in identity_tokens) else 1,
        len(PurePosixPath(path).parts),
        path.casefold(),
    ))
    descriptor_text: dict[str, str] = {}
    for path in descriptor_paths[:256]:
        raw = read_file(path)
        if raw:
            descriptor_text[path] = raw.decode("utf-8", "ignore")

    manifest = _source_manifest_match(source_entries, read_file, internal_name, plugin_name, assembly_version)
    scope = select_plugin_source_scope(set(source_entries), descriptor_text, internal_name, plugin_name)
    # `.omega/plugin.yaml` is developer-authored context, not scanner authority. It is
    # read independently of the plugin build graph because a monorepo profile may live
    # beside the primary project. Invalid enrichment is retained as diagnostics and
    # never prevents ordinary source analysis.
    developer_profile = observe_profile(set(source_entries), read_file, primary_project=str(scope.get("primaryProject") or ""))
    files_scanned = 0
    total_text = 0
    if analyze:
        for logical_name in sorted(scope["criticalPaths"], key=str.casefold):
            if files_scanned >= 500 or total_text >= MAX_SOURCE_TEXT_TOTAL:
                break
            if logical_name not in source_entries:
                continue
            # `.omega` is developer-provided explanation/profile data. Never feed it
            # back into independent source-code observations, otherwise a declared URL
            # or capability explanation could appear to prove itself.
            normalized_profile_path = logical_name.replace("\\", "/").casefold()
            if normalized_profile_path.endswith("/.omega/plugin.yaml") or normalized_profile_path in {".omega/plugin.yaml", ".omega/plugin.yml"}:
                continue
            raw = read_file(logical_name)
            if not raw:
                continue
            scan_source_text(logical_name, raw, raw.decode("utf-8", "ignore"), intel, hits)
            files_scanned += 1
            total_text += len(raw)
    finalize_intelligence(intel)
    return intel, scope, files_scanned, manifest, developer_profile


def _github_json(url: str, headers: dict[str, str], *, timeout: float = 20.0) -> dict:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub source API returned a non-object response")
    return payload


def _github_source_tree(api_url: str, tree_sha: str, headers: dict[str, str]) -> tuple[dict[str, int], dict[str, str], object, dict[str, int]]:
    tree = _github_json(f"{api_url}/git/trees/{urllib.parse.quote(tree_sha, safe='')}?recursive=1", headers)
    if bool(tree.get("truncated")):
        raise RuntimeError("GitHub source tree was truncated; refusing incomplete broad-tree attribution")
    records = tree.get("tree") if isinstance(tree.get("tree"), list) else []
    if len(records) > MAX_GIT_TREE_ENTRIES:
        raise RuntimeError(f"GitHub source tree exceeds hard limit {MAX_GIT_TREE_ENTRIES}")
    source_entries: dict[str, int] = {}
    blob_ids: dict[str, str] = {}
    for item in records:
        if not isinstance(item, dict) or str(item.get("type") or "") != "blob":
            continue
        path = str(item.get("path") or "")
        suffix = Path(path).suffix.lower()
        try:
            size = int(item.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        blob_sha = str(item.get("sha") or "").strip().lower()
        if suffix not in SOURCE_SUFFIXES or size <= 0 or size > MAX_TEXT_SOURCE_BYTES:
            continue
        if not safe_member_name(path) or len(blob_sha) != 40:
            continue
        source_entries[path] = size
        blob_ids[path] = blob_sha

    cache: dict[str, bytes] = {}
    stats = {"blobsRead": 0, "blobBytes": 0}
    def read_file(path: str) -> bytes:
        if path in cache:
            return cache[path]
        size = int(source_entries.get(path) or 0)
        blob_sha = blob_ids.get(path, "")
        if size <= 0 or size > MAX_TEXT_SOURCE_BYTES or not blob_sha:
            return b""
        payload = _github_json(f"{api_url}/git/blobs/{urllib.parse.quote(blob_sha, safe='')}", headers)
        if str(payload.get("encoding") or "").casefold() != "base64":
            raise RuntimeError(f"GitHub source blob has unsupported encoding: {path}")
        try:
            raw = base64.b64decode(str(payload.get("content") or ""), validate=False)
        except Exception as exc:
            raise RuntimeError(f"GitHub source blob could not be decoded: {path}") from exc
        if len(raw) != size or len(raw) > MAX_TEXT_SOURCE_BYTES:
            raise RuntimeError(f"GitHub source blob size mismatch: {path}")
        cache[path] = raw
        stats["blobsRead"] += 1
        stats["blobBytes"] += len(raw)
        return raw

    return source_entries, blob_ids, read_file, stats

def _fetch_source_candidate(
    repo_url: str, token: str, hits: dict[str, list[str]], internal_name: str = "", plugin_name: str = "",
    assembly_version: str = "", ref_hints: Iterable[str] = (), *, analyze: bool = True,
) -> dict:
    parts = github_repo_parts(repo_url)
    intel = empty_dependency_intelligence("source")
    if parts is None:
        return {
            "available": False, "repository": repo_url, "commit": "", "branch": "", "filesScanned": 0,
            "treeSha256": "", "dependencyIntelligence": finalize_intelligence(intel),
            "scope": {"schema": "omega.plugin-source-scope.v1", "mode": "unavailable", "confidence": "none", "primaryProject": "", "projectFiles": [], "solutionFiles": [], "contextProjects": [], "contextSolutions": [], "criticalPaths": [], "repositorySourceFiles": 0, "criticalSourceFiles": 0, "excludedSourceFiles": 0, "reason": "No supported source repository URL."},
            "provenance": {"schema": "omega.plugin-source-provenance.v1", "identityMatched": False, "versionMatched": False},
            "error": "No supported GitHub repository URL",
        }
    owner, repo = parts
    canonical_repo = f"https://github.com/{owner}/{repo}"
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(api_url, headers=headers)
    failures: list[str] = []
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            meta = json.load(response)
        default_branch = str(meta.get("default_branch") or "main")
        best: tuple[int, dict, dict[str, list[str]]] | None = None
        for ref, ref_kind in _source_ref_candidates(assembly_version, ref_hints, default_branch):
            ref_hits: dict[str, list[str]] = defaultdict(list)
            try:
                commit_req = urllib.request.Request(
                    f"{api_url}/commits/{urllib.parse.quote(ref, safe='')}", headers=headers,
                )
                with urllib.request.urlopen(commit_req, timeout=20) as response:
                    commit = json.load(response)
                sha = str(commit.get("sha") or "")
                tree_sha = str(((commit.get("commit") or {}).get("tree") or {}).get("sha") or "")
                if not sha or not tree_sha:
                    raise RuntimeError("GitHub commit response did not provide immutable commit/tree identity")
                source_entries, _blob_ids, read_file, retrieval_stats = _github_source_tree(api_url, tree_sha, headers)
                source_intel, scope, files_scanned, manifest, developer_profile = _inspect_source_tree(
                    source_entries, read_file, ref_hits, internal_name, plugin_name, assembly_version, analyze=analyze,
                )
                manifest_repo = github_repository_url(str(manifest.get("repoUrl") or ""))
                manifest_repo_matched = bool(manifest_repo and manifest_repo.casefold() == canonical_repo.casefold())
                provenance = {
                    "schema": "omega.plugin-source-provenance.v1",
                    "requestedAssemblyVersion": str(assembly_version or ""),
                    "selectedRef": ref,
                    "selectedRefKind": ref_kind,
                    "manifestPath": str(manifest.get("manifestPath") or ""),
                    "manifestInternalName": str(manifest.get("internalName") or ""),
                    "manifestAssemblyVersion": str(manifest.get("assemblyVersion") or ""),
                    "manifestRepoUrl": str(manifest.get("repoUrl") or ""),
                    "identityMatched": bool(manifest.get("identityMatched")) or bool(scope.get("identityMatched")),
                    "versionMatched": bool(manifest.get("versionMatched")),
                    "manifestRepositoryMatched": manifest_repo_matched,
                }
                result = {
                    "available": True,
                    "repository": canonical_repo,
                    "commit": sha,
                    "branch": ref,
                    "treeSha256": tree_sha,
                    "filesScanned": files_scanned,
                    "scope": scope,
                    "developerProfile": developer_profile,
                    "dependencyIntelligence": source_intel,
                    "retrieval": {
                        "schema": "omega.source-retrieval.v1", "mode": "github-tree-selected-blobs",
                        "treeEntries": len(source_entries), "blobsRead": int(retrieval_stats.get("blobsRead") or 0),
                        "blobBytes": int(retrieval_stats.get("blobBytes") or 0), "checkout": False,
                    },
                    "provenance": provenance,
                    "error": "",
                }
                score = (
                    (8 if provenance["identityMatched"] else 0) +
                    (8 if provenance["versionMatched"] else 0) +
                    (2 if provenance["manifestRepositoryMatched"] else 0) +
                    (1 if scope.get("mode") == "plugin-build-graph" else 0)
                )
                if best is None or score > best[0]:
                    best = (score, result, ref_hits)
                if provenance["identityMatched"] and (provenance["versionMatched"] or not assembly_version):
                    break
            except Exception as exc:
                failures.append(f"{ref}: {str(exc)[:220]}")
        if best is None:
            raise RuntimeError("; ".join(failures) or "No candidate Git ref could be inspected")
        _score, result, selected_hits = best
        for rule_id, evidence in selected_hits.items():
            for item in evidence:
                if item not in hits[rule_id]:
                    hits[rule_id].append(item)
        return result
    except Exception as exc:
        finalize_intelligence(intel)
        return {
            "available": False, "repository": repo_url, "commit": "", "branch": "", "treeSha256": "",
            "filesScanned": 0, "dependencyIntelligence": intel,
            "scope": {"schema": "omega.plugin-source-scope.v1", "mode": "unavailable", "confidence": "none", "primaryProject": "", "projectFiles": [], "solutionFiles": [], "contextProjects": [], "contextSolutions": [], "criticalPaths": [], "repositorySourceFiles": 0, "criticalSourceFiles": 0, "excludedSourceFiles": 0, "reason": "Source repository could not be inspected."},
            "provenance": {"schema": "omega.plugin-source-provenance.v1", "identityMatched": False, "versionMatched": False},
            "error": str(exc)[:1000],
        }


def _fetch_public_git_source_candidate(
    repo_url: str, _token: str, hits: dict[str, list[str]], internal_name: str = "", plugin_name: str = "",
    assembly_version: str = "", _ref_hints: Iterable[str] = (), *, analyze: bool = True,
) -> dict:
    """Inspect a public HTTPS Git remote through strict blobless partial retrieval."""
    intel = empty_dependency_intelligence("source")
    try:
        with PublicGitSource(repo_url) as repository:
            source_entries = {
                path: MAX_TEXT_SOURCE_BYTES for path in repository.files
                if Path(path).suffix.lower() in SOURCE_SUFFIXES
            }
            source_intel, scope, files_scanned, manifest, developer_profile = _inspect_source_tree(
                source_entries,
                lambda path: repository.read_file(path, MAX_TEXT_SOURCE_BYTES),
                hits,
                internal_name,
                plugin_name,
                assembly_version,
                analyze=analyze,
            )
            intel = source_intel
            retrieval = {
                "schema": "omega.source-retrieval.v1",
                "mode": "git-partial-blob-none",
                "treeEntries": len(repository.files),
                "blobsRead": int(getattr(repository, "blobs_read", 0) or 0),
                "blobBytes": int(getattr(repository, "blob_bytes", 0) or 0),
                "checkout": False,
            }
            return {
                "available": True, "repository": repository.repository, "commit": repository.commit, "branch": repository.branch,
                "treeSha256": repository.tree_sha, "filesScanned": files_scanned, "scope": scope,
                "developerProfile": developer_profile,
                "dependencyIntelligence": intel, "retrieval": retrieval,
                "provenance": {
                    "schema": "omega.plugin-source-provenance.v1",
                    "requestedAssemblyVersion": str(assembly_version or ""),
                    "selectedRef": repository.branch,
                    "selectedRefKind": "git-head",
                    "manifestPath": str(manifest.get("manifestPath") or ""),
                    "manifestInternalName": str(manifest.get("internalName") or ""),
                    "manifestAssemblyVersion": str(manifest.get("assemblyVersion") or ""),
                    "manifestRepoUrl": str(manifest.get("repoUrl") or ""),
                    "identityMatched": bool(manifest.get("identityMatched")) or bool(scope.get("identityMatched")),
                    "versionMatched": bool(manifest.get("versionMatched")),
                    "manifestRepositoryMatched": public_repository_url(str(manifest.get("repoUrl") or "")).casefold() == repository.repository.casefold() if manifest.get("repoUrl") else False,
                },
                "error": "",
            }
    except Exception as exc:
        finalize_intelligence(intel)
        return {
            "available": False, "repository": repo_url, "commit": "", "branch": "", "treeSha256": "", "filesScanned": 0,
            "dependencyIntelligence": intel,
            "scope": {"schema": "omega.plugin-source-scope.v1", "mode": "unavailable", "confidence": "none", "primaryProject": "", "projectFiles": [], "solutionFiles": [], "contextProjects": [], "contextSolutions": [], "criticalPaths": [], "repositorySourceFiles": 0, "criticalSourceFiles": 0, "excludedSourceFiles": 0, "reason": "Public Git source repository could not be inspected through safe partial retrieval."},
            "provenance": {"schema": "omega.plugin-source-provenance.v1", "identityMatched": False, "versionMatched": False},
            "retrieval": {"schema": "omega.source-retrieval.v1", "mode": "git-partial-blob-none", "checkout": False},
            "error": str(exc)[:500],
        }

def fetch_source(
    candidate_urls: list[object], token: str, hits: dict[str, list[str]], internal_name: str = "", plugin_name: str = "",
    assembly_version: str = "", artifact_url: str = "", resolved_artifact_url: str = "", *, analyze: bool = True,
) -> dict:
    """Try metadata-derived public Git repositories in deterministic priority order."""
    intel = empty_dependency_intelligence("source")
    normalized: list[dict[str, object]] = []
    for item in candidate_urls:
        if isinstance(item, dict):
            repository = str(item.get("repository") or "")
            if repository:
                normalized.append({
                    "repository": repository,
                    "origins": [str(value) for value in item.get("origins") or [] if str(value)],
                    "refHints": [str(value) for value in item.get("refHints") or [] if str(value)],
                    "urls": [str(value) for value in item.get("urls") or [] if str(value)],
                })
        else:
            repository = str(item or "")
            if repository:
                normalized.append({"repository": repository, "origins": [], "refHints": [], "urls": [repository]})
    if not normalized:
        return {
            "available": False, "repository": "", "commit": "", "branch": "", "treeSha256": "",
            "filesScanned": 0, "dependencyIntelligence": finalize_intelligence(intel),
            "scope": {"schema": "omega.plugin-source-scope.v1", "mode": "unavailable", "confidence": "none", "primaryProject": "", "projectFiles": [], "solutionFiles": [], "contextProjects": [], "contextSolutions": [], "criticalPaths": [], "repositorySourceFiles": 0, "criticalSourceFiles": 0, "excludedSourceFiles": 0, "reason": "No public source repository URL could be derived."},
            "provenance": {"schema": "omega.plugin-source-provenance.v1", "confidence": "none", "identityMatched": False, "versionMatched": False, "artifactOriginMatched": False},
            "candidates": [],
            "error": "No public source repository URL could be derived",
        }
    failures: list[str] = []
    last: dict | None = None
    repositories = [str(item["repository"]) for item in normalized]
    artifact_repositories = {
        github_repository_url(value).casefold()
        for value in (artifact_url, resolved_artifact_url)
        if github_repository_url(value)
    }
    for candidate in normalized:
        repository = str(candidate["repository"])
        candidate_hits: dict[str, list[str]] = defaultdict(list)
        fetcher = _fetch_source_candidate if github_repo_parts(repository) is not None else _fetch_public_git_source_candidate
        if internal_name or plugin_name or assembly_version:
            if analyze:
                result = fetcher(
                    repository, token, candidate_hits, internal_name, plugin_name, assembly_version, candidate.get("refHints") or [],
                )
            else:
                result = fetcher(
                    repository, token, candidate_hits, internal_name, plugin_name, assembly_version, candidate.get("refHints") or [], analyze=False,
                )
        else:
            result = fetcher(repository, token, candidate_hits) if analyze else fetcher(repository, token, candidate_hits, analyze=False)
        result["candidates"] = repositories
        if result["available"]:
            provenance = dict(result.get("provenance") or {})
            # A reachable repository is not automatically this plugin's source. When
            # plugin identity is known, continue through the candidate list until a
            # Dalamud manifest/source tree actually matches that identity. This lets
            # artifact-origin candidates recover from stale or incorrect RepoUrl data.
            if (internal_name or plugin_name) and not bool(provenance.get("identityMatched")):
                failures.append(f"{repository}: repository inspected but plugin identity did not match")
                last = result
                continue
            origins = [str(value) for value in candidate.get("origins") or [] if str(value)]
            artifact_origin_matched = repository.casefold() in artifact_repositories or any(origin.startswith("artifact-") for origin in origins)
            repo_url_matched = "repo-url" in origins or "override" in origins
            identity_matched = bool(provenance.get("identityMatched"))
            version_matched = bool(provenance.get("versionMatched"))
            if identity_matched and version_matched and artifact_origin_matched:
                confidence = "very-high"
            elif identity_matched and (artifact_origin_matched or repo_url_matched):
                confidence = "high"
            elif identity_matched or artifact_origin_matched or repo_url_matched:
                confidence = "medium"
            else:
                confidence = "low"
            selected_ref = str(provenance.get("selectedRef") or "").strip()
            artifact_pin = ""
            if (
                artifact_origin_matched
                and re.fullmatch(r"[0-9a-fA-F]{40}", selected_ref)
                and selected_ref.casefold() == str(result.get("commit") or "").strip().casefold()
            ):
                artifact_pin = str(result.get("commit") or "").strip().casefold()
            provenance.update({
                "schema": "omega.plugin-source-provenance.v1",
                "confidence": confidence,  # legacy display compatibility; machine logic uses source.attribution.confidence
                "discoveryOrigins": origins,
                "candidateUrls": [str(value) for value in candidate.get("urls") or [] if str(value)][:16],
                "artifactOriginMatched": artifact_origin_matched,
                "repoUrlMatched": repo_url_matched,
                "originMatched": artifact_origin_matched or repo_url_matched,
                "artifactPinnedCommit": artifact_pin,
                "reproducibleSourceToArtifact": False,
                "sourceToBinaryVerified": False,
            })
            result["provenance"] = provenance
            for rule_id, evidence in candidate_hits.items():
                for item in evidence:
                    if item not in hits[rule_id]:
                        hits[rule_id].append(item)
            return result
        failures.append(f"{repository}: {result.get('error') or 'unavailable'}")
        last = result
    assert last is not None
    last["candidates"] = repositories
    last["error"] = "; ".join(failures)[:1000]
    return last

def merge_dependency_intelligence(*items: dict) -> dict:
    combined = empty_dependency_intelligence("combined")
    combined["staticPatternMatchContractVersion"] = 0
    static_pattern_contract_versions: list[int] = []
    source_archives: list[str] = []
    relevant_hashes: list[str] = []
    project_hashes: list[str] = []
    for intel in items:
        if not isinstance(intel, dict):
            continue
        static_pattern_contract_versions.append(int(intel.get("staticPatternMatchContractVersion") or 0))
        for item in intel.get("imports") or []:
            _append_intel(combined, "imports", dict(item), ("origin", "namespace", "path"))
        for item in intel.get("dependencies") or []:
            _append_intel(combined, "dependencies", dict(item), ("origin", "kind", "name", "version", "path", "requirement"))
        for item in intel.get("dalamudServices") or []:
            _append_intel(combined, "dalamudServices", dict(item), ("origin", "service", "path"))
        for item in intel.get("ipcIntegrations") or []:
            _append_intel(combined, "ipcIntegrations", dict(item), ("origin", "role", "channel", "signature", "path"))
        for item in intel.get("nativeImports") or []:
            _append_intel(combined, "nativeImports", dict(item), ("origin", "library", "path"))
        for item in intel.get("managedAssemblies") or []:
            _append_intel(combined, "managedAssemblies", dict(item), ("origin", "path", "sha256"))
        for item in intel.get("managedSymbols") or []:
            _append_intel(combined, "managedSymbols", dict(item), ("origin", "path", "kind", "declaringType", "name", "assemblyName"))
        for item in intel.get("managedCallSites") or []:
            _append_intel(combined, "managedCallSites", dict(item), ("origin", "path", "sourceMethodToken", "ilOffset", "opcode", "targetToken"))
        for item in intel.get("managedReachability") or []:
            _append_intel(combined, "managedReachability", dict(item), ("origin", "path", "rootMethodToken", "methodToken"))
        for item in intel.get("permissionCandidates") or []:
            _append_intel(combined, "permissionCandidates", dict(item), ("origin", "permissionId", "risk", "confidence", "reason"))
        for item in intel.get("sourceFiles") or []:
            _append_intel(combined, "sourceFiles", dict(item), ("origin", "path", "sha256"))
        for item in intel.get("networkEndpoints") or []:
            _append_intel(combined, "networkEndpoints", dict(item), ("origin", "originType", "url"))
        for item in intel.get("staticPatternMatches") or []:
            _append_intel(combined, "staticPatternMatches", dict(item), ("origin", "pattern", "evidenceLabel"))
        fp = intel.get("fingerprints") or {}
        if fp.get("sourceArchiveSha256"):
            source_archives.append(str(fp["sourceArchiveSha256"]))
        if fp.get("relevantSourceSha256"):
            relevant_hashes.append(str(fp["relevantSourceSha256"]))
        if fp.get("projectDependencySha256"):
            project_hashes.append(str(fp["projectDependencySha256"]))
        source_limits = intel.get("limits") or {}
        if source_limits.get("truncated"):
            combined["limits"]["truncated"] = True
            for collection, count in (source_limits.get("droppedByCollection") or {}).items():
                dropped = combined["limits"]["droppedByCollection"]
                dropped[collection] = int(dropped.get(collection, 0)) + int(count or 0)
    finalize_intelligence(combined)
    combined["staticPatternMatchContractVersion"] = (
        1 if static_pattern_contract_versions and all(version == 1 for version in static_pattern_contract_versions) else 0
    )
    if source_archives:
        combined["fingerprints"]["sourceArchiveSha256"] = sha256_bytes("\n".join(sorted(source_archives)).encode())
    if relevant_hashes:
        combined["fingerprints"]["relevantSourceSha256"] = sha256_bytes("\n".join(sorted(relevant_hashes)).encode())
    if project_hashes:
        combined["fingerprints"]["projectDependencySha256"] = sha256_bytes("\n".join(sorted(project_hashes)).encode())
    return combined


def finding_payload(hits: dict[str, list[str]], archive_meta: dict) -> tuple[list[dict], list[str]]:
    by_id = {r.rule_id: r for r in RULES}
    findings: list[dict] = []
    capabilities: set[str] = set()
    for rule_id, evidence in hits.items():
        rule = by_id[rule_id]
        capabilities.add(rule.capability)
        findings.append({
            "ruleId": rule.rule_id,
            "severity": rule.severity,
            "category": rule.category,
            "title": rule.title,
            "description": rule.description,
            "evidence": evidence,
        })

    if archive_meta.get("bundledExecutables"):
        capabilities.add("Bundled executable")
        findings.append({"ruleId": "package.executable", "severity": "caution", "category": "package", "title": "Bundled executable", "description": "The plugin package contains one or more executable files.", "evidence": archive_meta["bundledExecutables"][:8]})
    native = archive_meta.get("bundledNativeLibraries") or []
    if native:
        capabilities.add("Bundled native libraries")
        findings.append({"ruleId": "package.native-library", "severity": "informational", "category": "package", "title": "Bundled native libraries", "description": "The plugin package contains native-library payloads in addition to managed plugin files.", "evidence": native[:8]})

    wx_evidence: list[str] = []
    for classification in archive_meta.get("binaryClassifications") or []:
        if not isinstance(classification, dict) or str(classification.get("kind") or "") != "native-pe":
            continue
        path = str(classification.get("path") or "artifact")
        for section in classification.get("writableExecutableSections") or []:
            wx_evidence.append(f"{path}: {section}")
            if len(wx_evidence) >= 8:
                break
        if len(wx_evidence) >= 8:
            break
    if wx_evidence:
        capabilities.add("Writable+executable native section")
        findings.append({
            "ruleId": "native.pe.writable-executable-section", "severity": "caution", "category": "native",
            "title": "Writable and executable PE section",
            "description": "A bundled native PE contains a section marked both writable and executable. This is a structural static signal and is not by itself evidence of malicious behavior.",
            "evidence": wx_evidence,
        })

    rule_ids = {f["ruleId"] for f in findings}
    if "network.http" in rule_ids and ("process.launch" in rule_ids or "shell.powershell" in rule_ids):
        capabilities.add("Download/execute potential")
        findings.append({"ruleId": "compound.network-execute", "severity": "high", "category": "compound", "title": "Network plus process execution", "description": "The artifact references both network access and process/shell execution. This combination can download and execute external content; manual review is recommended.", "evidence": []})
    if "credential.api" in rule_ids and ("network.http" in rule_ids or "network.socket" in rule_ids):
        findings.append({"ruleId": "compound.credential-network", "severity": "high", "category": "compound", "title": "Credential APIs plus network access", "description": "The artifact references credential/protected-data APIs and network APIs. This is not proof of credential collection, but it warrants manual review.", "evidence": []})

    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["ruleId"]))
    return findings, sorted(capabilities, key=str.lower)


AUTOMATION_LEVEL_RANK = {
    "none": 0,
    "observational": 1,
    "ui-automation": 2,
    "character-automation": 3,
    "full-gameplay-automation": 4,
}


def _automation_rule_matches(rule: AutomationCallRule, call: dict) -> bool:
    declaring = str(call.get("targetDeclaringType") or "")
    name = str(call.get("targetName") or "")
    native = str(call.get("targetNativeEntryPoint") or "")
    if rule.native_entries and any(native.casefold() == item.casefold() for item in rule.native_entries):
        return True
    if not rule.type_patterns:
        return False
    if not any(pattern.casefold() in declaring.casefold() for pattern in rule.type_patterns):
        return False
    if not rule.member_names:
        return True
    for expected in rule.member_names:
        if expected.endswith("_") and name.startswith(expected):
            return True
        if expected == "set_" and name.startswith("set_"):
            return True
        if name.casefold() == expected.casefold():
            return True
    return False


def derive_automation_capabilities(intel: dict) -> dict:
    """Produce bounded, user-facing automation capability evidence from detailed static analysis."""
    reachable_tokens = {
        str(item.get("methodToken") or "")
        for item in intel.get("managedReachability") or []
        if str(item.get("methodToken") or "")
    }
    aggregated: dict[str, dict] = {}

    def add(capability_id: str, label: str, level: str, confidence: str, reachable: bool, indirect: bool, reason: str, evidence: str) -> None:
        item = aggregated.setdefault(capability_id, {
            "capabilityId": capability_id,
            "label": label,
            "automationLevel": level,
            "confidence": confidence,
            "reachable": reachable,
            "indirect": indirect,
            "reason": reason,
            "evidence": [],
        })
        if AUTOMATION_LEVEL_RANK.get(level, 0) > AUTOMATION_LEVEL_RANK.get(str(item.get("automationLevel") or "none"), 0):
            item["automationLevel"] = level
        confidence_rank = {"low": 0, "medium": 1, "high": 2, "very-high": 3}
        if confidence_rank.get(confidence, 0) > confidence_rank.get(str(item.get("confidence") or "low"), 0):
            item["confidence"] = confidence
        item["reachable"] = bool(item.get("reachable")) or reachable
        item["indirect"] = bool(item.get("indirect")) or indirect
        if evidence and evidence not in item["evidence"] and len(item["evidence"]) < 8:
            item["evidence"].append(evidence)

    for call in intel.get("managedCallSites") or []:
        source_token = str(call.get("sourceMethodToken") or "")
        reachable = bool(source_token and source_token in reachable_tokens)
        for rule in AUTOMATION_CALL_RULES:
            if not _automation_rule_matches(rule, call):
                continue
            confidence = "very-high" if reachable else "high"
            evidence_items = call.get("evidence") or []
            evidence = str(evidence_items[0]) if evidence_items else (
                f"IL call: {call.get('targetDeclaringType','')}.{call.get('targetName','')}"
            )
            add(rule.capability_id, rule.label, rule.automation_level, confidence, reachable, False, rule.description, evidence)

    for ipc in intel.get("ipcIntegrations") or []:
        # Provider declarations expose capability to other plugins; they are not evidence that this
        # plugin consumes another plugin's automation. Legacy rows without a role are consumer-like.
        if str(ipc.get("role") or "consumer").casefold() == "provider":
            continue
        channel = str(ipc.get("channel") or "")
        lowered = channel.casefold()
        for patterns, hints in IPC_AUTOMATION_HINTS:
            if not any(pattern in lowered for pattern in patterns):
                continue
            for capability_id, label, level in hints:
                add(
                    capability_id, label, level, "medium", False, True,
                    "References an IPC channel associated with an external automation provider; this is indirect capability evidence.",
                    f"IPC channel: {channel}",
                )
            add(
                "automation.via_ipc", "Indirect automation via IPC", level, "medium", False, True,
                "Uses an IPC integration associated with automation functionality supplied by another plugin.",
                f"IPC channel: {channel}",
            )

    capabilities = sorted(aggregated.values(), key=lambda item: (item["capabilityId"], item["label"]))
    level = "none"
    for item in capabilities:
        candidate = str(item.get("automationLevel") or "none")
        if AUTOMATION_LEVEL_RANK.get(candidate, 0) > AUTOMATION_LEVEL_RANK.get(level, 0):
            level = candidate
    if level == "none" and (
        intel.get("dalamudServices") or intel.get("managedAssemblies") or intel.get("managedSymbols")
    ):
        level = "observational"

    findings = []
    for item in capabilities:
        severity = "caution"
        if item["automationLevel"] == "full-gameplay-automation":
            severity = "high"
        reachability = " A call path from a plugin lifecycle/callback root was found." if item["reachable"] else ""
        indirect = " This capability is provided indirectly through IPC." if item["indirect"] else ""
        findings.append({
            "ruleId": f"automation.{item['capabilityId']}",
            "severity": severity,
            "category": "automation",
            "title": item["label"],
            "description": (
                f"Static analysis found capability evidence for {item['label'].lower()}. "
                f"This does not prove that the behavior executes during normal use.{reachability}{indirect}"
            ).strip(),
            "evidence": list(item["evidence"])[:4],
        })
    return {
        "level": level,
        "capabilities": capabilities,
        "findings": findings,
    }


def ensure_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS artifact_blobs (
        artifact_sha256 TEXT PRIMARY KEY,
        package_bytes INTEGER NOT NULL DEFAULT 0,
        first_seen_utc TEXT NOT NULL DEFAULT '',
        last_seen_utc TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS source_repositories (
        repository_key TEXT PRIMARY KEY,
        canonical_url TEXT NOT NULL UNIQUE COLLATE NOCASE,
        first_seen_utc TEXT NOT NULL DEFAULT '',
        last_seen_utc TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS source_revisions (
        source_revision_key TEXT PRIMARY KEY,
        repository_key TEXT NOT NULL REFERENCES source_repositories(repository_key) ON DELETE CASCADE,
        commit_sha TEXT NOT NULL,
        observed_ref TEXT NOT NULL DEFAULT '',
        observed_at_utc TEXT NOT NULL DEFAULT '',
        UNIQUE(repository_key, commit_sha)
    );
    CREATE INDEX IF NOT EXISTS ix_source_revisions_repository ON source_revisions(repository_key,commit_sha);

    CREATE TABLE IF NOT EXISTS artifact_source_attributions (
        attribution_key TEXT PRIMARY KEY,
        variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        artifact_sha256 TEXT NOT NULL REFERENCES artifact_blobs(artifact_sha256) ON DELETE CASCADE,
        source_revision_key TEXT NOT NULL DEFAULT '',
        source_root_path TEXT NOT NULL DEFAULT '',
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence IN (0,40,70,95,100)),
        basis_json TEXT NOT NULL DEFAULT '[]',
        coverage_label TEXT NOT NULL DEFAULT 'Unresolved',
        observed_at_utc TEXT NOT NULL DEFAULT '',
        active INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS ix_artifact_source_attributions_variant ON artifact_source_attributions(variant_id,active);
    CREATE INDEX IF NOT EXISTS ix_artifact_source_attributions_hash ON artifact_source_attributions(artifact_sha256,confidence DESC);

    CREATE TABLE IF NOT EXISTS artifact_analyses (
        artifact_sha256 TEXT NOT NULL REFERENCES artifact_blobs(artifact_sha256) ON DELETE CASCADE,
        scanner_version TEXT NOT NULL,
        definitions_revision TEXT NOT NULL DEFAULT '',
        catalog_definitions_revision TEXT NOT NULL DEFAULT '',
        representative_scan_id INTEGER REFERENCES plugin_security_scans(scan_id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT '',
        analyzed_at_utc TEXT NOT NULL DEFAULT '',
        last_used_at_utc TEXT NOT NULL DEFAULT '',
        reuse_count INTEGER NOT NULL DEFAULT 0,
        analysis_payload_json TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY(artifact_sha256,scanner_version,definitions_revision)
    );

    CREATE TABLE IF NOT EXISTS source_analyses (
        source_revision_key TEXT NOT NULL,
        source_root_path TEXT NOT NULL DEFAULT '',
        scanner_version TEXT NOT NULL,
        definitions_revision TEXT NOT NULL DEFAULT '',
        representative_scan_id INTEGER REFERENCES plugin_security_scans(scan_id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT '',
        analyzed_at_utc TEXT NOT NULL DEFAULT '',
        last_used_at_utc TEXT NOT NULL DEFAULT '',
        reuse_count INTEGER NOT NULL DEFAULT 0,
        analysis_payload_json TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY(source_revision_key,source_root_path,scanner_version,definitions_revision)
    );

    CREATE TABLE IF NOT EXISTS plugin_security_scans (
        scan_id INTEGER PRIMARY KEY,
        plugin_id INTEGER NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
        variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        source_id INTEGER NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
        assembly_version TEXT NOT NULL DEFAULT '',
        artifact_channel TEXT NOT NULL DEFAULT 'stable',
        artifact_url TEXT NOT NULL DEFAULT '',
        artifact_sha256 TEXT NOT NULL DEFAULT '',
        scanner_version TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        scanned_at_utc TEXT NOT NULL DEFAULT '',
        highest_severity TEXT NOT NULL DEFAULT 'none',
        informational_count INTEGER NOT NULL DEFAULT 0,
        caution_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        capabilities_json TEXT NOT NULL DEFAULT '[]',
        source_available INTEGER NOT NULL DEFAULT 0,
        source_repository TEXT NOT NULL DEFAULT '',
        source_commit TEXT NOT NULL DEFAULT '',
        source_to_binary_verified INTEGER NOT NULL DEFAULT 0,
        report_json TEXT NOT NULL DEFAULT '{}',
        error TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_scans_variant ON plugin_security_scans(variant_id, scanned_at_utc DESC);
    CREATE INDEX IF NOT EXISTS ix_security_scans_hash ON plugin_security_scans(artifact_sha256);

    CREATE TABLE IF NOT EXISTS plugin_security_findings (
        finding_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_findings_scan ON plugin_security_findings(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_findings_severity ON plugin_security_findings(severity);

    CREATE TABLE IF NOT EXISTS plugin_security_dependencies (
        dependency_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL DEFAULT '',
        version TEXT NOT NULL DEFAULT '',
        version_requirement TEXT NOT NULL DEFAULT '',
        resolved_version TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        requirement TEXT NOT NULL DEFAULT 'observed',
        evidence_json TEXT NOT NULL DEFAULT '[]',
        relationship TEXT NOT NULL DEFAULT '',
        relationship_confidence TEXT NOT NULL DEFAULT '',
        relationship_evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_dependencies_scan ON plugin_security_dependencies(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_dependencies_name ON plugin_security_dependencies(name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_dependencies_kind ON plugin_security_dependencies(kind);

    CREATE TABLE IF NOT EXISTS plugin_security_ipc_endpoints (
        ipc_endpoint_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'consumer',
        channel TEXT NOT NULL DEFAULT '',
        signature TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        relationship TEXT NOT NULL DEFAULT '',
        relationship_confidence TEXT NOT NULL DEFAULT '',
        relationship_evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_ipc_endpoints_scan ON plugin_security_ipc_endpoints(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_ipc_endpoints_channel ON plugin_security_ipc_endpoints(channel);
    CREATE INDEX IF NOT EXISTS ix_security_ipc_endpoints_role ON plugin_security_ipc_endpoints(role);

    CREATE TABLE IF NOT EXISTS plugin_security_ipc_registry (
        channel TEXT NOT NULL,
        provider_plugin_id INTEGER NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
        provider_variant_id INTEGER REFERENCES plugin_variants(variant_id) ON DELETE SET NULL,
        provider_internal_name TEXT NOT NULL DEFAULT '',
        provider_variant_count INTEGER NOT NULL DEFAULT 0,
        provider_scan_id INTEGER REFERENCES plugin_security_scans(scan_id) ON DELETE SET NULL,
        provider_signature TEXT NOT NULL DEFAULT '',
        provider_origin TEXT NOT NULL DEFAULT '',
        provider_path TEXT NOT NULL DEFAULT '',
        provider_registration_count INTEGER NOT NULL DEFAULT 1,
        refreshed_at_utc TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(channel, provider_plugin_id)
    );
    CREATE INDEX IF NOT EXISTS ix_security_ipc_registry_provider ON plugin_security_ipc_registry(provider_plugin_id);

    CREATE TABLE IF NOT EXISTS plugin_security_imports (
        import_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        namespace TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_imports_scan ON plugin_security_imports(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_imports_namespace ON plugin_security_imports(namespace COLLATE NOCASE);

    CREATE TABLE IF NOT EXISTS plugin_security_managed_assemblies (
        managed_assembly_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        sha256 TEXT NOT NULL DEFAULT '',
        assembly_name TEXT NOT NULL DEFAULT '',
        assembly_version TEXT NOT NULL DEFAULT '',
        metadata_version TEXT NOT NULL DEFAULT '',
        parse_status TEXT NOT NULL DEFAULT '',
        reference_count INTEGER NOT NULL DEFAULT 0,
        type_reference_count INTEGER NOT NULL DEFAULT 0,
        member_reference_count INTEGER NOT NULL DEFAULT 0,
        native_import_count INTEGER NOT NULL DEFAULT 0,
        truncated INTEGER NOT NULL DEFAULT 0,
        error TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_managed_assemblies_scan ON plugin_security_managed_assemblies(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_managed_assemblies_name ON plugin_security_managed_assemblies(assembly_name COLLATE NOCASE);

    CREATE TABLE IF NOT EXISTS plugin_security_managed_symbols (
        managed_symbol_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        symbol_kind TEXT NOT NULL DEFAULT '',
        declaring_type TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL DEFAULT '',
        assembly_name TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_managed_symbols_scan ON plugin_security_managed_symbols(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_managed_symbols_name ON plugin_security_managed_symbols(name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_managed_symbols_declaring_type ON plugin_security_managed_symbols(declaring_type COLLATE NOCASE);

    CREATE TABLE IF NOT EXISTS plugin_security_managed_calls (
        managed_call_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        source_method_token TEXT NOT NULL DEFAULT '',
        source_declaring_type TEXT NOT NULL DEFAULT '',
        source_method_name TEXT NOT NULL DEFAULT '',
        il_offset INTEGER NOT NULL DEFAULT 0,
        opcode TEXT NOT NULL DEFAULT '',
        target_token TEXT NOT NULL DEFAULT '',
        target_kind TEXT NOT NULL DEFAULT '',
        target_declaring_type TEXT NOT NULL DEFAULT '',
        target_name TEXT NOT NULL DEFAULT '',
        target_assembly_name TEXT NOT NULL DEFAULT '',
        target_native_library TEXT NOT NULL DEFAULT '',
        target_native_entry_point TEXT NOT NULL DEFAULT '',
        target_method_token TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_managed_calls_scan ON plugin_security_managed_calls(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_managed_calls_target ON plugin_security_managed_calls(target_declaring_type COLLATE NOCASE, target_name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_managed_calls_native ON plugin_security_managed_calls(target_native_library COLLATE NOCASE);

    CREATE TABLE IF NOT EXISTS plugin_security_managed_reachability (
        reachability_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        root_method_token TEXT NOT NULL DEFAULT '',
        root_declaring_type TEXT NOT NULL DEFAULT '',
        root_method_name TEXT NOT NULL DEFAULT '',
        root_kind TEXT NOT NULL DEFAULT '',
        root_confidence TEXT NOT NULL DEFAULT '',
        method_token TEXT NOT NULL DEFAULT '',
        method_declaring_type TEXT NOT NULL DEFAULT '',
        method_name TEXT NOT NULL DEFAULT '',
        depth INTEGER NOT NULL DEFAULT 0,
        via_method_token TEXT NOT NULL DEFAULT '',
        via_il_offset INTEGER NOT NULL DEFAULT -1,
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_reachability_scan ON plugin_security_managed_reachability(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_reachability_method ON plugin_security_managed_reachability(method_token);
    CREATE INDEX IF NOT EXISTS ix_security_reachability_root ON plugin_security_managed_reachability(root_method_token);

    CREATE TABLE IF NOT EXISTS plugin_security_dependency_resolutions (
        dependency_id INTEGER PRIMARY KEY REFERENCES plugin_security_dependencies(dependency_id) ON DELETE CASCADE,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        source_plugin_id INTEGER NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
        source_variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        dependency_kind TEXT NOT NULL DEFAULT '',
        dependency_name TEXT NOT NULL DEFAULT '',
        dependency_version TEXT NOT NULL DEFAULT '',
        version_requirement TEXT NOT NULL DEFAULT '',
        resolved_version TEXT NOT NULL DEFAULT '',
        normalized_name TEXT NOT NULL DEFAULT '',
        component_key TEXT NOT NULL DEFAULT '',
        requirement TEXT NOT NULL DEFAULT 'observed',
        relationship TEXT NOT NULL DEFAULT '',
        relationship_confidence TEXT NOT NULL DEFAULT '',
        relationship_evidence_json TEXT NOT NULL DEFAULT '[]',
        resolution_status TEXT NOT NULL DEFAULT '',
        version_status TEXT NOT NULL DEFAULT '',
        target_plugin_id INTEGER REFERENCES plugins(plugin_id) ON DELETE SET NULL,
        target_variant_id INTEGER REFERENCES plugin_variants(variant_id) ON DELETE SET NULL,
        target_internal_name TEXT NOT NULL DEFAULT '',
        target_variant_count INTEGER NOT NULL DEFAULT 0,
        target_version TEXT NOT NULL DEFAULT '',
        confidence TEXT NOT NULL DEFAULT '',
        match_basis TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_dependency_resolutions_scan ON plugin_security_dependency_resolutions(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_resolutions_target_plugin ON plugin_security_dependency_resolutions(target_plugin_id);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_resolutions_component ON plugin_security_dependency_resolutions(component_key COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_resolutions_status ON plugin_security_dependency_resolutions(resolution_status);

    CREATE TABLE IF NOT EXISTS plugin_security_dependency_components (
        component_key TEXT PRIMARY KEY COLLATE NOCASE,
        component_kind TEXT NOT NULL DEFAULT '',
        display_name TEXT NOT NULL DEFAULT '',
        normalized_name TEXT NOT NULL DEFAULT '',
        current_usage_count INTEGER NOT NULL DEFAULT 0,
        source_plugin_count INTEGER NOT NULL DEFAULT 0,
        source_variant_count INTEGER NOT NULL DEFAULT 0,
        required_count INTEGER NOT NULL DEFAULT 0,
        soft_count INTEGER NOT NULL DEFAULT 0,
        optional_count INTEGER NOT NULL DEFAULT 0,
        bundled_count INTEGER NOT NULL DEFAULT 0,
        observed_count INTEGER NOT NULL DEFAULT 0,
        unknown_count INTEGER NOT NULL DEFAULT 0,
        versions_json TEXT NOT NULL DEFAULT '[]',
        distinct_version_count INTEGER NOT NULL DEFAULT 0,
        version_divergence TEXT NOT NULL DEFAULT 'none',
        refreshed_at_utc TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_dependency_components_name ON plugin_security_dependency_components(normalized_name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_components_kind ON plugin_security_dependency_components(component_kind);

    CREATE TABLE IF NOT EXISTS plugin_security_dependency_issues (
        issue_id INTEGER PRIMARY KEY,
        dependency_id INTEGER REFERENCES plugin_security_dependencies(dependency_id) ON DELETE CASCADE,
        scan_id INTEGER REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        source_plugin_id INTEGER REFERENCES plugins(plugin_id) ON DELETE CASCADE,
        source_variant_id INTEGER REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        component_key TEXT NOT NULL DEFAULT '',
        issue_code TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT 'informational',
        title TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        requirement TEXT NOT NULL DEFAULT '',
        version_requirement TEXT NOT NULL DEFAULT '',
        observed_version TEXT NOT NULL DEFAULT '',
        target_version TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '[]',
        refreshed_at_utc TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_dependency_issues_dependency ON plugin_security_dependency_issues(dependency_id);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_issues_component ON plugin_security_dependency_issues(component_key COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_issues_code ON plugin_security_dependency_issues(issue_code);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_issues_severity ON plugin_security_dependency_issues(severity);

    CREATE TABLE IF NOT EXISTS plugin_security_dependency_advisory_matches (
        advisory_match_id INTEGER PRIMARY KEY,
        advisory_id TEXT NOT NULL DEFAULT '',
        component_key TEXT NOT NULL DEFAULT '',
        component_kind TEXT NOT NULL DEFAULT '',
        component_name TEXT NOT NULL DEFAULT '',
        affected_version TEXT NOT NULL DEFAULT '',
        affected_range TEXT NOT NULL DEFAULT '',
        fixed_version TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT '',
        title TEXT NOT NULL DEFAULT '',
        advisory_url TEXT NOT NULL DEFAULT '',
        advisory_source TEXT NOT NULL DEFAULT '',
        refreshed_at_utc TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_advisory_matches_component ON plugin_security_dependency_advisory_matches(component_key COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_advisory_matches_advisory ON plugin_security_dependency_advisory_matches(advisory_id);

    CREATE TABLE IF NOT EXISTS plugin_security_scan_lineage (
        current_scan_id INTEGER PRIMARY KEY REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        previous_scan_id INTEGER REFERENCES plugin_security_scans(scan_id) ON DELETE SET NULL,
        variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        previous_artifact_sha256 TEXT NOT NULL DEFAULT '',
        current_artifact_sha256 TEXT NOT NULL DEFAULT '',
        previous_source_commit TEXT NOT NULL DEFAULT '',
        current_source_commit TEXT NOT NULL DEFAULT '',
        previous_assembly_version TEXT NOT NULL DEFAULT '',
        current_assembly_version TEXT NOT NULL DEFAULT '',
        previous_scanner_version TEXT NOT NULL DEFAULT '',
        current_scanner_version TEXT NOT NULL DEFAULT '',
        artifact_changed INTEGER NOT NULL DEFAULT 0,
        source_changed INTEGER NOT NULL DEFAULT 0,
        assembly_version_changed INTEGER NOT NULL DEFAULT 0,
        scanner_changed INTEGER NOT NULL DEFAULT 0,
        change_basis TEXT NOT NULL DEFAULT 'baseline',
        detected_at_utc TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_scan_lineage_previous ON plugin_security_scan_lineage(previous_scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_scan_lineage_variant ON plugin_security_scan_lineage(variant_id,current_scan_id);

    CREATE TABLE IF NOT EXISTS plugin_security_dependency_drift (
        drift_id INTEGER PRIMARY KEY,
        variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        previous_scan_id INTEGER REFERENCES plugin_security_scans(scan_id) ON DELETE SET NULL,
        current_scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        change_scope TEXT NOT NULL DEFAULT 'dependency',
        change_type TEXT NOT NULL DEFAULT '',
        change_basis TEXT NOT NULL DEFAULT '',
        origin TEXT NOT NULL DEFAULT '',
        component_key TEXT NOT NULL DEFAULT '',
        dependency_kind TEXT NOT NULL DEFAULT '',
        dependency_name TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT 'informational',
        previous_json TEXT NOT NULL DEFAULT '{}',
        current_json TEXT NOT NULL DEFAULT '{}',
        detected_at_utc TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_dependency_drift_variant ON plugin_security_dependency_drift(variant_id,current_scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_drift_component ON plugin_security_dependency_drift(component_key COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS ix_security_dependency_drift_type ON plugin_security_dependency_drift(change_type);

    CREATE TABLE IF NOT EXISTS plugin_security_source_artifact_comparisons (
        comparison_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL UNIQUE REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        variant_id INTEGER NOT NULL REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        source_available INTEGER NOT NULL DEFAULT 0,
        source_dependency_count INTEGER NOT NULL DEFAULT 0,
        artifact_dependency_count INTEGER NOT NULL DEFAULT 0,
        matched_component_count INTEGER NOT NULL DEFAULT 0,
        source_only_count INTEGER NOT NULL DEFAULT 0,
        artifact_only_count INTEGER NOT NULL DEFAULT 0,
        version_mismatch_count INTEGER NOT NULL DEFAULT 0,
        requirement_mismatch_count INTEGER NOT NULL DEFAULT 0,
        source_project_sha256 TEXT NOT NULL DEFAULT '',
        artifact_project_sha256 TEXT NOT NULL DEFAULT '',
        comparison_status TEXT NOT NULL DEFAULT '',
        source_only_json TEXT NOT NULL DEFAULT '[]',
        artifact_only_json TEXT NOT NULL DEFAULT '[]',
        version_mismatches_json TEXT NOT NULL DEFAULT '[]',
        requirement_mismatches_json TEXT NOT NULL DEFAULT '[]',
        compared_at_utc TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_security_source_artifact_variant ON plugin_security_source_artifact_comparisons(variant_id,scan_id);

    CREATE TABLE IF NOT EXISTS plugin_security_permission_candidates (
        candidate_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        origin TEXT NOT NULL DEFAULT '',
        permission_id TEXT NOT NULL DEFAULT '',
        risk TEXT NOT NULL DEFAULT '',
        confidence TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_permission_candidates_scan ON plugin_security_permission_candidates(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_permission_candidates_permission ON plugin_security_permission_candidates(permission_id);

    CREATE TABLE IF NOT EXISTS plugin_security_automation_capabilities (
        automation_capability_id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        capability_id TEXT NOT NULL DEFAULT '',
        label TEXT NOT NULL DEFAULT '',
        automation_level TEXT NOT NULL DEFAULT 'none',
        confidence TEXT NOT NULL DEFAULT '',
        reachable INTEGER NOT NULL DEFAULT 0,
        indirect INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS ix_security_automation_scan ON plugin_security_automation_capabilities(scan_id);
    CREATE INDEX IF NOT EXISTS ix_security_automation_capability ON plugin_security_automation_capabilities(capability_id);
    CREATE INDEX IF NOT EXISTS ix_security_automation_level ON plugin_security_automation_capabilities(automation_level);

    CREATE TABLE IF NOT EXISTS plugin_security_current (
        variant_id INTEGER PRIMARY KEY REFERENCES plugin_variants(variant_id) ON DELETE CASCADE,
        scan_id INTEGER NOT NULL REFERENCES plugin_security_scans(scan_id) ON DELETE CASCADE,
        assembly_version TEXT NOT NULL DEFAULT '',
        artifact_channel TEXT NOT NULL DEFAULT 'stable',
        artifact_url TEXT NOT NULL DEFAULT '',
        artifact_sha256 TEXT NOT NULL DEFAULT '',
        scanner_version TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        scanned_at_utc TEXT NOT NULL DEFAULT '',
        highest_severity TEXT NOT NULL DEFAULT 'none',
        informational_count INTEGER NOT NULL DEFAULT 0,
        caution_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        capabilities_json TEXT NOT NULL DEFAULT '[]',
        automation_level TEXT NOT NULL DEFAULT 'none',
        automation_capabilities_json TEXT NOT NULL DEFAULT '[]',
        findings_json TEXT NOT NULL DEFAULT '[]',
        source_available INTEGER NOT NULL DEFAULT 0,
        source_repository TEXT NOT NULL DEFAULT '',
        source_commit TEXT NOT NULL DEFAULT '',
        source_to_binary_verified INTEGER NOT NULL DEFAULT 0,
        report_json TEXT NOT NULL DEFAULT '{}',
        error TEXT NOT NULL DEFAULT ''
    );
    """)
    # Sigmascope schema evolves independently of the base catalog builder. Additive
    # migrations keep already-published catalogs enrichable in place.
    dependency_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_dependencies)")}
    if "requirement" not in dependency_columns:
        db.execute("ALTER TABLE plugin_security_dependencies ADD COLUMN requirement TEXT NOT NULL DEFAULT 'observed'")
    if "version_requirement" not in dependency_columns:
        db.execute("ALTER TABLE plugin_security_dependencies ADD COLUMN version_requirement TEXT NOT NULL DEFAULT ''")
    if "resolved_version" not in dependency_columns:
        db.execute("ALTER TABLE plugin_security_dependencies ADD COLUMN resolved_version TEXT NOT NULL DEFAULT ''")
    for column, declaration in (
        ("relationship", "TEXT NOT NULL DEFAULT ''"),
        ("relationship_confidence", "TEXT NOT NULL DEFAULT ''"),
        ("relationship_evidence_json", "TEXT NOT NULL DEFAULT '[]'"),
    ):
        if column not in dependency_columns:
            db.execute(f"ALTER TABLE plugin_security_dependencies ADD COLUMN {column} {declaration}")
    ipc_endpoint_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_ipc_endpoints)")}
    for column, declaration in (
        ("relationship", "TEXT NOT NULL DEFAULT ''"),
        ("relationship_confidence", "TEXT NOT NULL DEFAULT ''"),
        ("relationship_evidence_json", "TEXT NOT NULL DEFAULT '[]'"),
    ):
        if column not in ipc_endpoint_columns:
            db.execute(f"ALTER TABLE plugin_security_ipc_endpoints ADD COLUMN {column} {declaration}")
    resolution_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_dependency_resolutions)")}
    for column, declaration in (
        ("dependency_version", "TEXT NOT NULL DEFAULT ''"),
        ("version_requirement", "TEXT NOT NULL DEFAULT ''"),
        ("resolved_version", "TEXT NOT NULL DEFAULT ''"),
        ("version_status", "TEXT NOT NULL DEFAULT ''"),
        ("target_version", "TEXT NOT NULL DEFAULT ''"),
        ("relationship", "TEXT NOT NULL DEFAULT ''"),
        ("relationship_confidence", "TEXT NOT NULL DEFAULT ''"),
        ("relationship_evidence_json", "TEXT NOT NULL DEFAULT '[]'"),
    ):
        if column not in resolution_columns:
            db.execute(f"ALTER TABLE plugin_security_dependency_resolutions ADD COLUMN {column} {declaration}")
    component_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_dependency_components)")}
    if "distinct_version_count" not in component_columns:
        db.execute("ALTER TABLE plugin_security_dependency_components ADD COLUMN distinct_version_count INTEGER NOT NULL DEFAULT 0")
    if "version_divergence" not in component_columns:
        db.execute("ALTER TABLE plugin_security_dependency_components ADD COLUMN version_divergence TEXT NOT NULL DEFAULT 'none'")
    managed_call_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_managed_calls)")}
    if "target_method_token" not in managed_call_columns:
        db.execute("ALTER TABLE plugin_security_managed_calls ADD COLUMN target_method_token TEXT NOT NULL DEFAULT ''")
    current_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_current)")}
    if "automation_level" not in current_columns:
        db.execute("ALTER TABLE plugin_security_current ADD COLUMN automation_level TEXT NOT NULL DEFAULT 'none'")
    if "automation_capabilities_json" not in current_columns:
        db.execute("ALTER TABLE plugin_security_current ADD COLUMN automation_capabilities_json TEXT NOT NULL DEFAULT '[]'")
    artifact_analysis_columns = {row[1] for row in db.execute("PRAGMA table_info(artifact_analyses)")}
    for column, declaration in (
        ("catalog_definitions_revision", "TEXT NOT NULL DEFAULT ''"),
        ("last_used_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("reuse_count", "INTEGER NOT NULL DEFAULT 0"),
        ("analysis_payload_json", "TEXT NOT NULL DEFAULT '{}'") ,
    ):
        if column not in artifact_analysis_columns:
            db.execute(f"ALTER TABLE artifact_analyses ADD COLUMN {column} {declaration}")
    source_analysis_columns = {row[1] for row in db.execute("PRAGMA table_info(source_analyses)")}
    for column, declaration in (
        ("last_used_at_utc", "TEXT NOT NULL DEFAULT ''"),
        ("reuse_count", "INTEGER NOT NULL DEFAULT 0"),
        ("analysis_payload_json", "TEXT NOT NULL DEFAULT '{}'") ,
    ):
        if column not in source_analysis_columns:
            db.execute(f"ALTER TABLE source_analyses ADD COLUMN {column} {declaration}")
    db.execute("CREATE INDEX IF NOT EXISTS ix_security_dependencies_requirement ON plugin_security_dependencies(requirement)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_security_managed_calls_target_method ON plugin_security_managed_calls(target_method_token)")


PLUGIN_DEPENDENCY_KINDS = {"external-plugin"}
NUGET_DEPENDENCY_KINDS = {"nuget", "nuget-lock", "nuget-resolved"}
ASSEMBLY_DEPENDENCY_KINDS = {"assembly-reference", "managed-assembly", "managed-assembly-reference", "managed-executable"}
NATIVE_DEPENDENCY_KINDS = {"native-import", "native-library"}


def normalize_dependency_name(kind: str, name: str) -> str:
    value = (name or "").strip().replace("\\", "/")
    if not value:
        return ""
    if kind == "project-reference":
        value = Path(value).stem
    elif kind in ASSEMBLY_DEPENDENCY_KINDS | NATIVE_DEPENDENCY_KINDS:
        value = Path(value).name
        if value.lower().endswith(".dll"):
            value = value[:-4]
    return re.sub(r"\s+", " ", value).strip().casefold()


def dependency_component(kind: str, name: str) -> tuple[str, str, str]:
    normalized = normalize_dependency_name(kind, name)
    if not normalized:
        return "", "", ""
    if kind in PLUGIN_DEPENDENCY_KINDS:
        component_kind = "plugin"
    elif kind in NUGET_DEPENDENCY_KINDS:
        component_kind = "nuget"
    elif kind in ASSEMBLY_DEPENDENCY_KINDS:
        component_kind = "assembly"
    elif kind in NATIVE_DEPENDENCY_KINDS:
        component_kind = "native"
    elif kind == "project-reference":
        component_kind = "project"
    elif kind == "ipc":
        component_kind = "ipc"
    elif kind == "executable":
        component_kind = "executable"
    else:
        component_kind = kind or "dependency"
    return component_kind, normalized, f"{component_kind}:{normalized}"

_VERSION_RE = re.compile(r"^\s*[vV]?([0-9]+(?:\.[0-9]+){0,3})(?:[-+]([0-9A-Za-z.-]+))?\s*$")


def parse_version(value: str) -> tuple[tuple[int, int, int, int], str] | None:
    match = _VERSION_RE.match(value or "")
    if not match:
        return None
    parts = [int(x) for x in match.group(1).split(".")]
    parts.extend([0] * (4 - len(parts)))
    return (tuple(parts[:4]), (match.group(2) or "").casefold())


def compare_versions(left: str, right: str) -> int | None:
    a = parse_version(left)
    b = parse_version(right)
    if a is None or b is None:
        return None
    if a[0] < b[0]:
        return -1
    if a[0] > b[0]:
        return 1
    # Stable releases sort after prerelease labels for the same numeric version.
    if not a[1] and b[1]:
        return 1
    if a[1] and not b[1]:
        return -1
    if a[1] < b[1]:
        return -1
    if a[1] > b[1]:
        return 1
    return 0


def version_satisfies(version: str, requirement: str) -> bool | None:
    """Evaluate common NuGet/plugin version constraints conservatively.

    None means the expression could not be interpreted; callers must not turn
    an unknown expression into an incompatibility claim.
    """
    version = (version or "").strip()
    spec = (requirement or "").strip()
    if not spec or spec in {"*", "any", "Any"}:
        return True
    if parse_version(version) is None:
        return None

    range_match = re.match(r"^([\[(])\s*([^,]*)\s*,\s*([^\])}]*)\s*([\])])$", spec)
    if range_match:
        lower_inclusive = range_match.group(1) == "["
        upper_inclusive = range_match.group(4) == "]"
        lower = range_match.group(2).strip()
        upper = range_match.group(3).strip()
        if lower:
            cmp = compare_versions(version, lower)
            if cmp is None or cmp < 0 or (cmp == 0 and not lower_inclusive):
                return False if cmp is not None else None
        if upper:
            cmp = compare_versions(version, upper)
            if cmp is None or cmp > 0 or (cmp == 0 and not upper_inclusive):
                return False if cmp is not None else None
        return True

    if "*" in spec:
        prefix = spec.rstrip("*").rstrip(".")
        if not prefix or not all(part.isdigit() for part in prefix.split(".")):
            return None
        numeric = parse_version(version)
        if numeric is None:
            return None
        wanted = tuple(int(x) for x in prefix.split("."))
        return numeric[0][:len(wanted)] == wanted

    operator_matches = list(re.finditer(r"(>=|<=|>|<|==|=)\s*([vV]?[0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?)", spec))
    if operator_matches:
        remainder = re.sub(r"(>=|<=|>|<|==|=)\s*[vV]?[0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?", "", spec)
        if remainder.replace(",", " ").strip():
            return None
        for match in operator_matches:
            cmp = compare_versions(version, match.group(2))
            if cmp is None:
                return None
            op = match.group(1)
            if op == ">=" and cmp < 0:
                return False
            if op == ">" and cmp <= 0:
                return False
            if op == "<=" and cmp > 0:
                return False
            if op == "<" and cmp >= 0:
                return False
            if op in {"=", "=="} and cmp != 0:
                return False
        return True

    cmp = compare_versions(version, spec)
    return None if cmp is None else cmp == 0


def version_compatibility_status(observed: str, requirement: str) -> str:
    if not (requirement or "").strip():
        return "no-constraint"
    if not (observed or "").strip():
        return "unknown-observed-version"
    result = version_satisfies(observed, requirement)
    if result is True:
        return "compatible"
    if result is False:
        return "incompatible"
    return "unparsed-constraint"


def component_version_divergence(versions: Iterable[str]) -> str:
    clean = sorted({str(v).strip() for v in versions if str(v).strip()}, key=str.casefold)
    if len(clean) <= 1:
        return "none"
    parsed = [parse_version(v) for v in clean]
    if any(v is None for v in parsed):
        return "multiple-unparsed"
    majors = {v[0][0] for v in parsed if v is not None}
    return "major-version-divergence" if len(majors) > 1 else "version-divergence"


def is_platform_assembly_component(component_kind: str, normalized_name: str) -> bool:
    if component_kind != "assembly":
        return False
    normalized = (normalized_name or "").casefold()
    return normalized in PLATFORM_ASSEMBLY_NAMES or any(normalized.startswith(prefix) for prefix in PLATFORM_ASSEMBLY_PREFIXES)


def load_advisory_coverage(path: str) -> dict[str, str | int]:
    """Read bounded collector coverage metadata without trusting it as advisory evidence."""
    if not path:
        return {}
    advisory_path = Path(path)
    if not advisory_path.exists():
        return {}
    doc = json.loads(advisory_path.read_text(encoding="utf-8-sig"))
    if not isinstance(doc, dict):
        return {}
    result: dict[str, str | int] = {}
    for key in ("source", "ecosystem", "generatedAtUtc"):
        value = str(doc.get(key) or "").strip()
        if value:
            result[key] = value[:200]
    for key in ("queriedPackages", "matchedPackages"):
        try:
            result[key] = max(0, int(doc.get(key) or 0))
        except (TypeError, ValueError):
            result[key] = 0
    return result


def load_advisories(path: str) -> list[dict]:
    """Load optional local advisory data; Sigmascope never fetches advisories itself."""
    if not path:
        return []
    advisory_path = Path(path)
    if not advisory_path.exists():
        raise ValueError(f"Advisory file does not exist: {advisory_path}")
    doc = json.loads(advisory_path.read_text(encoding="utf-8-sig"))
    items = doc.get("advisories", []) if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise ValueError("Advisory document must be a list or contain an advisories list")
    if len(items) > MAX_ADVISORIES:
        raise ValueError(f"Advisory document has {len(items)} entries; limit is {MAX_ADVISORIES}")
    deduped: dict[tuple[str, ...], dict] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("id") or item.get("advisoryId") or "").casefold(),
            str(item.get("componentKind") or item.get("ecosystem") or "nuget").casefold(),
            str(item.get("name") or item.get("package") or "").casefold(),
            str(item.get("affectedRange") or item.get("affected") or ""),
            str(item.get("fixedVersion") or item.get("fixed") or ""),
        )
        deduped.setdefault(key, item)
    return [deduped[key] for key in sorted(deduped)]


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    return row is not None


def _plugin_aliases(db: sqlite3.Connection) -> tuple[dict[str, list[tuple[int, str]]], dict[int, str], dict[int, list[int]]]:
    plugin_columns = {str(row[1]) for row in db.execute("PRAGMA table_info(plugins)")}
    variant_columns = {str(row[1]) for row in db.execute("PRAGMA table_info(plugin_variants)")}
    aliases: dict[str, list[tuple[int, str]]] = defaultdict(list)
    internal_names: dict[int, str] = {}
    variants: dict[int, list[int]] = defaultdict(list)

    select_parts = ["plugin_id"]
    for column in ("internal_name", "canonical_name"):
        if column in plugin_columns:
            select_parts.append(column)
    if "active" in plugin_columns:
        plugin_rows = db.execute(f"SELECT {','.join(select_parts)} FROM plugins WHERE active=1").fetchall()
    else:
        plugin_rows = db.execute(f"SELECT {','.join(select_parts)} FROM plugins").fetchall()
    for row in plugin_rows:
        plugin_id = int(row["plugin_id"] if isinstance(row, sqlite3.Row) else row[0])
        data = dict(row) if isinstance(row, sqlite3.Row) else {select_parts[i]: row[i] for i in range(len(select_parts))}
        internal = str(data.get("internal_name") or "")
        internal_names[plugin_id] = internal
        if internal:
            aliases[internal.casefold()].append((plugin_id, "internal-name"))
        canonical = str(data.get("canonical_name") or "")
        if canonical:
            aliases[canonical.casefold()].append((plugin_id, "canonical-name"))

    variant_select = ["variant_id", "plugin_id"] + (["name"] if "name" in variant_columns else [])
    query = f"SELECT {','.join(variant_select)} FROM plugin_variants"
    if "active" in variant_columns:
        query += " WHERE active=1"
    for row in db.execute(query).fetchall():
        data = dict(row) if isinstance(row, sqlite3.Row) else {variant_select[i]: row[i] for i in range(len(variant_select))}
        plugin_id = int(data["plugin_id"])
        variants[plugin_id].append(int(data["variant_id"]))
        name = str(data.get("name") or "")
        if name:
            aliases[name.casefold()].append((plugin_id, "variant-name"))

    # Deduplicate identical aliases while preserving the strongest match basis.
    basis_rank = {"internal-name": 0, "canonical-name": 1, "variant-name": 2}
    for key, values in list(aliases.items()):
        best: dict[int, str] = {}
        for plugin_id, basis in values:
            if plugin_id not in best or basis_rank[basis] < basis_rank[best[plugin_id]]:
                best[plugin_id] = basis
        aliases[key] = sorted(best.items(), key=lambda item: (basis_rank[item[1]], item[0]))
    return aliases, internal_names, variants


def _preferred_target_variant(db: sqlite3.Connection, plugin_id: int, variants: dict[int, list[int]]) -> tuple[int | None, int]:
    active = sorted(set(variants.get(plugin_id) or []))
    if len(active) == 1:
        return active[0], 1
    if _table_exists(db, "presentation"):
        columns = {str(row[1]) for row in db.execute("PRAGMA table_info(presentation)")}
        if {"plugin_id", "preferred_variant_id"}.issubset(columns):
            row = db.execute("SELECT preferred_variant_id FROM presentation WHERE plugin_id=?", (plugin_id,)).fetchone()
            if row and row[0] is not None and int(row[0]) in active:
                return int(row[0]), len(active)
    return None, len(active)


def _variant_version(db: sqlite3.Connection, variant_id: int | None) -> str:
    if variant_id is None:
        return ""
    columns = {str(row[1]) for row in db.execute("PRAGMA table_info(plugin_variants)")}
    choices = [column for column in ("assembly_version", "testing_assembly_version") if column in columns]
    if not choices:
        return ""
    row = db.execute(f"SELECT {','.join(choices)} FROM plugin_variants WHERE variant_id=?", (variant_id,)).fetchone()
    if row is None:
        return ""
    for value in row:
        value = str(value or "").strip()
        if value:
            return value
    return ""


def resolve_plugin_dependency(name: str, aliases: dict[str, list[tuple[int, str]]], internal_names: dict[int, str], variants: dict[int, list[int]], db: sqlite3.Connection) -> dict:
    normalized = normalize_dependency_name("external-plugin", name)
    candidates = aliases.get(normalized, [])
    if not candidates:
        return {"status": "external-unresolved", "targetPluginId": None, "targetVariantId": None, "targetInternalName": "", "targetVariantCount": 0, "targetVersion": "", "confidence": "Low", "matchBasis": "not-in-catalog"}
    plugin_ids = sorted({plugin_id for plugin_id, _basis in candidates})
    if len(plugin_ids) != 1:
        return {"status": "ambiguous-plugin", "targetPluginId": None, "targetVariantId": None, "targetInternalName": "", "targetVariantCount": 0, "targetVersion": "", "confidence": "Low", "matchBasis": "multiple-catalog-matches"}
    plugin_id = plugin_ids[0]
    basis = next(basis for candidate_id, basis in candidates if candidate_id == plugin_id)
    target_variant_id, variant_count = _preferred_target_variant(db, plugin_id, variants)
    confidence = "VeryHigh" if basis == "internal-name" else "High"
    return {
        "status": "resolved-plugin",
        "targetPluginId": plugin_id,
        "targetVariantId": target_variant_id,
        "targetInternalName": internal_names.get(plugin_id, ""),
        "targetVariantCount": variant_count,
        "targetVersion": _variant_version(db, target_variant_id),
        "confidence": confidence,
        "matchBasis": basis,
    }


def refresh_ipc_provider_registry(
    db: sqlite3.Connection,
    internal_names: dict[int, str],
    variants: dict[int, list[int]],
    refreshed_at_utc: str,
) -> dict[str, list[dict]]:
    """Rebuild the current IPC provider registry from current completed plugin scans.

    The registry is intentionally separate from dependency rows: providing a call gate is not a
    dependency on another plugin. Consumer edges are resolved against exact channel strings after
    all current providers are registered, which allows cross-plugin IPC relationships to be
    refreshed without rescanning artifacts when the catalog changes.
    """
    endpoint_count = int(db.execute("""
        SELECT COUNT(*)
          FROM plugin_security_ipc_endpoints e
          JOIN plugin_security_scans s ON s.scan_id=e.scan_id
          JOIN plugin_security_current c ON c.scan_id=e.scan_id AND c.variant_id=s.variant_id
         WHERE c.status='complete' AND s.status='complete' AND e.role='provider' AND TRIM(e.channel)<>''
    """).fetchone()[0])
    if endpoint_count > MAX_CURRENT_IPC_ENDPOINT_ROWS:
        raise RuntimeError(f"Current IPC provider registry has {endpoint_count} endpoint rows; hard limit is {MAX_CURRENT_IPC_ENDPOINT_ROWS}")

    rows = db.execute("""
        SELECT e.ipc_endpoint_id,e.scan_id,e.origin,e.channel,e.signature,e.path,e.status,
               s.plugin_id,s.variant_id
          FROM plugin_security_ipc_endpoints e
          JOIN plugin_security_scans s ON s.scan_id=e.scan_id
          JOIN plugin_security_current c ON c.scan_id=e.scan_id AND c.variant_id=s.variant_id
         WHERE c.status='complete' AND s.status='complete' AND e.role='provider' AND TRIM(e.channel)<>''
         ORDER BY e.channel,s.plugin_id,s.variant_id,e.ipc_endpoint_id
    """).fetchall()

    grouped: dict[str, dict[int, list[sqlite3.Row]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        plugin_id = int(row["plugin_id"])
        if plugin_id not in internal_names:
            continue
        grouped[str(row["channel"])][plugin_id].append(row)

    db.execute("DELETE FROM plugin_security_ipc_registry")
    registry: dict[str, list[dict]] = defaultdict(list)
    for channel in sorted(grouped, key=str.casefold):
        for plugin_id in sorted(grouped[channel]):
            endpoints = grouped[channel][plugin_id]
            preferred_variant_id, variant_count = _preferred_target_variant(db, plugin_id, variants)
            chosen = next((row for row in endpoints if preferred_variant_id is not None and int(row["variant_id"]) == preferred_variant_id), endpoints[0])
            signatures = sorted({str(row["signature"] or "") for row in endpoints if str(row["signature"] or "")}, key=str.casefold)
            signature = signatures[0] if len(signatures) == 1 else ""
            entry = {
                "channel": channel,
                "pluginId": plugin_id,
                "variantId": preferred_variant_id,
                "internalName": internal_names.get(plugin_id, ""),
                "variantCount": variant_count,
                "targetVersion": _variant_version(db, preferred_variant_id),
                "scanId": int(chosen["scan_id"]),
                "signature": signature,
                "origin": str(chosen["origin"] or ""),
                "path": str(chosen["path"] or ""),
                "registrationCount": len(endpoints),
            }
            registry[channel].append(entry)
            db.execute("""
                INSERT INTO plugin_security_ipc_registry(
                    channel,provider_plugin_id,provider_variant_id,provider_internal_name,provider_variant_count,provider_scan_id,
                    provider_signature,provider_origin,provider_path,provider_registration_count,refreshed_at_utc)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (
                channel, plugin_id, preferred_variant_id, entry["internalName"], variant_count, entry["scanId"],
                signature, entry["origin"], entry["path"], len(endpoints), refreshed_at_utc,
            ))
    return dict(registry)


def resolve_ipc_dependency(channel: str, source_plugin_id: int, registry: dict[str, list[dict]]) -> dict:
    """Resolve an IPC subscriber to the plugin that currently exposes the exact channel."""
    providers = list(registry.get((channel or "").strip(), []))
    external = [entry for entry in providers if int(entry.get("pluginId") or 0) != source_plugin_id]
    if not external:
        if providers:
            own = providers[0]
            return {
                "status": "self-provided-ipc",
                "targetPluginId": int(own["pluginId"]),
                "targetVariantId": own.get("variantId"),
                "targetInternalName": str(own.get("internalName") or ""),
                "targetVariantCount": int(own.get("variantCount") or 0),
                "targetVersion": str(own.get("targetVersion") or ""),
                "confidence": "VeryHigh",
                "matchBasis": "exact-ipc-channel-self",
            }
        return {
            "status": "ipc-provider-unresolved", "targetPluginId": None, "targetVariantId": None,
            "targetInternalName": "", "targetVariantCount": 0, "targetVersion": "",
            "confidence": "Low", "matchBasis": "no-current-ipc-provider",
        }
    plugin_ids = sorted({int(entry["pluginId"]) for entry in external})
    if len(plugin_ids) != 1:
        return {
            "status": "ambiguous-ipc-provider", "targetPluginId": None, "targetVariantId": None,
            "targetInternalName": "", "targetVariantCount": 0, "targetVersion": "",
            "confidence": "Low", "matchBasis": "multiple-exact-ipc-providers",
        }
    provider = next(entry for entry in external if int(entry["pluginId"]) == plugin_ids[0])
    return {
        "status": "resolved-ipc-provider",
        "targetPluginId": int(provider["pluginId"]),
        "targetVariantId": provider.get("variantId"),
        "targetInternalName": str(provider.get("internalName") or ""),
        "targetVariantCount": int(provider.get("variantCount") or 0),
        "targetVersion": str(provider.get("targetVersion") or ""),
        "confidence": "VeryHigh",
        "matchBasis": "exact-ipc-channel-provider",
    }


def _observed_dependency_version(row: sqlite3.Row, kind: str, resolution: dict) -> str:
    if kind in PLUGIN_DEPENDENCY_KINDS:
        return str(resolution.get("targetVersion") or "").strip()
    resolved = str(row["resolved_version"] or "").strip()
    if resolved:
        return resolved
    version = str(row["version"] or "").strip()
    return version if parse_version(version) is not None else ""


def _issue_severity(requirement: str, issue_code: str) -> str:
    if issue_code in {"missing-required-plugin", "missing-required-ipc-provider", "required-version-incompatible"}:
        return "high"
    if issue_code in {"ambiguous-required-plugin", "ambiguous-required-ipc-provider", "soft-version-incompatible", "major-component-version-divergence"}:
        return "caution"
    return "informational"


def refresh_dependency_graph(db: sqlite3.Connection, advisories: list[dict] | None = None) -> dict:
    """Rebuild current dependency cross-references from current completed scans only.

    Raw scan/dependency history is immutable. Resolution, compatibility, component
    divergence and advisory matches are current projections and can be refreshed when
    catalog contents or advisory data change without rescanning plugin artifacts.
    """
    ensure_schema(db)
    aliases, internal_names, variants = _plugin_aliases(db)
    current_dependency_count = int(db.execute("""
        SELECT COUNT(*)
          FROM plugin_security_dependencies d
          JOIN plugin_security_scans s ON s.scan_id=d.scan_id
          JOIN plugin_security_current c ON c.scan_id=d.scan_id AND c.variant_id=s.variant_id
         WHERE c.status='complete' AND s.status='complete'
    """).fetchone()[0])
    if current_dependency_count > MAX_CURRENT_DEPENDENCY_ROWS:
        raise RuntimeError(f"Current dependency graph has {current_dependency_count} rows; hard limit is {MAX_CURRENT_DEPENDENCY_ROWS}")
    current_rows = db.execute("""
        SELECT d.dependency_id,d.scan_id,d.origin,d.kind,d.name,d.version,d.version_requirement,d.resolved_version,
               d.path,d.status,d.requirement,d.evidence_json,d.relationship,d.relationship_confidence,d.relationship_evidence_json,
               s.plugin_id AS source_plugin_id,s.variant_id AS source_variant_id
          FROM plugin_security_dependencies d
          JOIN plugin_security_scans s ON s.scan_id=d.scan_id
          JOIN plugin_security_current c ON c.scan_id=d.scan_id AND c.variant_id=s.variant_id
         WHERE c.status='complete' AND s.status='complete'
         ORDER BY d.dependency_id
    """).fetchall()
    db.execute("""
        DELETE FROM plugin_security_dependency_resolutions
         WHERE dependency_id NOT IN (
             SELECT d.dependency_id
               FROM plugin_security_dependencies d
               JOIN plugin_security_scans s ON s.scan_id=d.scan_id
               JOIN plugin_security_current c ON c.scan_id=d.scan_id AND c.variant_id=s.variant_id
              WHERE c.status='complete' AND s.status='complete'
         )
    """)
    db.execute("DELETE FROM plugin_security_dependency_components")
    db.execute("DELETE FROM plugin_security_dependency_issues")
    db.execute("DELETE FROM plugin_security_dependency_advisory_matches")

    components: dict[str, dict] = {}
    resolved_plugins = unresolved_plugins = ambiguous_plugins = 0
    resolved_ipc = unresolved_ipc = ambiguous_ipc = self_ipc = 0
    incompatible_versions = missing_required = missing_required_ipc = 0
    refreshed = utc_now()
    ipc_registry = refresh_ipc_provider_registry(db, internal_names, variants, refreshed)

    def record_issue(row: sqlite3.Row, component_key: str, issue_code: str, title: str, detail: str, observed: str, target: str = "") -> None:
        nonlocal incompatible_versions, missing_required, missing_required_ipc
        requirement = str(row["requirement"] or "observed")
        severity = _issue_severity(requirement, issue_code)
        if issue_code in {"required-version-incompatible", "soft-version-incompatible"}:
            incompatible_versions += 1
        if issue_code == "missing-required-plugin":
            missing_required += 1
        if issue_code == "missing-required-ipc-provider":
            missing_required_ipc += 1
        db.execute("""
            INSERT INTO plugin_security_dependency_issues(
                dependency_id,scan_id,source_plugin_id,source_variant_id,component_key,issue_code,severity,title,detail,
                requirement,version_requirement,observed_version,target_version,evidence_json,refreshed_at_utc)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            int(row["dependency_id"]), int(row["scan_id"]), int(row["source_plugin_id"]), int(row["source_variant_id"]),
            component_key, issue_code, severity, title, detail, requirement, str(row["version_requirement"] or ""), observed,
            target, str(row["evidence_json"] or "[]"), refreshed,
        ))

    for row in current_rows:
        kind = str(row["kind"] or "")
        name = str(row["name"] or "")
        component_kind, normalized, component_key = dependency_component(kind, name)
        requirement = str(row["requirement"] or "observed")
        version_requirement = str(row["version_requirement"] or "").strip()
        resolved_version = str(row["resolved_version"] or "").strip()
        if kind in PLUGIN_DEPENDENCY_KINDS:
            resolution = resolve_plugin_dependency(name, aliases, internal_names, variants, db)
            if resolution["status"] == "resolved-plugin":
                resolved_plugins += 1
            elif resolution["status"] == "ambiguous-plugin":
                ambiguous_plugins += 1
            else:
                unresolved_plugins += 1
        elif kind == "ipc":
            resolution = resolve_ipc_dependency(name, int(row["source_plugin_id"]), ipc_registry)
            if resolution["status"] == "resolved-ipc-provider":
                resolved_ipc += 1
            elif resolution["status"] == "ambiguous-ipc-provider":
                ambiguous_ipc += 1
            elif resolution["status"] == "self-provided-ipc":
                self_ipc += 1
            else:
                unresolved_ipc += 1
        else:
            resolution = {"status": "component", "targetPluginId": None, "targetVariantId": None, "targetInternalName": "", "targetVariantCount": 0, "targetVersion": "", "confidence": "High", "matchBasis": "normalized-component"}

        observed_version = _observed_dependency_version(row, kind, resolution)
        compatibility_requirement = version_requirement
        # Legacy graph rows may contain only the earlier version field. For plugin rows,
        # that field represented the declared target requirement.
        if not compatibility_requirement and kind in PLUGIN_DEPENDENCY_KINDS:
            compatibility_requirement = str(row["version"] or "").strip()
        version_status = version_compatibility_status(observed_version, compatibility_requirement)

        db.execute("""
            INSERT INTO plugin_security_dependency_resolutions(
                dependency_id,scan_id,source_plugin_id,source_variant_id,dependency_kind,dependency_name,dependency_version,
                version_requirement,resolved_version,normalized_name,component_key,requirement,relationship,relationship_confidence,relationship_evidence_json,resolution_status,version_status,
                target_plugin_id,target_variant_id,target_internal_name,target_variant_count,target_version,confidence,match_basis,evidence_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(dependency_id) DO UPDATE SET
                scan_id=excluded.scan_id,source_plugin_id=excluded.source_plugin_id,source_variant_id=excluded.source_variant_id,
                dependency_kind=excluded.dependency_kind,dependency_name=excluded.dependency_name,dependency_version=excluded.dependency_version,
                version_requirement=excluded.version_requirement,resolved_version=excluded.resolved_version,normalized_name=excluded.normalized_name,
                component_key=excluded.component_key,requirement=excluded.requirement,relationship=excluded.relationship,
                relationship_confidence=excluded.relationship_confidence,relationship_evidence_json=excluded.relationship_evidence_json,
                resolution_status=excluded.resolution_status,version_status=excluded.version_status,target_plugin_id=excluded.target_plugin_id,target_variant_id=excluded.target_variant_id,
                target_internal_name=excluded.target_internal_name,target_variant_count=excluded.target_variant_count,target_version=excluded.target_version,
                confidence=excluded.confidence,match_basis=excluded.match_basis,evidence_json=excluded.evidence_json
        """, (
            int(row["dependency_id"]), int(row["scan_id"]), int(row["source_plugin_id"]), int(row["source_variant_id"]),
            kind, name, str(row["version"] or ""), compatibility_requirement, resolved_version, normalized, component_key,
            requirement, str(row["relationship"] or ""), str(row["relationship_confidence"] or ""),
            str(row["relationship_evidence_json"] or "[]"), resolution["status"], version_status, resolution["targetPluginId"], resolution["targetVariantId"],
            resolution["targetInternalName"], int(resolution["targetVariantCount"]), resolution.get("targetVersion", ""),
            resolution["confidence"], resolution["matchBasis"], str(row["evidence_json"] or "[]"),
        ))

        if kind in PLUGIN_DEPENDENCY_KINDS:
            if resolution["status"] == "external-unresolved":
                if requirement == "required":
                    record_issue(row, component_key, "missing-required-plugin", "Required plugin dependency is not in the current catalog", f"{name} is declared required but could not be resolved to an active Omega catalog plugin.", observed_version)
                elif requirement in {"soft", "optional"}:
                    record_issue(row, component_key, "soft-plugin-unresolved", "Optional/soft plugin dependency is not in the current catalog", f"{name} remains listed as {requirement}; absence is informational and does not imply the source plugin is broken.", observed_version)
            elif resolution["status"] == "ambiguous-plugin":
                code = "ambiguous-required-plugin" if requirement == "required" else "ambiguous-soft-plugin"
                record_issue(row, component_key, code, "Plugin dependency matches multiple catalog entries", f"{name} was not guessed because more than one catalog plugin matched.", observed_version)
            elif version_status == "incompatible":
                code = "required-version-incompatible" if requirement == "required" else "soft-version-incompatible"
                record_issue(row, component_key, code, "Resolved plugin version does not satisfy declared requirement", f"Declared requirement {compatibility_requirement!r} does not include target version {observed_version!r}.", observed_version, resolution.get("targetVersion", ""))
        elif kind == "ipc":
            relationship = str(row["relationship"] or "unknown").casefold()
            relationship_confidence = str(row["relationship_confidence"] or "Low")
            strong_required = relationship == "required" and relationship_confidence in {"High", "VeryHigh"}
            if strong_required and resolution["status"] == "ipc-provider-unresolved":
                record_issue(row, component_key, "missing-required-ipc-provider", "Required IPC provider is not in the current catalog", f"{name} is inferred as a required IPC provider ({relationship_confidence} confidence) but no current provider exposes this exact channel.", observed_version)
            elif strong_required and resolution["status"] == "ambiguous-ipc-provider":
                record_issue(row, component_key, "ambiguous-required-ipc-provider", "Required IPC channel has multiple possible providers", f"{name} is inferred as required but multiple current plugins expose the exact channel; Omega will not guess which provider is intended.", observed_version)
            if version_status == "incompatible":
                code = "required-version-incompatible" if strong_required else "soft-version-incompatible"
                record_issue(row, component_key, code, "Resolved dependency version does not satisfy declared requirement", f"Declared requirement {compatibility_requirement!r} does not include observed version {observed_version!r}.", observed_version)
        elif version_status == "incompatible":
            code = "required-version-incompatible" if requirement == "required" else "soft-version-incompatible"
            record_issue(row, component_key, code, "Resolved dependency version does not satisfy declared requirement", f"Declared requirement {compatibility_requirement!r} does not include observed version {observed_version!r}.", observed_version)

        if not component_key:
            continue
        component = components.setdefault(component_key, {
            "kind": component_kind, "name": name, "normalized": normalized, "usage": 0,
            "plugins": set(), "variants": set(), "versions": set(),
            "requirements": {"required": 0, "soft": 0, "optional": 0, "bundled": 0, "observed": 0, "unknown": 0},
        })
        component["usage"] += 1
        component["plugins"].add(int(row["source_plugin_id"]))
        component["variants"].add(int(row["source_variant_id"]))
        if observed_version:
            component["versions"].add(observed_version)
        if requirement in component["requirements"]:
            component["requirements"][requirement] += 1
        else:
            component["requirements"]["unknown"] += 1

    divergent_components = 0
    platform_version_variations = 0
    for key, component in sorted(components.items()):
        req = component["requirements"]
        versions = sorted(component["versions"], key=str.casefold)
        divergence = component_version_divergence(versions)
        if divergence != "none" and is_platform_assembly_component(component["kind"], component["normalized"]):
            divergence = "platform-version-variation"
            platform_version_variations += 1
        if divergence not in {"none", "platform-version-variation"}:
            divergent_components += 1
        db.execute("""
            INSERT INTO plugin_security_dependency_components(
                component_key,component_kind,display_name,normalized_name,current_usage_count,source_plugin_count,
                source_variant_count,required_count,soft_count,optional_count,bundled_count,observed_count,unknown_count,
                versions_json,distinct_version_count,version_divergence,refreshed_at_utc)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            key, component["kind"], component["name"], component["normalized"], int(component["usage"]),
            len(component["plugins"]), len(component["variants"]), req["required"], req["soft"], req["optional"],
            req["bundled"], req["observed"], req["unknown"], json.dumps(versions, separators=(",", ":")), len(versions), divergence, refreshed,
        ))
        if divergence not in {"none", "platform-version-variation"}:
            issue_code = "major-component-version-divergence" if divergence == "major-version-divergence" else "component-version-divergence"
            severity = _issue_severity("observed", issue_code)
            db.execute("""
                INSERT INTO plugin_security_dependency_issues(
                    dependency_id,scan_id,source_plugin_id,source_variant_id,component_key,issue_code,severity,title,detail,
                    requirement,version_requirement,observed_version,target_version,evidence_json,refreshed_at_utc)
                VALUES(NULL,NULL,NULL,NULL,?,?,?,?,?,'observed','','','','[]',?)
            """, (key, issue_code, severity, "Shared dependency is present at multiple versions", f"Current catalog users reference versions: {', '.join(versions)}. This is divergence evidence, not by itself proof of a runtime conflict.", refreshed))

    advisory_matches = 0
    for advisory in advisories or []:
        advisory_id = str(advisory.get("id") or advisory.get("advisoryId") or "").strip()
        component_kind = str(advisory.get("componentKind") or advisory.get("ecosystem") or "nuget").strip().casefold()
        if component_kind in {"nuget", "nuget.org"}:
            component_kind = "nuget"
        name = str(advisory.get("name") or advisory.get("package") or "").strip()
        if not name:
            continue
        normalized = normalize_dependency_name("nuget" if component_kind == "nuget" else component_kind, name)
        key = f"{component_kind}:{normalized}"
        component = components.get(key)
        if component is None:
            continue
        affected_range = str(advisory.get("affectedRange") or advisory.get("affected") or "").strip()
        fixed_version = str(advisory.get("fixedVersion") or advisory.get("fixed") or "").strip()
        affected_versions = {str(v).strip() for v in advisory.get("affectedVersions", []) if str(v).strip()} if isinstance(advisory.get("affectedVersions"), list) else set()
        for version in sorted(component["versions"], key=str.casefold):
            affected = version in affected_versions
            if not affected and affected_range:
                affected = version_satisfies(version, affected_range) is True
            if not affected:
                continue
            if advisory_matches >= MAX_ADVISORY_MATCHES:
                raise RuntimeError(f"Dependency advisory matches exceed hard limit {MAX_ADVISORY_MATCHES}")
            db.execute("""
                INSERT INTO plugin_security_dependency_advisory_matches(
                    advisory_id,component_key,component_kind,component_name,affected_version,affected_range,fixed_version,
                    severity,title,advisory_url,advisory_source,refreshed_at_utc)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                advisory_id, key, component_kind, name, version, affected_range, fixed_version,
                str(advisory.get("severity") or "unknown"), str(advisory.get("title") or advisory_id or "Dependency advisory"),
                str(advisory.get("url") or ""), str(advisory.get("source") or "local-advisory-file"), refreshed,
            ))
            advisory_matches += 1

    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_graph_version',?)", (SCANNER_VERSION,))
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_graph_refreshed_at_utc',?)", (refreshed,))
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_version_intelligence_version',?)", (SCANNER_VERSION,))
    return {
        "dependencies": len(current_rows), "components": len(components), "resolvedPluginDependencies": resolved_plugins,
        "unresolvedPluginDependencies": unresolved_plugins, "ambiguousPluginDependencies": ambiguous_plugins,
        "ipcProviderChannels": len(ipc_registry), "resolvedIpcDependencies": resolved_ipc,
        "unresolvedIpcDependencies": unresolved_ipc, "ambiguousIpcDependencies": ambiguous_ipc, "selfProvidedIpcDependencies": self_ipc,
        "missingRequiredDependencies": missing_required, "missingRequiredIpcProviders": missing_required_ipc, "incompatibleVersionRequirements": incompatible_versions,
        "divergentComponents": divergent_components, "platformVersionVariationsSuppressed": platform_version_variations, "advisoryMatches": advisory_matches,
        "issueRows": int(db.execute("SELECT COUNT(*) FROM plugin_security_dependency_issues").fetchone()[0]),
    }


def _dependency_snapshot(db: sqlite3.Connection, scan_id: int, origin: str = "") -> dict[str, dict]:
    params: list[object] = [scan_id]
    where_origin = ""
    if origin:
        where_origin = " AND origin=?"
        params.append(origin)
    rows = db.execute(f"""
        SELECT origin,kind,name,version,version_requirement,resolved_version,path,status,requirement
          FROM plugin_security_dependencies
         WHERE scan_id=?{where_origin}
         ORDER BY dependency_id
    """, params).fetchall()
    out: dict[str, dict] = {}
    for row in rows:
        kind = str(row["kind"] or "")
        name = str(row["name"] or "")
        component_kind, normalized, component_key = dependency_component(kind, name)
        if not component_key:
            continue
        row_origin = str(row["origin"] or "combined")
        key = f"{row_origin}|{component_key}"
        item = out.setdefault(key, {
            "origin": row_origin,
            "componentKey": component_key,
            "componentKind": component_kind,
            "normalizedName": normalized,
            "name": name,
            "kinds": set(),
            "versions": set(),
            "versionRequirements": set(),
            "resolvedVersions": set(),
            "requirements": set(),
            "statuses": set(),
            "paths": set(),
        })
        item["kinds"].add(kind)
        for field, target in (("version", "versions"), ("version_requirement", "versionRequirements"), ("resolved_version", "resolvedVersions"), ("requirement", "requirements"), ("status", "statuses"), ("path", "paths")):
            value = str(row[field] or "").strip()
            if value:
                item[target].add(value)
    return out


def _snapshot_json(item: dict | None) -> dict:
    if item is None:
        return {}
    return {
        "origin": str(item.get("origin") or ""),
        "componentKey": str(item.get("componentKey") or ""),
        "componentKind": str(item.get("componentKind") or ""),
        "normalizedName": str(item.get("normalizedName") or ""),
        "name": str(item.get("name") or ""),
        "kinds": sorted(item.get("kinds") or [], key=str.casefold),
        "versions": sorted(item.get("versions") or [], key=str.casefold),
        "versionRequirements": sorted(item.get("versionRequirements") or [], key=str.casefold),
        "resolvedVersions": sorted(item.get("resolvedVersions") or [], key=str.casefold),
        "requirements": sorted(item.get("requirements") or [], key=str.casefold),
        "statuses": sorted(item.get("statuses") or [], key=str.casefold),
        "paths": sorted(item.get("paths") or [], key=str.casefold)[:32],
    }


def _permission_snapshot(db: sqlite3.Connection, scan_id: int) -> dict[str, dict]:
    rows = db.execute("""
        SELECT origin,permission_id,risk,confidence,reason
          FROM plugin_security_permission_candidates
         WHERE scan_id=?
         ORDER BY candidate_id
    """, (scan_id,)).fetchall()
    out: dict[str, dict] = {}
    for row in rows:
        origin = str(row["origin"] or "combined")
        permission_id = str(row["permission_id"] or "")
        if not permission_id:
            continue
        key = f"{origin}|{permission_id}"
        item = out.setdefault(key, {"origin": origin, "permissionId": permission_id, "risks": set(), "confidences": set(), "reasons": set()})
        for field, target in (("risk", "risks"), ("confidence", "confidences"), ("reason", "reasons")):
            value = str(row[field] or "").strip()
            if value:
                item[target].add(value)
    return out


def _permission_json(item: dict | None) -> dict:
    if item is None:
        return {}
    return {
        "origin": str(item.get("origin") or ""),
        "permissionId": str(item.get("permissionId") or ""),
        "risks": sorted(item.get("risks") or [], key=str.casefold),
        "confidences": sorted(item.get("confidences") or [], key=str.casefold),
        "reasons": sorted(item.get("reasons") or [], key=str.casefold)[:16],
    }


def _comparison_component_snapshot(db: sqlite3.Connection, scan_id: int, origin: str) -> dict[str, dict]:
    raw = _dependency_snapshot(db, scan_id, origin)
    out: dict[str, dict] = {}
    for item in raw.values():
        key = str(item["componentKey"])
        merged = out.setdefault(key, {
            "componentKey": key, "componentKind": item["componentKind"], "normalizedName": item["normalizedName"],
            "name": item["name"], "versions": set(), "requirements": set(), "kinds": set(),
        })
        merged["versions"].update(item["versions"])
        merged["versions"].update(item["resolvedVersions"])
        merged["requirements"].update(item["requirements"])
        merged["kinds"].update(item["kinds"])
    return out


def _comparison_json(item: dict) -> dict:
    return {
        "componentKey": item["componentKey"], "componentKind": item["componentKind"], "name": item["name"],
        "versions": sorted(item["versions"], key=str.casefold),
        "requirements": sorted(item["requirements"], key=str.casefold),
        "kinds": sorted(item["kinds"], key=str.casefold),
    }


def save_source_artifact_comparison(db: sqlite3.Connection, scan_id: int, variant_id: int, result: dict) -> dict:
    source = _comparison_component_snapshot(db, scan_id, "source")
    artifact = _comparison_component_snapshot(db, scan_id, "artifact")
    common = sorted(set(source) & set(artifact), key=str.casefold)
    source_only = [_comparison_json(source[key]) for key in sorted(set(source) - set(artifact), key=str.casefold)]
    artifact_only = [_comparison_json(artifact[key]) for key in sorted(set(artifact) - set(source), key=str.casefold)]
    version_mismatches: list[dict] = []
    requirement_mismatches: list[dict] = []
    for key in common:
        left, right = source[key], artifact[key]
        source_versions = {x for x in left["versions"] if x}
        artifact_versions = {x for x in right["versions"] if x}
        if source_versions and artifact_versions and source_versions.isdisjoint(artifact_versions):
            version_mismatches.append({"componentKey": key, "sourceVersions": sorted(source_versions), "artifactVersions": sorted(artifact_versions)})
        explicit = {"required", "soft", "optional"}
        source_req = left["requirements"] & explicit
        artifact_req = right["requirements"] & explicit
        if source_req and artifact_req and source_req != artifact_req:
            requirement_mismatches.append({"componentKey": key, "sourceRequirements": sorted(source_req), "artifactRequirements": sorted(artifact_req)})

    source_available = bool((result.get("source") or {}).get("available"))
    source_intel = ((result.get("source") or {}).get("dependencyIntelligence") or {})
    artifact_intel = ((result.get("package") or {}).get("dependencyIntelligence") or {})
    source_fp = str((source_intel.get("fingerprints") or {}).get("projectDependencySha256") or "")
    artifact_fp = str((artifact_intel.get("fingerprints") or {}).get("projectDependencySha256") or "")
    status = "source-unavailable" if not source_available else "compared-not-verified"
    compared = utc_now()
    db.execute("""
        INSERT INTO plugin_security_source_artifact_comparisons(
            scan_id,variant_id,source_available,source_dependency_count,artifact_dependency_count,matched_component_count,
            source_only_count,artifact_only_count,version_mismatch_count,requirement_mismatch_count,source_project_sha256,
            artifact_project_sha256,comparison_status,source_only_json,artifact_only_json,version_mismatches_json,
            requirement_mismatches_json,compared_at_utc)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(scan_id) DO UPDATE SET
            variant_id=excluded.variant_id,source_available=excluded.source_available,source_dependency_count=excluded.source_dependency_count,
            artifact_dependency_count=excluded.artifact_dependency_count,matched_component_count=excluded.matched_component_count,
            source_only_count=excluded.source_only_count,artifact_only_count=excluded.artifact_only_count,
            version_mismatch_count=excluded.version_mismatch_count,requirement_mismatch_count=excluded.requirement_mismatch_count,
            source_project_sha256=excluded.source_project_sha256,artifact_project_sha256=excluded.artifact_project_sha256,
            comparison_status=excluded.comparison_status,source_only_json=excluded.source_only_json,artifact_only_json=excluded.artifact_only_json,
            version_mismatches_json=excluded.version_mismatches_json,requirement_mismatches_json=excluded.requirement_mismatches_json,
            compared_at_utc=excluded.compared_at_utc
    """, (scan_id, variant_id, int(source_available), len(source), len(artifact), len(common), len(source_only), len(artifact_only),
          len(version_mismatches), len(requirement_mismatches), source_fp, artifact_fp, status,
          json.dumps(source_only, separators=(",", ":")), json.dumps(artifact_only, separators=(",", ":")),
          json.dumps(version_mismatches, separators=(",", ":")), json.dumps(requirement_mismatches, separators=(",", ":")), compared))
    return {
        "status": status, "sourceAvailable": source_available, "sourceDependencies": len(source), "artifactDependencies": len(artifact),
        "matchedComponents": len(common), "sourceOnly": len(source_only), "artifactOnly": len(artifact_only),
        "versionMismatches": len(version_mismatches), "requirementMismatches": len(requirement_mismatches),
        "sourceToBinaryVerified": False,
    }


def _drift_basis(previous: sqlite3.Row, result: dict) -> tuple[str, dict]:
    previous_artifact = str(previous["artifact_sha256"] or "")
    current_artifact = str(result.get("artifactSha256") or "")
    previous_source = str(previous["source_commit"] or "")
    current_source = str((result.get("source") or {}).get("commit") or "")
    previous_version = str(previous["assembly_version"] or "")
    current_version = str(result.get("assemblyVersion") or "")
    previous_scanner = str(previous["scanner_version"] or "")
    artifact_changed = bool(previous_artifact and current_artifact and previous_artifact != current_artifact)
    repository_changed = bool((previous_source or current_source) and previous_source != current_source)
    previous_source_fp = ""
    try:
        previous_report = json.loads(str(previous["report_json"] or "{}"))
        previous_source_fp = str((((previous_report.get("source") or {}).get("dependencyIntelligence") or {}).get("fingerprints") or {}).get("relevantSourceSha256") or "")
    except (json.JSONDecodeError, TypeError, AttributeError):
        previous_source_fp = ""
    current_source_fp = str(((((result.get("source") or {}).get("dependencyIntelligence") or {}).get("fingerprints") or {}).get("relevantSourceSha256")) or "")
    version_changed = bool((previous_version or current_version) and previous_version != current_version)
    scanner_changed = previous_scanner != SCANNER_VERSION
    if scanner_changed:
        # Source-scope fingerprints are not comparable across Sigmascope generations.
        source_changed = False
    elif previous_source_fp or current_source_fp:
        source_changed = previous_source_fp != current_source_fp
    else:
        # Legacy/fallback scans without source fingerprints retain commit-level behavior.
        source_changed = repository_changed
    if artifact_changed and source_changed:
        basis = "artifact-and-source-changed"
    elif artifact_changed:
        basis = "artifact-changed"
    elif scanner_changed:
        basis = "scanner-changed"
    elif source_changed:
        basis = "source-changed"
    elif repository_changed:
        basis = "repository-context-changed"
    else:
        basis = "revalidation"
    return basis, {
        "previousArtifactSha256": previous_artifact, "currentArtifactSha256": current_artifact,
        "previousSourceCommit": previous_source, "currentSourceCommit": current_source,
        "previousRelevantSourceSha256": previous_source_fp, "currentRelevantSourceSha256": current_source_fp,
        "previousAssemblyVersion": previous_version, "currentAssemblyVersion": current_version,
        "previousScannerVersion": previous_scanner, "currentScannerVersion": SCANNER_VERSION,
        "artifactChanged": artifact_changed, "sourceChanged": source_changed, "repositoryChanged": repository_changed,
        "assemblyVersionChanged": version_changed, "scannerChanged": scanner_changed,
    }


def record_dependency_history(db: sqlite3.Connection, previous_scan_id: int | None, current_scan_id: int, variant_id: int, result: dict) -> dict:
    detected = utc_now()
    if previous_scan_id is None:
        db.execute("""
            INSERT OR REPLACE INTO plugin_security_scan_lineage(
                current_scan_id,previous_scan_id,variant_id,current_artifact_sha256,current_source_commit,current_assembly_version,
                current_scanner_version,change_basis,detected_at_utc)
            VALUES(?,NULL,?,?,?,?,?,'baseline',?)
        """, (current_scan_id, variant_id, str(result.get("artifactSha256") or ""), str((result.get("source") or {}).get("commit") or ""),
              str(result.get("assemblyVersion") or ""), SCANNER_VERSION, detected))
        return {"previousScanId": None, "changeBasis": "baseline", "events": 0, "dependencyEvents": 0, "permissionEvents": 0}

    previous = db.execute("""
        SELECT scan_id,artifact_sha256,source_commit,assembly_version,scanner_version,status,report_json
          FROM plugin_security_scans WHERE scan_id=?
    """, (previous_scan_id,)).fetchone()
    if previous is None:
        return record_dependency_history(db, None, current_scan_id, variant_id, result)
    basis, lineage = _drift_basis(previous, result)
    db.execute("""
        INSERT OR REPLACE INTO plugin_security_scan_lineage(
            current_scan_id,previous_scan_id,variant_id,previous_artifact_sha256,current_artifact_sha256,previous_source_commit,
            current_source_commit,previous_assembly_version,current_assembly_version,previous_scanner_version,current_scanner_version,
            artifact_changed,source_changed,assembly_version_changed,scanner_changed,change_basis,detected_at_utc)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (current_scan_id, previous_scan_id, variant_id, lineage["previousArtifactSha256"], lineage["currentArtifactSha256"],
          lineage["previousSourceCommit"], lineage["currentSourceCommit"], lineage["previousAssemblyVersion"], lineage["currentAssemblyVersion"],
          lineage["previousScannerVersion"], lineage["currentScannerVersion"], int(lineage["artifactChanged"]), int(lineage["sourceChanged"]),
          int(lineage["assemblyVersionChanged"]), int(lineage["scannerChanged"]), basis, detected))

    previous_deps = _dependency_snapshot(db, previous_scan_id)
    current_deps = _dependency_snapshot(db, current_scan_id)
    previous_perms = _permission_snapshot(db, previous_scan_id)
    current_perms = _permission_snapshot(db, current_scan_id)
    events = 0
    dependency_events = 0
    permission_events = 0

    def severity_for(change_type: str, before: dict | None, after: dict | None, permission: bool = False) -> str:
        if basis in {"scanner-changed", "revalidation"}:
            return "informational"
        item = after or before or {}
        if permission:
            risks = {x.casefold() for x in item.get("risks", set())}
            return "caution" if risks & {"high", "critical"} else "informational"
        requirements = set(item.get("requirements", set()))
        if "required" in requirements and change_type in {"dependency-added", "dependency-removed", "requirement-changed", "version-changed", "version-requirement-changed"}:
            return "caution"
        return "informational"

    def add_event(change_scope: str, change_type: str, key: str, before: dict | None, after: dict | None, permission: bool = False) -> None:
        nonlocal events, dependency_events, permission_events
        if events >= MAX_DRIFT_EVENTS_PER_SCAN:
            return
        item = after or before or {}
        if permission:
            before_json, after_json = _permission_json(before), _permission_json(after)
            component_key = f"permission:{item.get('permissionId','')}"
            kind = "permission"
            name = str(item.get("permissionId") or "")
        else:
            before_json, after_json = _snapshot_json(before), _snapshot_json(after)
            component_key = str(item.get("componentKey") or "")
            kinds = sorted(item.get("kinds") or [], key=str.casefold)
            kind = kinds[0] if kinds else ""
            name = str(item.get("name") or "")
        db.execute("""
            INSERT INTO plugin_security_dependency_drift(
                variant_id,previous_scan_id,current_scan_id,change_scope,change_type,change_basis,origin,component_key,
                dependency_kind,dependency_name,severity,previous_json,current_json,detected_at_utc)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (variant_id, previous_scan_id, current_scan_id, change_scope, change_type, basis, str(item.get("origin") or ""),
              component_key, kind, name, severity_for(change_type, before, after, permission),
              json.dumps(before_json, separators=(",", ":")), json.dumps(after_json, separators=(",", ":")), detected))
        events += 1
        if permission:
            permission_events += 1
        else:
            dependency_events += 1

    for key in sorted(set(previous_deps) | set(current_deps), key=str.casefold):
        before, after = previous_deps.get(key), current_deps.get(key)
        if before is None:
            add_event("dependency", "dependency-added", key, None, after)
            continue
        if after is None:
            add_event("dependency", "dependency-removed", key, before, None)
            continue
        for field, change_type in (("versions", "version-changed"), ("resolvedVersions", "resolved-version-changed"),
                                   ("versionRequirements", "version-requirement-changed"), ("requirements", "requirement-changed"),
                                   ("statuses", "analysis-status-changed"), ("kinds", "dependency-kind-changed")):
            if set(before.get(field) or []) != set(after.get(field) or []):
                add_event("dependency", change_type, key, before, after)

    for key in sorted(set(previous_perms) | set(current_perms), key=str.casefold):
        before, after = previous_perms.get(key), current_perms.get(key)
        if before is None:
            add_event("permission", "permission-added", key, None, after, True)
        elif after is None:
            add_event("permission", "permission-removed", key, before, None, True)
        elif set(before.get("risks") or []) != set(after.get("risks") or []) or set(before.get("confidences") or []) != set(after.get("confidences") or []):
            add_event("permission", "permission-evidence-changed", key, before, after, True)

    return {
        "previousScanId": previous_scan_id, "changeBasis": basis, "events": events,
        "dependencyEvents": dependency_events, "permissionEvents": permission_events,
        "artifactChanged": lineage["artifactChanged"], "sourceChanged": lineage["sourceChanged"],
        "assemblyVersionChanged": lineage["assemblyVersionChanged"], "scannerChanged": lineage["scannerChanged"],
        "truncated": events >= MAX_DRIFT_EVENTS_PER_SCAN,
    }


def validate_database_health(db: sqlite3.Connection) -> dict:
    """Validate the enriched projection before descriptor/bundle publication."""
    integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
    if integrity.casefold() != "ok":
        raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
    foreign_key_rows = db.execute("PRAGMA foreign_key_check").fetchmany(32)
    if foreign_key_rows:
        raise RuntimeError(f"SQLite foreign_key_check reported {len(foreign_key_rows)} row(s)")
    current_dependencies = int(db.execute("""
        SELECT COUNT(*)
          FROM plugin_security_dependencies d
          JOIN plugin_security_scans s ON s.scan_id=d.scan_id
          JOIN plugin_security_current c ON c.scan_id=d.scan_id AND c.variant_id=s.variant_id
         WHERE c.status='complete' AND s.status='complete'
    """).fetchone()[0])
    resolutions = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependency_resolutions").fetchone()[0])
    if resolutions != current_dependencies:
        raise RuntimeError(f"Dependency projection mismatch: {resolutions} resolutions for {current_dependencies} current dependency rows")
    orphan_findings = int(db.execute("""
        SELECT COUNT(*) FROM plugin_security_findings f
         LEFT JOIN plugin_security_scans s ON s.scan_id=f.scan_id WHERE s.scan_id IS NULL
    """).fetchone()[0])
    if orphan_findings:
        raise RuntimeError(f"Found {orphan_findings} orphan security finding rows")
    return {
        "integrity": integrity,
        "foreignKeyViolations": 0,
        "currentDependencies": current_dependencies,
        "dependencyResolutions": resolutions,
        "orphanFindings": orphan_findings,
    }


def recreate_runtime_view(db: sqlite3.Connection) -> None:
    # Keep the runtime projection owned by the authoritative catalog builder so
    # Sigmascope and catalog workflows cannot drift into incompatible views.
    from build_sqlite_catalog import create_runtime_view
    create_runtime_view(db)


def choose_artifact(row: sqlite3.Row) -> tuple[str, str, str]:
    stable = str(row["download_link_install"] or "").strip()
    testing = str(row["download_link_testing"] or "").strip()
    if stable:
        return "stable", str(row["assembly_version"] or ""), stable
    return "testing", str(row["testing_assembly_version"] or row["assembly_version"] or ""), testing


def load_scan_ledger(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {"schema": SECURITY_LEDGER_SCHEMA, "variants": {}}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {"schema": SECURITY_LEDGER_SCHEMA, "variants": {}}
    if not isinstance(doc, dict) or doc.get("schema") != SECURITY_LEDGER_SCHEMA or not isinstance(doc.get("variants"), dict):
        return {"schema": SECURITY_LEDGER_SCHEMA, "variants": {}}
    return doc


def ledger_entry_is_fresh(entry: object, version: str, url: str, now: dt.datetime, rescan_hours: int) -> bool:
    if not isinstance(entry, dict):
        return False
    if str(entry.get("status") or "") != "complete":
        return False
    # Release identity is provenance, not analysis freshness. Narrow artifact/source
    # analysis revisions own semantic invalidation, so a version-only SigmaScope bump
    # must not make an unchanged ledger entry stale.
    if str(entry.get("artifactUrl") or "") != url or str(entry.get("assemblyVersion") or "") != version:
        return False
    validated = parse_utc(str(entry.get("lastValidatedAtUtc") or ""))
    return validated is not None and (now - validated).total_seconds() < rescan_hours * 3600


def write_scan_ledger(path: Path | None, ledger: dict, db: sqlite3.Connection, changed: bool) -> None:
    if path is None:
        return
    variants = ledger.get("variants") if isinstance(ledger.get("variants"), dict) else {}
    active = {str(row[0]) for row in db.execute("""
        SELECT v.variant_id FROM plugin_variants v
        JOIN plugins p ON p.plugin_id=v.plugin_id
        WHERE v.active=1 AND p.active=1
    """)}
    ledger["schema"] = SECURITY_LEDGER_SCHEMA
    ledger["scannerVersion"] = SCANNER_VERSION
    ledger["variants"] = {key: value for key, value in variants.items() if key in active}
    if changed or not path.exists():
        ledger["updatedAtUtc"] = utc_now()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def due_rows(db: sqlite3.Connection, max_scans: int, rescan_hours: int, names: set[str], ledger: dict | None = None, variant_ids: set[int] | None = None) -> list[sqlite3.Row]:
    """Select artifact rows from identity/revision events, never elapsed age.

    ``rescan_hours`` and the legacy ledger parameter remain accepted for compatibility
    with developer tooling, but they no longer make an unchanged plugin due. Production
    scheduling is owned by the typed persistent queue.
    """
    if max_scans <= 0:
        return []
    _ = rescan_hours, ledger
    variant_columns = {str(row[1]).casefold() for row in db.execute("PRAGMA table_info(plugin_variants)")}
    update_projection = "v.download_link_update" if "download_link_update" in variant_columns else "'' AS download_link_update"
    rows = db.execute(f"""
        SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.author,v.assembly_version,
               v.testing_assembly_version,v.download_link_install,{update_projection},v.download_link_testing,v.repo_url,
               s.name AS source_name,s.url AS source_url,s.source_repo_url,sc.status AS current_status,sc.scanned_at_utc AS current_scanned_at_utc,
               sc.scanner_version AS current_scanner_version,sc.artifact_url AS current_artifact_url,
               sc.assembly_version AS current_assembly_version
          FROM plugin_variants v
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
          LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
         WHERE v.active=1 AND p.active=1 AND (v.download_link_install<>'' OR v.download_link_testing<>'')
         ORDER BY CASE
                    WHEN sc.scan_id IS NULL THEN 0
                    WHEN sc.status<>'complete' THEN 1
                    ELSE 2
                  END,
                  COALESCE(sc.scanned_at_utc,''), p.internal_name COLLATE NOCASE, s.name COLLATE NOCASE
    """).fetchall()
    result = []
    for row in rows:
        if variant_ids and int(row["variant_id"]) not in variant_ids:
            continue
        if names and str(row["internal_name"]).lower() not in names:
            continue
        _channel, version, url = choose_artifact(row)
        if not url:
            continue
        if variant_ids:
            # Exact typed queue selection owns all due/retry semantics.
            result.append(row)
            if len(result) >= max_scans:
                break
            continue
        due = (
            row["current_status"] is None
            or str(row["current_status"]) != "complete"
            # Engine release identity alone is not a due reason. Semantic changes
            # are represented by the typed queue's analysis revisions.
            or str(row["current_artifact_url"] or "") != url
            or str(row["current_assembly_version"] or "") != version
        )
        if due:
            result.append(row)
        if len(result) >= max_scans:
            break
    return result


def save_dependency_intelligence(db: sqlite3.Connection, scan_id: int, result: dict) -> None:
    intel = result.get("dependencyIntelligence") or {}
    for item in intel.get("dependencies") or []:
        db.execute(
            """INSERT INTO plugin_security_dependencies(scan_id,origin,kind,name,version,version_requirement,resolved_version,path,status,requirement,evidence_json,relationship,relationship_confidence,relationship_evidence_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id, str(item.get("origin") or intel.get("origin") or "combined"), str(item.get("kind") or ""),
                str(item.get("name") or ""), str(item.get("version") or ""), str(item.get("versionRequirement") or ""),
                str(item.get("resolvedVersion") or ""), str(item.get("path") or ""), str(item.get("status") or ""),
                str(item.get("requirement") or "observed"), json.dumps(item.get("evidence") or [], separators=(",", ":")),
                str(item.get("relationship") or ""), str(item.get("relationshipConfidence") or ""),
                json.dumps(item.get("relationshipEvidence") or [], separators=(",", ":")),
            ),
        )
    for item in intel.get("ipcIntegrations") or []:
        db.execute(
            """INSERT INTO plugin_security_ipc_endpoints(scan_id,origin,role,channel,signature,path,status,relationship,relationship_confidence,relationship_evidence_json)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id, str(item.get("origin") or intel.get("origin") or "combined"),
                str(item.get("role") or "consumer"), str(item.get("channel") or ""),
                str(item.get("signature") or ""), str(item.get("path") or ""), str(item.get("status") or ""),
                str(item.get("relationship") or ""), str(item.get("relationshipConfidence") or ""),
                json.dumps(item.get("relationshipEvidence") or [], separators=(",", ":")),
            ),
        )
    for item in intel.get("imports") or []:
        db.execute(
            "INSERT INTO plugin_security_imports(scan_id,origin,namespace,path) VALUES(?,?,?,?)",
            (scan_id, str(item.get("origin") or intel.get("origin") or "combined"), str(item.get("namespace") or ""), str(item.get("path") or "")),
        )
    for item in intel.get("managedAssemblies") or []:
        db.execute(
            """INSERT INTO plugin_security_managed_assemblies(
                   scan_id,origin,path,sha256,assembly_name,assembly_version,metadata_version,parse_status,
                   reference_count,type_reference_count,member_reference_count,native_import_count,truncated,error)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id, str(item.get("origin") or intel.get("origin") or "combined"), str(item.get("path") or ""),
                str(item.get("sha256") or ""), str(item.get("assemblyName") or ""), str(item.get("assemblyVersion") or ""),
                str(item.get("metadataVersion") or ""), str(item.get("parseStatus") or ""), int(item.get("referenceCount") or 0),
                int(item.get("typeReferenceCount") or 0), int(item.get("memberReferenceCount") or 0),
                int(item.get("nativeImportCount") or 0), int(bool(item.get("truncated"))), str(item.get("error") or ""),
            ),
        )
    for item in intel.get("managedSymbols") or []:
        db.execute(
            """INSERT INTO plugin_security_managed_symbols(
                   scan_id,origin,path,symbol_kind,declaring_type,name,assembly_name,evidence_json)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                scan_id, str(item.get("origin") or intel.get("origin") or "combined"), str(item.get("path") or ""),
                str(item.get("kind") or ""), str(item.get("declaringType") or ""), str(item.get("name") or ""),
                str(item.get("assemblyName") or ""), json.dumps(item.get("evidence") or [], separators=(",", ":")),
            ),
        )
    for item in intel.get("managedCallSites") or []:
        db.execute(
            """INSERT INTO plugin_security_managed_calls(
                   scan_id,origin,path,source_method_token,source_declaring_type,source_method_name,il_offset,opcode,
                   target_token,target_kind,target_declaring_type,target_name,target_assembly_name,target_native_library,
                   target_native_entry_point,target_method_token,evidence_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id, str(item.get("origin") or intel.get("origin") or "combined"), str(item.get("path") or ""),
                str(item.get("sourceMethodToken") or ""), str(item.get("sourceDeclaringType") or ""),
                str(item.get("sourceMethodName") or ""), int(item.get("ilOffset") or 0), str(item.get("opcode") or ""),
                str(item.get("targetToken") or ""), str(item.get("targetKind") or ""),
                str(item.get("targetDeclaringType") or ""), str(item.get("targetName") or ""),
                str(item.get("targetAssemblyName") or ""), str(item.get("targetNativeLibrary") or ""),
                str(item.get("targetNativeEntryPoint") or ""), str(item.get("targetMethodToken") or ""),
                json.dumps(item.get("evidence") or [], separators=(",", ":")),
            ),
        )
    for item in intel.get("managedReachability") or []:
        db.execute(
            """INSERT INTO plugin_security_managed_reachability(
                   scan_id,origin,path,root_method_token,root_declaring_type,root_method_name,root_kind,root_confidence,
                   method_token,method_declaring_type,method_name,depth,via_method_token,via_il_offset,evidence_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id, str(item.get("origin") or intel.get("origin") or "combined"), str(item.get("path") or ""),
                str(item.get("rootMethodToken") or ""), str(item.get("rootDeclaringType") or ""),
                str(item.get("rootMethodName") or ""), str(item.get("rootKind") or ""), str(item.get("rootConfidence") or ""),
                str(item.get("methodToken") or ""), str(item.get("methodDeclaringType") or ""), str(item.get("methodName") or ""),
                int(item.get("depth") or 0), str(item.get("viaMethodToken") or ""), int(item.get("viaIlOffset") if item.get("viaIlOffset") is not None else -1),
                json.dumps(item.get("evidence") or [], separators=(",", ":")),
            ),
        )
    for item in intel.get("permissionCandidates") or []:
        db.execute(
            """INSERT INTO plugin_security_permission_candidates(scan_id,origin,permission_id,risk,confidence,reason,evidence_json)
               VALUES(?,?,?,?,?,?,?)""",
            (
                scan_id, str(item.get("origin") or intel.get("origin") or "combined"), str(item.get("permissionId") or ""),
                str(item.get("risk") or ""), str(item.get("confidence") or ""), str(item.get("reason") or ""),
                json.dumps(item.get("evidence") or [], separators=(",", ":")),
            ),
        )


def save_automation_capabilities(db: sqlite3.Connection, scan_id: int, result: dict) -> None:
    automation = result.get("automation") if isinstance(result.get("automation"), dict) else {}
    for item in automation.get("capabilities") or []:
        db.execute(
            """INSERT INTO plugin_security_automation_capabilities(
                   scan_id,capability_id,label,automation_level,confidence,reachable,indirect,reason,evidence_json)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                scan_id,
                str(item.get("capabilityId") or ""),
                str(item.get("label") or ""),
                str(item.get("automationLevel") or "none"),
                str(item.get("confidence") or ""),
                int(bool(item.get("reachable"))),
                int(bool(item.get("indirect"))),
                str(item.get("reason") or ""),
                json.dumps(item.get("evidence") or [], separators=(",", ":")),
            ),
        )


def persist_artifact_source_identity(db: sqlite3.Connection, variant_id: int, result: dict, scan_id: int) -> None:
    """Persist artifact/source identities separately from the legacy combined scan row."""
    artifact_sha = str(result.get("artifactSha256") or "").strip().casefold()
    if not artifact_sha:
        return
    observed = str(result.get("scannedAtUtc") or utc_now())
    package_bytes = int(result.get("artifactBytes") or 0)
    db.execute(
        """INSERT INTO artifact_blobs(artifact_sha256,package_bytes,first_seen_utc,last_seen_utc) VALUES(?,?,?,?)
           ON CONFLICT(artifact_sha256) DO UPDATE SET package_bytes=MAX(artifact_blobs.package_bytes,excluded.package_bytes),last_seen_utc=excluded.last_seen_utc""",
        (artifact_sha, package_bytes, observed, observed),
    )
    catalog_definitions_revision = read_catalog_meta(db, "definitions_revision")
    analysis_revision = str(result.get("artifactAnalysisRevision") or "").strip() or _artifact_analysis_revision(
        db,
        result.get("scanProvenance") if isinstance(result.get("scanProvenance"), dict) else None,
    )
    analysis_payload = result.get("artifactAnalysis") if isinstance(result.get("artifactAnalysis"), dict) else {}
    reused = int(bool(result.get("artifactAnalysisReused")))
    db.execute(
        """INSERT INTO artifact_analyses(
               artifact_sha256,scanner_version,definitions_revision,catalog_definitions_revision,representative_scan_id,
               status,analyzed_at_utc,last_used_at_utc,reuse_count,analysis_payload_json)
           VALUES(?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(artifact_sha256,scanner_version,definitions_revision) DO UPDATE SET
               catalog_definitions_revision=excluded.catalog_definitions_revision,
               representative_scan_id=CASE
                   WHEN artifact_analyses.representative_scan_id IS NULL OR artifact_analyses.representative_scan_id=0
                   THEN excluded.representative_scan_id ELSE artifact_analyses.representative_scan_id END,
               status=excluded.status,
               analyzed_at_utc=CASE WHEN artifact_analyses.analyzed_at_utc='' THEN excluded.analyzed_at_utc ELSE artifact_analyses.analyzed_at_utc END,
               last_used_at_utc=excluded.last_used_at_utc,
               reuse_count=artifact_analyses.reuse_count + excluded.reuse_count,
               analysis_payload_json=CASE WHEN excluded.analysis_payload_json<>'{}' THEN excluded.analysis_payload_json ELSE artifact_analyses.analysis_payload_json END""",
        (
            artifact_sha, SCANNER_VERSION, analysis_revision, catalog_definitions_revision, scan_id,
            str(result.get("status") or ""), observed, observed, reused,
            json.dumps(analysis_payload, separators=(",", ":")),
        ),
    )

    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    attribution = attribution_from_source_result(source)
    source["attribution"] = attribution
    result["source"] = source
    result["sourceAttributionContractVersion"] = 1
    repository = public_repository_url(str(source.get("repository") or ""))
    commit_sha = str(source.get("commit") or "").strip()
    revision_key = ""
    if repository:
        rkey = repository_key(repository)
        db.execute(
            """INSERT INTO source_repositories(repository_key,canonical_url,first_seen_utc,last_seen_utc) VALUES(?,?,?,?)
               ON CONFLICT(repository_key) DO UPDATE SET canonical_url=excluded.canonical_url,last_seen_utc=excluded.last_seen_utc""",
            (rkey, repository, observed, observed),
        )
        if commit_sha:
            revision_key = source_revision_key(repository, commit_sha)
            db.execute(
                """INSERT OR REPLACE INTO source_revisions(source_revision_key,repository_key,commit_sha,observed_ref,observed_at_utc)
                   VALUES(?,?,?,?,?)""",
                (revision_key, rkey, commit_sha, str(source.get("branch") or ""), observed),
            )

    scope = source.get("scope") if isinstance(source.get("scope"), dict) else {}
    primary_project = str(scope.get("primaryProject") or "").strip().replace("\\", "/")
    root_path = str(PurePosixPath(primary_project).parent) if primary_project else ""
    if root_path == ".":
        root_path = ""
    attr_key = attribution_key(int(variant_id), artifact_sha, revision_key, root_path)
    db.execute("UPDATE artifact_source_attributions SET active=0 WHERE variant_id=?", (int(variant_id),))
    db.execute(
        """INSERT OR REPLACE INTO artifact_source_attributions(
               attribution_key,variant_id,artifact_sha256,source_revision_key,source_root_path,confidence,basis_json,coverage_label,observed_at_utc,active)
           VALUES(?,?,?,?,?,?,?,?,?,1)""",
        (attr_key, int(variant_id), artifact_sha, revision_key, root_path, int(attribution["confidence"]),
         basis_json(attribution.get("basis") or []), str(attribution.get("coverageLabel") or ""), observed),
    )
    if revision_key:
        source_analysis_revision = str(result.get("sourceAnalysisRevision") or "").strip() or _source_analysis_revision(
            db, result.get("scanProvenance") if isinstance(result.get("scanProvenance"), dict) else None,
        )
        source_analysis = result.get("sourceAnalysis") if isinstance(result.get("sourceAnalysis"), dict) else {}
        if not source_analysis:
            source_analysis = _source_payload(source, {})
        source_reused = int(bool(result.get("sourceAnalysisReused")))
        source_status = "complete" if str(result.get("workType") or "") == "source" else "combined-compatibility"
        db.execute(
            """INSERT INTO source_analyses(
                   source_revision_key,source_root_path,scanner_version,definitions_revision,representative_scan_id,status,analyzed_at_utc,
                   last_used_at_utc,reuse_count,analysis_payload_json)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(source_revision_key,source_root_path,scanner_version,definitions_revision) DO UPDATE SET
                   representative_scan_id=CASE
                       WHEN source_analyses.representative_scan_id IS NULL OR source_analyses.representative_scan_id=0
                       THEN excluded.representative_scan_id ELSE source_analyses.representative_scan_id END,
                   status=CASE WHEN excluded.status='complete' THEN 'complete' ELSE source_analyses.status END,
                   analyzed_at_utc=CASE WHEN source_analyses.analyzed_at_utc='' THEN excluded.analyzed_at_utc ELSE source_analyses.analyzed_at_utc END,
                   last_used_at_utc=excluded.last_used_at_utc,
                   reuse_count=source_analyses.reuse_count + excluded.reuse_count,
                   analysis_payload_json=CASE WHEN excluded.analysis_payload_json<>'{}' THEN excluded.analysis_payload_json ELSE source_analyses.analysis_payload_json END""",
            (revision_key, root_path, SCANNER_VERSION, source_analysis_revision, scan_id, source_status, observed, observed, source_reused,
             json.dumps(source_analysis, separators=(",", ":"))),
        )


def rebuild_artifact_source_contracts(db: sqlite3.Connection) -> int:
    """Reconstruct artifact/source identity tables from current Evidence v2 projections.

    Evidence v2 keeps the compact report plus current artifact hash. This makes the
    new identity tables durable across the existing Evidence v2 transport before the
    future split artifact/source analysis datasets are introduced.
    """
    ensure_schema(db)
    db.execute("DELETE FROM artifact_source_attributions")
    rebuilt = 0
    rows = db.execute("SELECT variant_id,scan_id,artifact_sha256,scanned_at_utc,status,report_json FROM plugin_security_current ORDER BY variant_id").fetchall()
    for row in rows:
        try:
            report = json.loads(str(row["report_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            report = {}
        if not isinstance(report, dict):
            report = {}
        report["artifactSha256"] = str(row["artifact_sha256"] or "")
        report["scannedAtUtc"] = str(row["scanned_at_utc"] or "")
        report["status"] = str(row["status"] or "")
        persist_artifact_source_identity(db, int(row["variant_id"]), report, int(row["scan_id"] or 0))
        if str(row["artifact_sha256"] or ""):
            rebuilt += 1
    return rebuilt


ARTIFACT_CLONE_TABLES = (
    "plugin_security_findings",
    "plugin_security_dependencies",
    "plugin_security_ipc_endpoints",
    "plugin_security_imports",
    "plugin_security_managed_assemblies",
    "plugin_security_managed_symbols",
    "plugin_security_managed_calls",
    "plugin_security_managed_reachability",
    "plugin_security_permission_candidates",
    "plugin_security_automation_capabilities",
)


def _clone_scan_dataset_rows(db: sqlite3.Connection, table: str, source_scan_id: int, target_scan_id: int) -> int:
    if not _table_exists(db, table):
        return 0
    info = list(db.execute(f'PRAGMA table_info("{table}")'))
    columns = [str(row[1]) for row in info]
    if "scan_id" not in columns:
        return 0
    primary_keys = {str(row[1]) for row in info if int(row[5] or 0) > 0}
    copy_columns = [column for column in columns if column != "scan_id" and column not in primary_keys]
    quoted = ",".join(f'"{column}"' for column in copy_columns)
    select_columns = ",".join(f'"{column}"' for column in copy_columns)
    if copy_columns:
        db.execute(
            f'INSERT INTO "{table}"(scan_id,{quoted}) SELECT ?,{select_columns} FROM "{table}" WHERE scan_id=?',
            (target_scan_id, source_scan_id),
        )
    else:
        db.execute(f'INSERT INTO "{table}"(scan_id) SELECT ? FROM "{table}" WHERE scan_id=?', (target_scan_id, source_scan_id))
    return int(db.execute("SELECT changes()").fetchone()[0])


def _save_reused_artifact_scan(db: sqlite3.Connection, row: sqlite3.Row, result: dict, source_scan_id: int) -> int:
    """Project one already-proven artifact analysis onto another distributing variant.

    The target variant still downloaded and SHA-256 verified its own artifact bytes.
    Only after that identity match do we copy the immutable normalized artifact evidence
    from the representative scan. No source evidence is copied or inferred.
    """
    representative = db.execute(
        """SELECT * FROM plugin_security_scans WHERE scan_id=? AND status='complete'""",
        (source_scan_id,),
    ).fetchone()
    if representative is None:
        raise RuntimeError(f"artifact reuse representative scan {source_scan_id} is unavailable")
    artifact_sha = str(result.get("artifactSha256") or "").strip().casefold()
    if artifact_sha != str(representative["artifact_sha256"] or "").strip().casefold():
        raise RuntimeError("artifact reuse refused because representative SHA-256 differs")
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    cur = db.execute(
        """INSERT INTO plugin_security_scans(
               plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
               scanner_version,status,scanned_at_utc,highest_severity,informational_count,caution_count,high_count,
               critical_count,capabilities_json,source_available,source_repository,source_commit,source_to_binary_verified,
               report_json,error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            row["plugin_id"], row["variant_id"], row["source_id"], result["assemblyVersion"], result["artifactChannel"],
            result["artifactUrl"], artifact_sha, SCANNER_VERSION, result["status"], result["scannedAtUtc"],
            result["highestSeverity"], int(counts.get("informational") or 0), int(counts.get("caution") or 0),
            int(counts.get("high") or 0), int(counts.get("critical") or 0),
            json.dumps(result.get("capabilities") or [], separators=(",", ":")), 0,
            str(source.get("repository") or ""), "", 0, json.dumps(result, separators=(",", ":")), "",
        ),
    )
    scan_id = int(cur.lastrowid)
    for table in ARTIFACT_CLONE_TABLES:
        _clone_scan_dataset_rows(db, table, source_scan_id, scan_id)
    persist_artifact_source_identity(db, int(row["variant_id"]), result, scan_id)
    previous_current = db.execute("SELECT scan_id,status FROM plugin_security_current WHERE variant_id=?", (row["variant_id"],)).fetchone()
    previous_scan_id = int(previous_current["scan_id"]) if previous_current is not None and str(previous_current["status"] or "") == "complete" else None
    result["dependencyHistory"] = record_dependency_history(db, previous_scan_id, scan_id, int(row["variant_id"]), result)
    db.execute("UPDATE plugin_security_scans SET report_json=? WHERE scan_id=?", (json.dumps(result, separators=(",", ":")), scan_id))
    automation = result.get("automation") if isinstance(result.get("automation"), dict) else {}
    db.execute(
        """INSERT INTO plugin_security_current(
               variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
               scanned_at_utc,highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,
               automation_level,automation_capabilities_json,findings_json,source_available,source_repository,source_commit,
               source_to_binary_verified,report_json,error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(variant_id) DO UPDATE SET
               scan_id=excluded.scan_id,assembly_version=excluded.assembly_version,artifact_channel=excluded.artifact_channel,
               artifact_url=excluded.artifact_url,artifact_sha256=excluded.artifact_sha256,scanner_version=excluded.scanner_version,
               status=excluded.status,scanned_at_utc=excluded.scanned_at_utc,highest_severity=excluded.highest_severity,
               informational_count=excluded.informational_count,caution_count=excluded.caution_count,high_count=excluded.high_count,
               critical_count=excluded.critical_count,capabilities_json=excluded.capabilities_json,
               automation_level=excluded.automation_level,automation_capabilities_json=excluded.automation_capabilities_json,
               findings_json=excluded.findings_json,source_available=0,source_repository=excluded.source_repository,
               source_commit='',source_to_binary_verified=0,report_json=excluded.report_json,error=excluded.error""",
        (
            row["variant_id"], scan_id, result["assemblyVersion"], result["artifactChannel"], result["artifactUrl"], artifact_sha,
            SCANNER_VERSION, result["status"], result["scannedAtUtc"], result["highestSeverity"],
            int(counts.get("informational") or 0), int(counts.get("caution") or 0), int(counts.get("high") or 0), int(counts.get("critical") or 0),
            json.dumps(result.get("capabilities") or [], separators=(",", ":")), str(automation.get("level") or "none"),
            json.dumps(automation.get("capabilities") or [], separators=(",", ":")), json.dumps(result.get("findings") or [], separators=(",", ":")),
            0, str(source.get("repository") or ""), "", 0, json.dumps(result, separators=(",", ":")), "",
        ),
    )
    return scan_id


def _save_source_projection_scan(db: sqlite3.Connection, row: sqlite3.Row, result: dict, artifact_scan_id: int) -> int:
    """Attach source analysis to an existing artifact analysis without rerunning it.

    The immutable artifact datasets are cloned from the artifact representative scan.
    Only source-origin normalized rows are appended. This keeps source work from
    replacing artifact dependency/IL/permission evidence when Evidence v2 has compacted
    the in-memory artifact-analysis JSON payload between workers.
    """
    representative = db.execute(
        "SELECT * FROM plugin_security_scans WHERE scan_id=? AND status='complete'",
        (int(artifact_scan_id),),
    ).fetchone()
    if representative is None:
        raise RuntimeError(f"source projection artifact representative scan {artifact_scan_id} is unavailable")
    artifact_sha = str(result.get("artifactSha256") or "").strip().casefold()
    if not artifact_sha or artifact_sha != str(representative["artifact_sha256"] or "").strip().casefold():
        raise RuntimeError("source projection refused because artifact representative SHA-256 differs")
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    cur = db.execute(
        """INSERT INTO plugin_security_scans(
               plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
               scanner_version,status,scanned_at_utc,highest_severity,informational_count,caution_count,high_count,
               critical_count,capabilities_json,source_available,source_repository,source_commit,source_to_binary_verified,
               report_json,error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            row["plugin_id"], row["variant_id"], row["source_id"], result["assemblyVersion"], result["artifactChannel"],
            result["artifactUrl"], artifact_sha, SCANNER_VERSION, result["status"], result["scannedAtUtc"],
            result["highestSeverity"], int(counts.get("informational") or 0), int(counts.get("caution") or 0),
            int(counts.get("high") or 0), int(counts.get("critical") or 0),
            json.dumps(result.get("capabilities") or [], separators=(",", ":")), int(bool(source.get("available"))),
            str(source.get("repository") or ""), str(source.get("commit") or ""), 0,
            json.dumps(result, separators=(",", ":")), str(result.get("error") or ""),
        ),
    )
    scan_id = int(cur.lastrowid)
    for table in ARTIFACT_CLONE_TABLES:
        if table == "plugin_security_findings":
            continue
        _clone_scan_dataset_rows(db, table, artifact_scan_id, scan_id)

    # The source projection's immutable finding rows must reproduce the *final*
    # combined result, not merely artifact rows plus source rule findings.
    # _apply_source_analysis() can derive additional endpoint/automation findings
    # from the merged artifact+source intelligence.  Persist that authoritative
    # final list exactly so scan counters and normalized evidence cannot diverge.
    for finding in result.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        db.execute(
            """INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
               VALUES(?,?,?,?,?,?,?)""",
            (scan_id, str(finding.get("ruleId") or ""), str(finding.get("severity") or ""),
             str(finding.get("category") or ""), str(finding.get("title") or ""), str(finding.get("description") or ""),
             json.dumps(finding.get("evidence") or [], separators=(",", ":"))),
        )
    source_automation = source.get("automation") if isinstance(source.get("automation"), dict) else {}
    save_dependency_intelligence(db, scan_id, {"dependencyIntelligence": source.get("dependencyIntelligence") or empty_dependency_intelligence("source")})
    if source_automation:
        save_automation_capabilities(db, scan_id, {"automation": source_automation})

    previous_current = db.execute("SELECT scan_id,status FROM plugin_security_current WHERE variant_id=?", (row["variant_id"],)).fetchone()
    previous_scan_id = int(previous_current["scan_id"]) if previous_current is not None and str(previous_current["status"] or "") == "complete" else None
    persist_artifact_source_identity(db, int(row["variant_id"]), result, scan_id)
    result["sourceArtifactComparison"] = save_source_artifact_comparison(db, scan_id, int(row["variant_id"]), result)
    result["dependencyHistory"] = record_dependency_history(db, previous_scan_id, scan_id, int(row["variant_id"]), result)
    db.execute("UPDATE plugin_security_scans SET report_json=? WHERE scan_id=?", (json.dumps(result, separators=(",", ":")), scan_id))

    automation = result.get("automation") if isinstance(result.get("automation"), dict) else {}
    db.execute(
        """INSERT INTO plugin_security_current(
               variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
               scanned_at_utc,highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,
               automation_level,automation_capabilities_json,findings_json,source_available,source_repository,source_commit,
               source_to_binary_verified,report_json,error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(variant_id) DO UPDATE SET
               scan_id=excluded.scan_id,assembly_version=excluded.assembly_version,artifact_channel=excluded.artifact_channel,
               artifact_url=excluded.artifact_url,artifact_sha256=excluded.artifact_sha256,scanner_version=excluded.scanner_version,
               status=excluded.status,scanned_at_utc=excluded.scanned_at_utc,highest_severity=excluded.highest_severity,
               informational_count=excluded.informational_count,caution_count=excluded.caution_count,high_count=excluded.high_count,
               critical_count=excluded.critical_count,capabilities_json=excluded.capabilities_json,
               automation_level=excluded.automation_level,automation_capabilities_json=excluded.automation_capabilities_json,
               findings_json=excluded.findings_json,source_available=excluded.source_available,
               source_repository=excluded.source_repository,source_commit=excluded.source_commit,
               source_to_binary_verified=excluded.source_to_binary_verified,report_json=excluded.report_json,error=excluded.error""",
        (
            row["variant_id"], scan_id, result["assemblyVersion"], result["artifactChannel"], result["artifactUrl"], artifact_sha,
            SCANNER_VERSION, result["status"], result["scannedAtUtc"], result["highestSeverity"],
            int(counts.get("informational") or 0), int(counts.get("caution") or 0), int(counts.get("high") or 0), int(counts.get("critical") or 0),
            json.dumps(result.get("capabilities") or [], separators=(",", ":")), str(automation.get("level") or "none"),
            json.dumps(automation.get("capabilities") or [], separators=(",", ":")), json.dumps(result.get("findings") or [], separators=(",", ":")),
            int(bool(source.get("available"))), str(source.get("repository") or ""), str(source.get("commit") or ""), 0,
            json.dumps(result, separators=(",", ":")), str(result.get("error") or ""),
        ),
    )
    return scan_id


def save_scan(db: sqlite3.Connection, row: sqlite3.Row, result: dict) -> int:
    work_type = str(result.get("workType") or "")
    if work_type == "source" and result.get("status") == "complete":
        source_projection_base = int(result.get("sourceProjectionArtifactScanId") or result.get("artifactAnalysisRepresentativeScanId") or 0)
        if source_projection_base <= 0:
            raise RuntimeError("source work cannot publish without an artifact representative scan")
        return _save_source_projection_scan(db, row, result, source_projection_base)
    clone_from = int(result.get("artifactAnalysisCloneFromScanId") or 0)
    if clone_from > 0 and work_type == "artifact" and result.get("status") == "complete":
        return _save_reused_artifact_scan(db, row, result, clone_from)
    counts = result["counts"]
    previous_current = db.execute("SELECT scan_id,status FROM plugin_security_current WHERE variant_id=?", (row["variant_id"],)).fetchone()
    previous_scan_id = int(previous_current["scan_id"]) if previous_current is not None and str(previous_current["status"] or "") == "complete" else None
    cur = db.execute("""
        INSERT INTO plugin_security_scans(
            plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,
            scanner_version,status,scanned_at_utc,highest_severity,informational_count,caution_count,high_count,
            critical_count,capabilities_json,source_available,source_repository,source_commit,source_to_binary_verified,
            report_json,error)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        row["plugin_id"], row["variant_id"], row["source_id"], result["assemblyVersion"], result["artifactChannel"],
        result["artifactUrl"], result["artifactSha256"], SCANNER_VERSION, result["status"], result["scannedAtUtc"],
        result["highestSeverity"], counts["informational"], counts["caution"], counts["high"], counts["critical"],
        json.dumps(result["capabilities"], separators=(",", ":")), int(result["source"]["available"]),
        result["source"]["repository"], result["source"]["commit"], 0, json.dumps(result, separators=(",", ":")),
        result.get("error", ""),
    ))
    scan_id = int(cur.lastrowid)
    persist_artifact_source_identity(db, int(row["variant_id"]), result, scan_id)
    for finding in result["findings"]:
        db.execute(
            """INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json)
               VALUES(?,?,?,?,?,?,?)""",
            (scan_id, finding["ruleId"], finding["severity"], finding["category"], finding["title"], finding["description"], json.dumps(finding["evidence"], separators=(",", ":"))),
        )
    save_dependency_intelligence(db, scan_id, result)
    save_automation_capabilities(db, scan_id, result)

    if result["status"] == "complete":
        result["sourceArtifactComparison"] = save_source_artifact_comparison(db, scan_id, int(row["variant_id"]), result)
        result["dependencyHistory"] = record_dependency_history(db, previous_scan_id, scan_id, int(row["variant_id"]), result)
        db.execute("UPDATE plugin_security_scans SET report_json=? WHERE scan_id=?", (json.dumps(result, separators=(",", ":")), scan_id))

    if result["status"] != "complete" and previous_current is not None and str(previous_current["status"] or "") == "complete":
        # Preserve last-known-good intelligence when a periodic revalidation fails transiently.
        return scan_id

    db.execute("""
        INSERT INTO plugin_security_current(
            variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
            scanned_at_utc,highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,
            automation_level,automation_capabilities_json,findings_json,source_available,source_repository,source_commit,
            source_to_binary_verified,report_json,error)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(variant_id) DO UPDATE SET
            scan_id=excluded.scan_id,assembly_version=excluded.assembly_version,artifact_channel=excluded.artifact_channel,
            artifact_url=excluded.artifact_url,artifact_sha256=excluded.artifact_sha256,scanner_version=excluded.scanner_version,
            status=excluded.status,scanned_at_utc=excluded.scanned_at_utc,highest_severity=excluded.highest_severity,
            informational_count=excluded.informational_count,caution_count=excluded.caution_count,high_count=excluded.high_count,
            critical_count=excluded.critical_count,capabilities_json=excluded.capabilities_json,
            automation_level=excluded.automation_level,automation_capabilities_json=excluded.automation_capabilities_json,
            findings_json=excluded.findings_json,
            source_available=excluded.source_available,source_repository=excluded.source_repository,source_commit=excluded.source_commit,
            source_to_binary_verified=excluded.source_to_binary_verified,report_json=excluded.report_json,error=excluded.error
    """, (
        row["variant_id"], scan_id, result["assemblyVersion"], result["artifactChannel"], result["artifactUrl"],
        result["artifactSha256"], SCANNER_VERSION, result["status"], result["scannedAtUtc"], result["highestSeverity"],
        counts["informational"], counts["caution"], counts["high"], counts["critical"],
        json.dumps(result["capabilities"], separators=(",", ":")),
        str((result.get("automation") or {}).get("level") or "none"),
        json.dumps((result.get("automation") or {}).get("capabilities") or [], separators=(",", ":")),
        json.dumps(result["findings"], separators=(",", ":")),
        int(result["source"]["available"]), result["source"]["repository"], result["source"]["commit"], 0,
        json.dumps(result, separators=(",", ":")), result.get("error", ""),
    ))
    return scan_id


def _artifact_analysis_revision(db: sqlite3.Connection | None, scan_provenance: dict | None = None) -> str:
    provenance = scan_provenance if isinstance(scan_provenance, dict) else {}
    narrow_revision = str(provenance.get("artifactAnalysisRevision") or "").strip()
    if narrow_revision:
        return narrow_revision
    if db is not None:
        revision = read_catalog_meta(db, "artifact_analysis_revision", "")
        if revision:
            return str(revision)
    # Backward compatibility for evidence produced before the narrow revision existed.
    scanner_revision = str(provenance.get("scannerRevision") or "").strip()
    rule_revision = str(provenance.get("ruleSetRevision") or "").strip()
    if scanner_revision or rule_revision:
        return f"legacy:{scanner_revision or 'scanner-unknown'}+{rule_revision or 'rules-unknown'}"
    if db is not None:
        revision = read_catalog_meta(db, "scanner_revision", "") or read_catalog_meta(db, "rule_set_revision", "") or read_catalog_meta(db, "definitions_revision", "")
        if revision:
            return f"legacy:{revision}"
    return f"legacy:scanner-{SCANNER_VERSION}"


def _finalize_findings(rule_findings: list[dict], rule_capabilities: Iterable[str], intel: dict, candidates: Iterable[str]) -> dict:
    findings = copy.deepcopy(rule_findings)
    capabilities = set(str(item or "") for item in rule_capabilities if str(item or ""))
    has_network_capability = any(
        finding.get("ruleId") in {"network.http", "network.socket", "local.listener"} for finding in findings
    )
    intel["endpointSummary"] = endpoint_summary(intel.get("networkEndpoints") or [], has_network_capability)
    endpoint_results, endpoint_capabilities = endpoint_findings(
        intel.get("networkEndpoints") or [],
        has_network_capability,
        list(candidates),
    )
    automation = derive_automation_capabilities(intel)
    findings.extend(endpoint_results)
    findings.extend(automation["findings"])
    capabilities.update(endpoint_capabilities)
    capabilities.update(
        str(item.get("label") or "")
        for item in automation.get("capabilities") or []
        if str(item.get("label") or "")
    )
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(str(f.get("severity") or ""), 0), str(f.get("ruleId") or "")))
    counts = {
        severity: sum(1 for finding in findings if finding.get("severity") == severity)
        for severity in ("informational", "caution", "high", "critical")
    }
    highest = "none"
    for severity in ("critical", "high", "caution", "informational"):
        if counts[severity]:
            highest = severity
            break
    return {
        "findings": findings,
        "capabilities": sorted(capabilities, key=str.lower),
        "automation": automation,
        "counts": counts,
        "highestSeverity": highest,
    }


def _load_cached_artifact_analysis(
    db: sqlite3.Connection | None, artifact_sha256: str, analysis_revision: str,
) -> tuple[dict | None, int]:
    if db is None or not artifact_sha256 or not analysis_revision:
        return None, 0
    row = db.execute(
        """SELECT representative_scan_id,status,analysis_payload_json
             FROM artifact_analyses
            WHERE artifact_sha256=? AND scanner_version=? AND definitions_revision=?""",
        (artifact_sha256, SCANNER_VERSION, analysis_revision),
    ).fetchone()
    if row is None or str(row["status"] or "") != "complete":
        return None, 0
    representative_scan_id = int(row["representative_scan_id"] or 0)
    try:
        payload = json.loads(str(row["analysis_payload_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = {}
    if isinstance(payload, dict) and payload.get("schema") == ARTIFACT_ANALYSIS_SCHEMA:
        if str(payload.get("artifactSha256") or "").casefold() == artifact_sha256.casefold():
            return payload, representative_scan_id
    # Evidence v2 deliberately transports normalized scan datasets instead of a
    # second giant artifact-analysis JSON blob. After a worker re-materializes the
    # previous snapshot, reconstruct a small replay descriptor from the representative
    # scan and clone its normalized datasets when persisting the new variant.
    if representative_scan_id <= 0:
        return None, 0
    scan = db.execute(
        """SELECT assembly_version,artifact_sha256,highest_severity,informational_count,caution_count,high_count,critical_count,
                  capabilities_json,report_json,status
             FROM plugin_security_scans WHERE scan_id=?""",
        (representative_scan_id,),
    ).fetchone()
    if scan is None or str(scan["status"] or "") != "complete" or str(scan["artifact_sha256"] or "").casefold() != artifact_sha256.casefold():
        return None, 0
    try:
        report = json.loads(str(scan["report_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        report = {}
    findings: list[dict] = []
    for item in db.execute(
        "SELECT rule_id,severity,category,title,description,evidence_json FROM plugin_security_findings WHERE scan_id=? ORDER BY finding_id",
        (representative_scan_id,),
    ):
        try:
            evidence = json.loads(str(item["evidence_json"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            evidence = []
        findings.append({
            "ruleId": str(item["rule_id"] or ""), "severity": str(item["severity"] or ""),
            "category": str(item["category"] or ""), "title": str(item["title"] or ""),
            "description": str(item["description"] or ""), "evidence": evidence if isinstance(evidence, list) else [],
        })
    try:
        capabilities = json.loads(str(scan["capabilities_json"] or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        capabilities = []
    payload = {
        "schema": ARTIFACT_ANALYSIS_SCHEMA,
        "replayMode": "clone-normalized-evidence",
        "cloneFromScanId": representative_scan_id,
        "artifactSha256": artifact_sha256,
        "artifactBytes": int((report.get("artifactBytes") if isinstance(report, dict) else 0) or 0),
        "resolvedArtifactUrl": str((report.get("resolvedArtifactUrl") if isinstance(report, dict) else "") or ""),
        "artifactAssemblyVersion": str(scan["assembly_version"] or ""),
        "manifestPath": str(((report.get("artifactIdentity") or {}).get("manifestPath") if isinstance(report, dict) else "") or ""),
        "package": copy.deepcopy(report.get("package") or {}) if isinstance(report, dict) else {},
        # Source-only replay must retain the exact secondary-engine evidence that
        # belongs to this immutable artifact.  Dropping the payload while leaving
        # a transported contract marker creates an impossible half-contract.
        "secondarySecurity": copy.deepcopy(report.get("secondarySecurity") or {}) if isinstance(report, dict) else {},
        "secondarySecurityContractVersion": int(report.get("secondarySecurityContractVersion") or 0) if isinstance(report, dict) else 0,
        "ruleFindings": findings,
        "ruleCapabilities": capabilities if isinstance(capabilities, list) else [],
        "dependencyIntelligence": empty_dependency_intelligence("artifact"),
        "findings": findings,
        "capabilities": capabilities if isinstance(capabilities, list) else [],
        "automation": copy.deepcopy(report.get("automation") or {"level": "none", "capabilities": [], "findings": []}) if isinstance(report, dict) else {"level": "none", "capabilities": [], "findings": []},
        "counts": {
            "informational": int(scan["informational_count"] or 0), "caution": int(scan["caution_count"] or 0),
            "high": int(scan["high_count"] or 0), "critical": int(scan["critical_count"] or 0),
        },
        "highestSeverity": str(scan["highest_severity"] or "none"),
    }
    return payload, representative_scan_id


def _apply_artifact_analysis(base: dict, payload: dict, catalog_version: str, *, reused: bool, representative_scan_id: int = 0) -> None:
    artifact_version = str(payload.get("artifactAssemblyVersion") or "")
    base["package"] = copy.deepcopy(payload.get("package") or {})
    base["dependencyIntelligence"] = copy.deepcopy(payload.get("dependencyIntelligence") or empty_dependency_intelligence("artifact"))
    base["artifactIdentity"] = {
        "schema": "omega.sigmascope.artifact-identity.v1",
        "artifactSha256": str(payload.get("artifactSha256") or base.get("artifactSha256") or "").strip().lower(),
        "artifactBytes": int(payload.get("artifactBytes") or base.get("artifactBytes") or 0),
        "resolvedArtifactUrl": str(payload.get("resolvedArtifactUrl") or base.get("resolvedArtifactUrl") or ""),
        "catalogAssemblyVersion": catalog_version,
        "artifactAssemblyVersion": artifact_version,
        "manifestPath": str(payload.get("manifestPath") or ""),
        "manifestInternalName": str(payload.get("manifestInternalName") or ""),
        "manifestRepositoryUrl": str(payload.get("manifestRepositoryUrl") or ""),
        "versionMatchesCatalog": not artifact_version or not catalog_version or artifact_version.casefold() == catalog_version.casefold(),
    }
    if int(base["artifactIdentity"].get("artifactBytes") or 0) > 0 and str(base["artifactIdentity"].get("artifactSha256") or ""):
        base["artifactIdentityContractVersion"] = 1
    for key in ("findings", "capabilities", "automation", "counts", "highestSeverity", "secondarySecurity"):
        base[key] = copy.deepcopy(payload.get(key))
    if isinstance(base.get("secondarySecurity"), dict) and base.get("secondarySecurity"):
        # Preserve the contract that produced reusable historical artifact evidence.
        # Contract 3 is asserted only by a fresh artifact analysis that actually
        # carried bounded YARA member-scan scope; legacy 2.11-2.13 analyses remain v2.
        base["secondarySecurityContractVersion"] = int(payload.get("secondarySecurityContractVersion") or 2)
    else:
        # Never carry a stale contract marker after replay.  Either the exact
        # artifact-bound payload survives or the contract is explicitly absent.
        base.pop("secondarySecurityContractVersion", None)
    base["artifactAnalysis"] = copy.deepcopy(payload)
    base["artifactAnalysisReused"] = bool(reused)
    base["artifactAnalysisRepresentativeScanId"] = int(representative_scan_id or 0)
    base["artifactAnalysisCloneFromScanId"] = int(payload.get("cloneFromScanId") or 0)
    base["status"] = "complete"


def _build_artifact_analysis(row: sqlite3.Row, artifact: bytes, final_url: str, catalog_version: str) -> dict:
    artifact_sha = sha256_bytes(artifact)
    artifact_hits: dict[str, list[str]] = defaultdict(list)
    artifact_intel = empty_dependency_intelligence("artifact")
    package_meta = scan_archive(artifact, artifact_hits, artifact_intel)
    finalize_intelligence(artifact_intel)
    package_meta["dependencyIntelligence"] = artifact_intel
    artifact_manifest = next((
        item for item in package_meta.get("pluginManifests") or []
        if str(item.get("internalName") or "").casefold() == str(row["internal_name"] or "").casefold()
    ), None)
    artifact_version = str((artifact_manifest or {}).get("assemblyVersion") or catalog_version)
    secondary_config = _secondary_security_definition_config()
    secondary_security = scan_secondary_security_artifact(
        artifact,
        artifact_sha,
        yara_rules=secondary_config["yaraRules"],
        clamav_databases=secondary_config["clamavDatabases"],
        yara_executable_identity=secondary_config["yaraExecutableIdentity"],
        clamav_executable_identity=secondary_config["clamavExecutableIdentity"],
        yara_policy_revision=secondary_config["yaraPolicyRevision"],
        yara_rule_metadata=secondary_config["yaraRuleMetadata"],
        clamav_configuration_error=secondary_config["clamavConfigurationError"],
    )
    raw_findings, raw_capabilities = finding_payload(artifact_hits, package_meta)
    finalized = _finalize_findings(raw_findings, raw_capabilities, artifact_intel, [])
    return {
        "schema": ARTIFACT_ANALYSIS_SCHEMA,
        "artifactSha256": artifact_sha,
        "artifactBytes": len(artifact),
        "resolvedArtifactUrl": final_url,
        "artifactAssemblyVersion": artifact_version,
        "manifestPath": str((artifact_manifest or {}).get("path") or ""),
        "manifestInternalName": str((artifact_manifest or {}).get("internalName") or ""),
        "manifestRepositoryUrl": str((artifact_manifest or {}).get("repoUrl") or ""),
        "secondarySecurity": secondary_security,
        "secondarySecurityContractVersion": 3,
        "package": package_meta,
        "ruleFindings": raw_findings,
        "ruleCapabilities": sorted(set(raw_capabilities), key=str.lower),
        "dependencyIntelligence": artifact_intel,
        **finalized,
    }


def _source_analysis_revision(db: sqlite3.Connection | None, scan_provenance: dict | None = None) -> str:
    provenance = scan_provenance if isinstance(scan_provenance, dict) else {}
    narrow_revision = str(provenance.get("sourceAnalysisRevision") or "").strip()
    if narrow_revision:
        return narrow_revision
    if db is not None:
        revision = read_catalog_meta(db, "source_analysis_revision", "")
        if revision:
            return str(revision)
    scanner_revision = str(provenance.get("scannerRevision") or "").strip()
    rule_revision = str(provenance.get("ruleSetRevision") or "").strip()
    if scanner_revision or rule_revision:
        return f"legacy-source:{scanner_revision or 'scanner-unknown'}+{rule_revision or 'rules-unknown'}"
    if db is not None:
        definitions_revision = read_catalog_meta(db, "definitions_revision", "")
        if definitions_revision:
            return f"legacy-source:{definitions_revision}"
    return f"legacy-source:scanner-{SCANNER_VERSION}"


def _source_root_path(source: dict) -> str:
    scope = source.get("scope") if isinstance(source.get("scope"), dict) else {}
    primary_project = str(scope.get("primaryProject") or "").strip().replace("\\", "/")
    root_path = str(PurePosixPath(primary_project).parent) if primary_project else ""
    return "" if root_path == "." else root_path


def _source_payload(source: dict, source_hits: dict[str, list[str]], *, analysis_complete: bool = False) -> dict:
    source = copy.deepcopy(source if isinstance(source, dict) else {})
    findings, capabilities = finding_payload(source_hits, {})
    source["findings"] = findings
    source["capabilities"] = capabilities
    source["automation"] = derive_automation_capabilities(source.get("dependencyIntelligence") or empty_dependency_intelligence("source"))
    source["sourceToBinaryVerified"] = False
    source["status"] = "resolved" if source.get("available") else "unresolved"
    source["attribution"] = attribution_from_source_result(source)
    repository = public_repository_url(str(source.get("repository") or ""))
    commit_sha = str(source.get("commit") or "").strip()
    revision_key = source_revision_key(repository, commit_sha) if repository and commit_sha else ""
    return {
        "schema": SOURCE_ANALYSIS_SCHEMA,
        "sourceRevisionKey": revision_key,
        "sourceRootPath": _source_root_path(source),
        "analysisComplete": bool(analysis_complete),
        "source": source,
    }


def _load_cached_source_analysis(
    db: sqlite3.Connection | None, source_revision: str, root_path: str, analysis_revision: str,
) -> tuple[dict | None, int]:
    if db is None or not source_revision or not analysis_revision:
        return None, 0
    row = db.execute(
        """SELECT representative_scan_id,status,analysis_payload_json
             FROM source_analyses
            WHERE source_revision_key=? AND source_root_path=? AND scanner_version=? AND definitions_revision=?""",
        (source_revision, root_path, SCANNER_VERSION, analysis_revision),
    ).fetchone()
    if row is None or str(row["status"] or "") not in {"complete", "combined-compatibility"}:
        return None, 0
    representative_scan_id = int(row["representative_scan_id"] or 0)
    try:
        payload = json.loads(str(row["analysis_payload_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = {}
    if isinstance(payload, dict) and payload.get("schema") == SOURCE_ANALYSIS_SCHEMA and bool(payload.get("analysisComplete")):
        if str(payload.get("sourceRevisionKey") or "") == source_revision and str(payload.get("sourceRootPath") or "") == root_path:
            return payload, representative_scan_id
    if representative_scan_id <= 0:
        return None, 0
    scan = db.execute("SELECT report_json,status FROM plugin_security_scans WHERE scan_id=?", (representative_scan_id,)).fetchone()
    if scan is None or str(scan["status"] or "") != "complete":
        return None, 0
    try:
        report = json.loads(str(scan["report_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        report = {}
    source = report.get("source") if isinstance(report, dict) and isinstance(report.get("source"), dict) else {}
    repository = public_repository_url(str(source.get("repository") or ""))
    commit_sha = str(source.get("commit") or "").strip()
    observed_key = source_revision_key(repository, commit_sha) if repository and commit_sha else ""
    if observed_key != source_revision or _source_root_path(source) != root_path:
        return None, 0
    return {
        "schema": SOURCE_ANALYSIS_SCHEMA,
        "sourceRevisionKey": source_revision,
        "sourceRootPath": root_path,
        "analysisComplete": False,
        "source": copy.deepcopy(source),
    }, representative_scan_id


def _apply_source_analysis(
    base: dict,
    payload: dict,
    artifact_analysis: dict,
    candidates: list[str],
    candidate_records: list[dict],
    *,
    reused: bool,
    representative_scan_id: int = 0,
) -> None:
    source = copy.deepcopy(payload.get("source") or {})
    source["candidates"] = list(candidates)
    source["candidateEvidence"] = copy.deepcopy(candidate_records)
    source["sourceToBinaryVerified"] = False
    source["status"] = "resolved" if source.get("available") else "unresolved"
    source["attribution"] = attribution_from_source_result(source)
    base["source"] = source
    artifact_intel = artifact_analysis.get("dependencyIntelligence") or empty_dependency_intelligence("artifact")
    source_intel = source.get("dependencyIntelligence") or empty_dependency_intelligence("source")
    combined_intel = merge_dependency_intelligence(artifact_intel, source_intel)
    raw_findings = list(artifact_analysis.get("ruleFindings") or artifact_analysis.get("findings") or []) + list(source.get("findings") or [])
    raw_capabilities = list(artifact_analysis.get("ruleCapabilities") or artifact_analysis.get("capabilities") or []) + list(source.get("capabilities") or [])
    finalized = _finalize_findings(raw_findings, raw_capabilities, combined_intel, candidates)
    base["dependencyIntelligence"] = combined_intel
    base.update(finalized)
    base["sourceAnalysis"] = copy.deepcopy(payload)
    base["sourceAnalysisReused"] = bool(reused)
    base["sourceAnalysisRepresentativeScanId"] = int(representative_scan_id or 0)
    base["status"] = "complete"


def _artifact_payload_for_source_work(db: sqlite3.Connection, current: sqlite3.Row, report: dict) -> tuple[dict | None, int]:
    artifact_sha = str(current["artifact_sha256"] or "").strip().casefold()
    revision = str(report.get("artifactAnalysisRevision") or "").strip()
    if not revision:
        provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}
        revision = _artifact_analysis_revision(db, provenance)
    payload, representative = _load_cached_artifact_analysis(db, artifact_sha, revision)
    if payload is not None:
        return payload, representative
    if int(current["source_available"] or 0) == 0:
        return {
            "schema": ARTIFACT_ANALYSIS_SCHEMA,
            "artifactSha256": artifact_sha,
            "artifactAssemblyVersion": str(current["assembly_version"] or ""),
            "manifestPath": str(((report.get("artifactIdentity") or {}).get("manifestPath") if isinstance(report.get("artifactIdentity"), dict) else "") or ""),
            "package": copy.deepcopy(report.get("package") or {}),
            "secondarySecurity": copy.deepcopy(report.get("secondarySecurity") or {}),
            "secondarySecurityContractVersion": int(report.get("secondarySecurityContractVersion") or 0),
            "ruleFindings": copy.deepcopy(report.get("findings") or []),
            "ruleCapabilities": copy.deepcopy(report.get("capabilities") or []),
            "dependencyIntelligence": copy.deepcopy(report.get("dependencyIntelligence") or empty_dependency_intelligence("artifact")),
            "findings": copy.deepcopy(report.get("findings") or []),
            "capabilities": copy.deepcopy(report.get("capabilities") or []),
            "automation": copy.deepcopy(report.get("automation") or {"level": "none", "capabilities": [], "findings": []}),
            "counts": copy.deepcopy(report.get("counts") or {"informational": 0, "caution": 0, "high": 0, "critical": 0}),
            "highestSeverity": str(report.get("highestSeverity") or "none"),
        }, int(current["scan_id"] or 0)
    return None, 0


def scan_source_row(
    row: sqlite3.Row,
    token: str,
    source_override: str = "",
    *,
    db: sqlite3.Connection,
    source_analysis_revision: str = "",
) -> dict:
    current = db.execute("SELECT * FROM plugin_security_current WHERE variant_id=?", (int(row["variant_id"]),)).fetchone()
    scanned_at = utc_now()
    if current is None or str(current["status"] or "") != "complete" or not str(current["artifact_sha256"] or "").strip():
        return {
            "schema": "omega.plugin-security.scan.v1", "engineName": SIGMASCOPE_NAME, "engineVersion": SIGMASCOPE_VERSION,
            "scannerVersion": SCANNER_VERSION, "scannedAtUtc": scanned_at, "workType": "source", "status": "failed",
            "plugin": {"internalName": row["internal_name"], "name": row["name"], "author": row["author"], "sourceName": row["source_name"]},
            "assemblyVersion": str(row["assembly_version"] or ""), "artifactChannel": "", "artifactUrl": "", "artifactSha256": "",
            "highestSeverity": "none", "counts": {"informational": 0, "caution": 0, "high": 0, "critical": 0},
            "capabilities": [], "capabilityIds": [], "capabilityRegistryRevision": "", "findings": [], "automation": {"level": "none", "capabilities": [], "findings": []},
            "dependencyIntelligence": empty_dependency_intelligence("artifact"),
            "source": {"status": "unresolved", "available": False, "repository": "", "commit": "", "branch": "", "treeSha256": "", "filesScanned": 0, "sourceToBinaryVerified": False, "dependencyIntelligence": empty_dependency_intelligence("source"), "candidates": [], "candidateEvidence": [], "error": "Artifact analysis must complete before source work."},
            "package": {}, "error": "Artifact analysis must complete before source work.",
        }
    try:
        report = json.loads(str(current["report_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        report = {}
    base = copy.deepcopy(report if isinstance(report, dict) else {})
    base.update({
        "schema": "omega.plugin-security.scan.v1", "engineName": SIGMASCOPE_NAME, "engineVersion": SIGMASCOPE_VERSION,
        "scannerVersion": SCANNER_VERSION, "scannedAtUtc": scanned_at, "workType": "source", "status": "failed", "error": "",
        "assemblyVersion": str(current["assembly_version"] or ""), "artifactChannel": str(current["artifact_channel"] or ""),
        "artifactUrl": str(current["artifact_url"] or ""), "artifactSha256": str(current["artifact_sha256"] or ""),
    })
    if not isinstance(base.get("manifestObservation"), dict) or str(base.get("manifestObservation", {}).get("schema") or "") != MANIFEST_OBSERVATION_SCHEMA:
        base["manifestObservation"] = _manifest_observation_for_scan(
            db, row, str(current["artifact_channel"] or ""), str(current["artifact_url"] or ""), str(current["assembly_version"] or ""),
        )
    base["manifestObservationContractVersion"] = 1
    artifact_analysis, artifact_representative = _artifact_payload_for_source_work(db, current, base)
    if artifact_analysis is None:
        base["error"] = "Artifact-only representative evidence is unavailable for source projection."
        return base
    _apply_artifact_analysis(base, artifact_analysis, str(current["assembly_version"] or ""), reused=True, representative_scan_id=artifact_representative)
    base["sourceProjectionArtifactScanId"] = int(artifact_representative or current["scan_id"] or 0)
    base["workType"] = "source"
    base["artifactAnalysisRevision"] = str(report.get("artifactAnalysisRevision") or _artifact_analysis_revision(db, report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else None))
    final_url = str(report.get("resolvedArtifactUrl") or current["artifact_url"] or "")
    candidate_records = _source_candidates_for_row(row, source_override, final_url)
    candidates = [str(item.get("repository") or "") for item in candidate_records if str(item.get("repository") or "")]
    resolution_hits: dict[str, list[str]] = defaultdict(list)
    resolution = fetch_source(
        candidate_records, token, resolution_hits, str(row["internal_name"] or ""), str(row["name"] or ""),
        str(current["assembly_version"] or ""), str(current["artifact_url"] or ""), final_url, analyze=False,
    )
    if not resolution.get("available"):
        payload = _source_payload(resolution, {}, analysis_complete=True)
        _apply_source_analysis(base, payload, artifact_analysis, candidates, candidate_records, reused=False)
        base["sourceAnalysisRevision"] = source_analysis_revision or _source_analysis_revision(db)
        _refresh_capability_registry_projection(base)
        refresh_behavior_consistency(base)
        return base
    repository = public_repository_url(str(resolution.get("repository") or ""))
    commit_sha = str(resolution.get("commit") or "").strip()
    revision_key = source_revision_key(repository, commit_sha) if repository and commit_sha else ""
    root_path = _source_root_path(resolution)
    analysis_revision = source_analysis_revision or _source_analysis_revision(db)
    base["sourceAnalysisRevision"] = analysis_revision
    cached, representative_scan_id = _load_cached_source_analysis(db, revision_key, root_path, analysis_revision)
    if cached is not None:
        _apply_source_analysis(base, cached, artifact_analysis, candidates, candidate_records, reused=True, representative_scan_id=representative_scan_id)
        _refresh_capability_registry_projection(base)
        refresh_behavior_consistency(base)
        return base
    analysis_hits: dict[str, list[str]] = defaultdict(list)
    analyzed = fetch_source(
        candidate_records, token, analysis_hits, str(row["internal_name"] or ""), str(row["name"] or ""),
        str(current["assembly_version"] or ""), str(current["artifact_url"] or ""), final_url, analyze=True,
    )
    payload = _source_payload(analyzed, analysis_hits, analysis_complete=True)
    _apply_source_analysis(base, payload, artifact_analysis, candidates, candidate_records, reused=False)
    _refresh_capability_registry_projection(base)
    refresh_behavior_consistency(base)
    return base



def _manifest_observation_for_scan(db: sqlite3.Connection | None, row: sqlite3.Row, channel: str, artifact_url: str, manifest_version: str = "") -> dict:
    observation = None
    if db is not None and _table_exists(db, "manifest_observations"):
        observation = db.execute(
            """SELECT observation_id,variant_id,channel,internal_name,manifest_version,download_url,repository_url
                 FROM manifest_observations
                WHERE variant_id=? AND channel=? AND active=1
                ORDER BY observation_id DESC LIMIT 1""",
            (int(row["variant_id"]), str(channel or "")),
        ).fetchone()
        if observation is None and artifact_url:
            observation = db.execute(
                """SELECT observation_id,variant_id,channel,internal_name,manifest_version,download_url,repository_url
                     FROM manifest_observations
                    WHERE variant_id=? AND download_url=? AND active=1
                    ORDER BY observation_id DESC LIMIT 1""",
                (int(row["variant_id"]), str(artifact_url)),
            ).fetchone()
    if observation is not None:
        return manifest_observation_contract(
            int(observation["variant_id"]), str(observation["channel"] or ""), str(observation["internal_name"] or ""),
            str(observation["manifest_version"] or ""), str(observation["download_url"] or ""),
            str(observation["repository_url"] or ""), observation_id=int(observation["observation_id"] or 0),
        )
    # Compatibility fallback for materialized/legacy state that predates the explicit
    # manifest_observations table. The semantic key remains deterministic.
    return manifest_observation_contract(
        int(row["variant_id"]), str(channel or ""), str(row["internal_name"] or ""),
        str(manifest_version or row["assembly_version"] or ""), str(artifact_url or ""), str(row["repo_url"] or ""), observation_id=0,
    )


def _secondary_security_definition_config() -> dict:
    result = {
        "yaraRules": [],
        "clamavDatabases": [],
        "yaraExecutableIdentity": {},
        "clamavExecutableIdentity": {},
        "yaraPolicyRevision": "",
        "yaraRuleMetadata": [],
        "clamavConfigurationError": "",
    }
    root_text = str(os.environ.get("OMEGA_SECONDARY_SECURITY_ROOT") or "").strip()
    if not root_text:
        return result
    root = Path(root_text)
    index_path = root / "index.json"
    if not root.is_dir() or not index_path.is_file():
        return result
    try:
        document = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return result
    definitions_root = root.parent
    engines = {
        str(item.get("engine") or ""): item
        for item in document.get("engines") or []
        if isinstance(item, dict)
    }
    yara_engine = engines.get("yara") or {}
    result["yaraExecutableIdentity"] = copy.deepcopy(yara_engine.get("executableIdentity") or {})
    policy = yara_engine.get("policy") if isinstance(yara_engine.get("policy"), dict) else {}
    result["yaraPolicyRevision"] = str(policy.get("sha256") or "")
    yara_rules = []
    for entry in yara_engine.get("files") or []:
        if not isinstance(entry, dict) or not bool(entry.get("enabled")):
            continue
        rel = str(entry.get("path") or "")
        path = definitions_root / rel
        if path.is_file() and path.suffix.casefold() in {".yar", ".yara"}:
            yara_rules.append(path)
            metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
            if metadata:
                result["yaraRuleMetadata"].append(copy.deepcopy(metadata))
    result["yaraRules"] = sorted(yara_rules, key=lambda path: path.as_posix().casefold())[:128]

    clamav_engine = engines.get("clamav") or {}
    result["clamavExecutableIdentity"] = copy.deepcopy(clamav_engine.get("executableIdentity") or {})
    transport = clamav_engine.get("transport") if isinstance(clamav_engine.get("transport"), dict) else {}
    clamav_databases = []
    if transport:
        cache_text = str(os.environ.get("OMEGA_SECONDARY_SECURITY_CACHE") or "").strip()
        cache_root = Path(cache_text) if cache_text else None
        runtime_path = (cache_root / "runtime.json") if cache_root is not None else None
        runtime_ok = False
        if runtime_path is not None and runtime_path.is_file():
            try:
                runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
                runtime_ok = (
                    str(runtime.get("status") or "") == "ready"
                    and str(runtime.get("assetRevision") or "") == str(transport.get("revision") or "")
                    and str(runtime.get("assetSha256") or "") == str((transport.get("asset") or {}).get("sha256") or "")
                )
            except Exception:
                runtime_ok = False
        if not runtime_ok:
            result["clamavConfigurationError"] = "Frozen ClamAV asset is configured but was not materialized and verified for this worker."
        if runtime_ok and cache_root is not None:
            for entry in (transport.get("asset") or {}).get("files") or []:
                if not isinstance(entry, dict):
                    continue
                rel = str(entry.get("path") or "")
                if not rel.startswith("clamav/"):
                    continue
                path = cache_root / rel
                if path.is_file() and path.suffix.casefold() in {".cvd", ".cld"}:
                    clamav_databases.append(path)
    else:
        for entry in clamav_engine.get("files") or []:
            if not isinstance(entry, dict) or not bool(entry.get("enabled", True)):
                continue
            rel = str(entry.get("path") or "")
            path = definitions_root / rel
            if path.is_file() and path.suffix.casefold() in {".cvd", ".cld"}:
                clamav_databases.append(path)
    result["clamavDatabases"] = sorted(clamav_databases, key=lambda path: path.as_posix().casefold())[:32]
    return result

def _refresh_capability_registry_projection(report: dict) -> None:
    """Project current human/legacy capability evidence onto stable registry IDs.

    This is a report/transport projection, not a new artifact parser semantic. It can
    therefore be rebuilt from retained findings/permission/automation evidence without
    forcing artifact re-analysis. Unknown historical labels are ignored rather than
    invented.
    """
    if not isinstance(report, dict):
        return
    intel = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
    automation = report.get("automation") if isinstance(report.get("automation"), dict) else {}
    try:
        registry = load_registry()
        report["capabilityRegistryRevision"] = str(registry.get("revision") or "")
        report["capabilityIds"] = legacy_capability_ids(
            list(report.get("capabilities") or []),
            list(intel.get("permissionCandidates") or []),
            list(automation.get("capabilities") or []),
            registry,
        )
    except Exception as exc:
        # Registry failure must be visible but must not discard otherwise valid scanner
        # evidence. Daily Definitions validation is expected to fail closed before a
        # malformed production registry reaches a frozen worker.
        report["capabilityRegistryRevision"] = ""
        report["capabilityIds"] = []
        report["capabilityRegistryError"] = f"{type(exc).__name__}: {exc}"[:500]


def _source_candidates_for_row(row: sqlite3.Row, source_override: str, final_url: str) -> list[dict]:
    return source_candidate_records((
        ("override", source_override),
        ("repo-url", str(row["repo_url"] or "")),
        ("artifact-resolved", str(final_url or "")),
        ("artifact-install", str(row["download_link_install"] or "")),
        ("artifact-update", str(row["download_link_update"] or "")),
        ("artifact-testing", str(row["download_link_testing"] or "")),
    ))


def _attach_source_analysis(base: dict, row: sqlite3.Row, token: str, source_override: str) -> None:
    artifact_analysis = base.get("artifactAnalysis") if isinstance(base.get("artifactAnalysis"), dict) else {}
    candidate_records = _source_candidates_for_row(row, source_override, str(base.get("resolvedArtifactUrl") or ""))
    candidates = [str(item.get("repository") or "") for item in candidate_records if str(item.get("repository") or "")]
    base["source"]["candidates"] = candidates
    base["source"]["candidateEvidence"] = candidate_records
    if not candidates:
        base["source"]["status"] = "unresolved"
        base["source"]["error"] = "No GitHub source candidate could be derived from plugin metadata or download links"
        return

    source_hits: dict[str, list[str]] = defaultdict(list)
    artifact_version = str((base.get("artifactIdentity") or {}).get("artifactAssemblyVersion") or base.get("assemblyVersion") or "")
    base["source"] = fetch_source(
        candidate_records, token, source_hits, str(row["internal_name"] or ""), str(row["name"] or ""),
        artifact_version, str(base.get("artifactUrl") or ""), str(base.get("resolvedArtifactUrl") or ""),
    )
    base["source"]["sourceToBinaryVerified"] = False
    base["source"]["status"] = "resolved" if base["source"].get("available") else "unresolved"
    base["source"]["candidates"] = candidates
    base["source"]["candidateEvidence"] = candidate_records
    source_intel = base["source"].get("dependencyIntelligence") or empty_dependency_intelligence("source")
    source_findings, source_capabilities = finding_payload(source_hits, {})
    base["source"]["findings"] = source_findings
    base["source"]["capabilities"] = source_capabilities

    artifact_intel = artifact_analysis.get("dependencyIntelligence") or empty_dependency_intelligence("artifact")
    combined_intel = merge_dependency_intelligence(artifact_intel, source_intel)
    raw_findings = list(artifact_analysis.get("ruleFindings") or []) + source_findings
    raw_capabilities = list(artifact_analysis.get("ruleCapabilities") or []) + source_capabilities
    finalized = _finalize_findings(raw_findings, raw_capabilities, combined_intel, candidates)
    base["dependencyIntelligence"] = combined_intel
    base.update(finalized)


def scan_row(
    row: sqlite3.Row,
    token: str,
    scan_source: bool,
    source_override: str = "",
    *,
    db: sqlite3.Connection | None = None,
    artifact_analysis_revision: str = "",
) -> dict:
    channel, version, url = choose_artifact(row)
    scanned_at = utc_now()
    empty_source_intel = empty_dependency_intelligence("source")
    base = {
        "schema": "omega.plugin-security.scan.v1",
        "engineName": SIGMASCOPE_NAME,
        "engineVersion": SIGMASCOPE_VERSION,
        "scannerVersion": SCANNER_VERSION,
        "scannedAtUtc": scanned_at,
        "workType": "combined" if scan_source else "artifact",
        "plugin": {"internalName": row["internal_name"], "name": row["name"], "author": row["author"], "sourceName": row["source_name"]},
        "assemblyVersion": version,
        "artifactChannel": channel,
        "artifactUrl": url,
        "artifactSha256": "",
        "manifestObservation": _manifest_observation_for_scan(db, row, channel, url, version),
        "manifestObservationContractVersion": 1,
        "status": "failed",
        "highestSeverity": "none",
        "counts": {"informational": 0, "caution": 0, "high": 0, "critical": 0},
        "capabilities": [],
        "capabilityIds": [],
        "capabilityRegistryRevision": "",
        "findings": [],
        "automation": {"level": "none", "capabilities": [], "findings": []},
        "dependencyIntelligence": empty_dependency_intelligence("artifact"),
        "source": {
            "status": "unresolved", "available": False, "repository": str(row["repo_url"] or ""), "commit": "", "branch": "", "treeSha256": "",
            "filesScanned": 0, "sourceToBinaryVerified": False, "dependencyIntelligence": empty_source_intel,
            "scope": {"schema": "omega.plugin-source-scope.v1", "mode": "unavailable", "confidence": "none", "primaryProject": "", "projectFiles": [], "solutionFiles": [], "contextProjects": [], "contextSolutions": [], "criticalPaths": [], "repositorySourceFiles": 0, "criticalSourceFiles": 0, "excludedSourceFiles": 0, "reason": "Source analysis has not run."},
            "candidates": [], "candidateEvidence": [], "error": "",
        },
        "package": {},
        "artifactAnalysisReused": False,
        "artifactAnalysisRepresentativeScanId": 0,
        "error": "",
    }
    try:
        artifact, final_url = request_bytes(url, MAX_ARTIFACT_BYTES)
        artifact_sha = sha256_bytes(artifact)
        base["resolvedArtifactUrl"] = final_url
        base["artifactBytes"] = len(artifact)
        base["artifactSha256"] = artifact_sha
        candidate_records = _source_candidates_for_row(row, source_override, final_url)
        base["source"]["candidates"] = [str(item.get("repository") or "") for item in candidate_records if str(item.get("repository") or "")]
        base["source"]["candidateEvidence"] = candidate_records

        revision = artifact_analysis_revision or _artifact_analysis_revision(db)
        base["artifactAnalysisRevision"] = revision
        cached, representative_scan_id = _load_cached_artifact_analysis(db, artifact_sha, revision)
        if cached is not None:
            _apply_artifact_analysis(base, cached, version, reused=True, representative_scan_id=representative_scan_id)
        else:
            payload = _build_artifact_analysis(row, artifact, final_url, version)
            _apply_artifact_analysis(base, payload, version, reused=False)

        if scan_source:
            _attach_source_analysis(base, row, token, source_override)
        _refresh_capability_registry_projection(base)
        refresh_behavior_consistency(base)
        base["status"] = "complete"
    except Exception as exc:
        base["error"] = str(exc)[:1000]
    return base


def update_descriptor(database_path: Path, bundle_path: Path, descriptor_path: Path) -> dict:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.write(database_path, "omega-catalog.sqlite")
    catalog_sha = hashlib.sha256(database_path.read_bytes()).hexdigest()
    bundle_sha = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    descriptor["catalogSha256"] = catalog_sha
    descriptor["bundleSha256"] = bundle_sha
    descriptor["size"] = bundle_path.stat().st_size
    descriptor["databaseBytes"] = database_path.stat().st_size
    descriptor["securityGeneratedAtUtc"] = utc_now()
    with closing(sqlite3.connect(database_path)) as metadata_db:
        descriptor["catalogBaseRevision"] = read_catalog_meta(metadata_db, "catalog_base_revision")
        descriptor["securityRevision"] = read_catalog_meta(metadata_db, "security_revision_candidate")
        descriptor["evidenceRevision"] = read_catalog_meta(metadata_db, "evidence_revision_candidate")
        descriptor["catalogRevisionCandidate"] = read_catalog_meta(metadata_db, "catalog_revision_candidate")
        descriptor["sigmascopeName"] = SIGMASCOPE_NAME
        descriptor["sigmascopeVersion"] = read_catalog_meta(metadata_db, "sigmascope_version", SIGMASCOPE_VERSION)
        descriptor["scannerVersion"] = read_catalog_meta(metadata_db, "security_scanner_version", SCANNER_VERSION)
    descriptor_path.write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")
    (bundle_path.parent / f"{bundle_path.name}.sha256").write_text(f"{bundle_sha}  {bundle_path.name}\n", encoding="ascii")
    return descriptor


def run(args: argparse.Namespace) -> dict:
    db_path = Path(args.database)
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    token = os.environ.get("GITHUB_TOKEN", "")
    names = {x.strip().lower() for x in args.internal_names.split(",") if x.strip()}
    variant_ids = {int(x.strip()) for x in str(getattr(args, "variant_ids", "") or "").split(",") if x.strip().isdigit()}
    advisories = load_advisories(args.advisories)
    scan_provenance = getattr(args, "scan_provenance", None)
    artifact_analysis_revision = _artifact_analysis_revision(db, scan_provenance if isinstance(scan_provenance, dict) else None)
    advisory_coverage = load_advisory_coverage(args.advisories)
    source_overrides = load_source_overrides(Path(args.source_overrides) if args.source_overrides else None)
    summary = {
        "schema": "omega.plugin-security.batch.v1", "engineName": SIGMASCOPE_NAME, "engineVersion": SIGMASCOPE_VERSION, "scannerVersion": SCANNER_VERSION, "startedAtUtc": utc_now(),
        "selected": 0, "completed": 0, "failed": 0, "plugins": [],
        "workType": str((scan_provenance or {}).get("workType") or ("artifact" if args.skip_source else "combined")) if isinstance(scan_provenance, dict) else ("artifact" if args.skip_source else "combined"),
        "artifactAnalysisRevision": artifact_analysis_revision,
        "artifactAnalysesReused": 0,
        "sourceAnalysesReused": 0,
        "batchBudgetSeconds": max(0, int(args.max_batch_seconds)), "stoppedByBatchBudget": False,
    }
    batch_started = time.monotonic()
    deadline = batch_started + max(0, int(args.max_batch_seconds)) if int(args.max_batch_seconds) > 0 else None
    try:
        ensure_schema(db)
        ledger_path = Path(args.ledger) if args.ledger else None
        ledger = load_scan_ledger(ledger_path)
        ledger_changed = False
        rows = due_rows(db, args.max_scans, args.rescan_after_hours, names, ledger, variant_ids)
        summary["selected"] = len(rows)
        for index, row in enumerate(rows, start=1):
            if deadline is not None and time.monotonic() >= deadline:
                summary["stoppedByBatchBudget"] = True
                summary["remainingSelected"] = len(rows) - index + 1
                break
            print(f"[{index}/{len(rows)}] scanning {row['internal_name']} from {row['source_name']}", flush=True)
            scan_started = time.monotonic()
            override_key = source_override_key(str(row["internal_name"] or ""), str(row["source_url"] or ""))
            work_type = str((scan_provenance or {}).get("workType") or ("artifact" if args.skip_source else "combined")) if isinstance(scan_provenance, dict) else ("artifact" if args.skip_source else "combined")
            if work_type == "source":
                result = scan_source_row(
                    row, token, source_overrides.get(override_key, ""), db=db,
                    source_analysis_revision=_source_analysis_revision(db, scan_provenance if isinstance(scan_provenance, dict) else None),
                )
            else:
                result = scan_row(
                    row,
                    token,
                    not args.skip_source,
                    source_overrides.get(override_key, ""),
                    db=db,
                    artifact_analysis_revision=artifact_analysis_revision,
                )
            if isinstance(scan_provenance, dict) and scan_provenance:
                result["scanProvenance"] = dict(scan_provenance)
                result["scanProvenance"]["variantId"] = int(row["variant_id"])
            db.execute("SAVEPOINT omega_scan_persist")
            try:
                save_scan(db, row, result)
                db.execute("RELEASE SAVEPOINT omega_scan_persist")
                db.commit()
            except Exception:
                db.execute("ROLLBACK TO SAVEPOINT omega_scan_persist")
                db.execute("RELEASE SAVEPOINT omega_scan_persist")
                raise
            summary["completed" if result["status"] == "complete" else "failed"] += 1
            if result.get("artifactAnalysisReused"):
                summary["artifactAnalysesReused"] += 1
            if result.get("sourceAnalysisReused"):
                summary["sourceAnalysesReused"] += 1
            ledger_variants = ledger.setdefault("variants", {})
            ledger_variants[str(row["variant_id"])] = {
                "status": result["status"],
                "engineName": SIGMASCOPE_NAME,
                "engineVersion": SIGMASCOPE_VERSION,
                "scannerVersion": SCANNER_VERSION,
                "lastValidatedAtUtc": result["scannedAtUtc"],
                "assemblyVersion": result["assemblyVersion"],
                "artifactChannel": result["artifactChannel"],
                "artifactUrl": result["artifactUrl"],
                "artifactSha256": result["artifactSha256"],
            }
            ledger_changed = True
            intel = result.get("dependencyIntelligence") or {}
            if len(summary["plugins"]) < MAX_SCAN_REPORT_PLUGINS:
                summary["plugins"].append({
                "variantId": int(row["variant_id"]),
                "internalName": row["internal_name"], "sourceName": row["source_name"], "status": result["status"],
                "highestSeverity": result["highestSeverity"], "artifactSha256": result["artifactSha256"],
                "workType": result.get("workType") or "",
                "artifactAnalysisReused": bool(result.get("artifactAnalysisReused")),
                "artifactAnalysisRepresentativeScanId": int(result.get("artifactAnalysisRepresentativeScanId") or 0),
                "sourceAnalysisReused": bool(result.get("sourceAnalysisReused")),
                "sourceAnalysisRepresentativeScanId": int(result.get("sourceAnalysisRepresentativeScanId") or 0),
                "dependencyCount": len(intel.get("dependencies") or []),
                "softDependencyCount": sum(1 for item in (intel.get("dependencies") or []) if item.get("requirement") == "soft"),
                "reachableMethodCount": len({item.get("methodToken") for item in (intel.get("managedReachability") or []) if item.get("methodToken")}),
                "permissionCandidateCount": len(intel.get("permissionCandidates") or []),
                "managedAssemblyCount": len(intel.get("managedAssemblies") or []),
                "managedSymbolCount": len(intel.get("managedSymbols") or []),
                    "managedCallSiteCount": len(intel.get("managedCallSites") or []),
                    "intelligenceTruncated": bool((intel.get("limits") or {}).get("truncated")),
                    "droppedEvidence": dict((intel.get("limits") or {}).get("droppedByCollection") or {}),
                    "elapsedSeconds": round(time.monotonic() - scan_started, 3),
                    "error": result["error"],
                })
        summary["reportedPluginRows"] = len(summary["plugins"])
        derived = refresh_current_security_projection(db, advisories, advisory_coverage)
        summary.update(derived)
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('sigmascope_name',?)", (SIGMASCOPE_NAME,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('sigmascope_version',?)", (SIGMASCOPE_VERSION,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanner_version',?)", (SCANNER_VERSION,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanned_at_utc',?)", (utc_now(),))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_scanner_version',?)", (SCANNER_VERSION,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_history_version',?)", (SCANNER_VERSION,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_history_generated_at_utc',?)", (utc_now(),))
        db.commit()
        summary["databaseHealth"] = validate_database_health(db)
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_hardening_version',?)", (SCANNER_VERSION,))
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_hardening_validated_at_utc',?)", (utc_now(),))
        if getattr(args, "skip_revision_update", False):
            # Local reduced-catalog Sigmascope mode deliberately contains only catalog
            # identity + fresh security evidence.  It is not a publication candidate,
            # so production catalog/evidence revisions must not be recomputed from the
            # subset.  Preserve the source revision markers for diagnostics instead.
            revisions = {
                "baseRevision": read_catalog_meta(db, "base_revision", read_catalog_meta(db, "catalog_base_revision", "")),
                "catalogRevision": read_catalog_meta(db, "catalog_revision", read_catalog_meta(db, "catalog_revision_candidate", "")),
                "securityRevision": read_catalog_meta(db, "security_revision", ""),
                "evidenceRevision": read_catalog_meta(db, "evidence_revision", ""),
                "localTestSubset": True,
            }
        else:
            revisions = update_candidate_revisions(db)
        db.commit()
        summary["revisions"] = revisions
        summary["currentScanCount"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_current WHERE status='complete'").fetchone()[0])
        summary["currentHighOrCritical"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_current WHERE status='complete' AND highest_severity IN ('high','critical')").fetchone()[0])
        summary["dependencyRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependencies").fetchone()[0])
        summary["dependencyRowsByKind"] = {
            str(row[0] or ""): int(row[1] or 0)
            for row in db.execute(
                """SELECT lower(d.kind),COUNT(*) FROM plugin_security_dependencies d
                   JOIN plugin_security_current c ON c.scan_id=d.scan_id
                   WHERE c.status='complete' GROUP BY lower(d.kind) ORDER BY lower(d.kind)"""
            )
        }
        summary["nugetExactPackageVersionObservations"] = int(db.execute(
            """SELECT COUNT(*) FROM plugin_security_dependencies d JOIN plugin_security_current c ON c.scan_id=d.scan_id
               WHERE c.status='complete' AND lower(d.kind) IN ('nuget','nuget-lock','nuget-resolved')
                 AND TRIM(d.name)<>'' AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))<>''"""
        ).fetchone()[0])
        summary["nugetMissingVersionObservations"] = int(db.execute(
            """SELECT COUNT(*) FROM plugin_security_dependencies d JOIN plugin_security_current c ON c.scan_id=d.scan_id
               WHERE c.status='complete' AND lower(d.kind) IN ('nuget','nuget-lock','nuget-resolved')
                 AND TRIM(d.name)<>'' AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))=''"""
        ).fetchone()[0])
        summary["ipcProviderChannels"] = int(db.execute(
            """SELECT COUNT(*) FROM plugin_security_ipc_endpoints e JOIN plugin_security_current c ON c.scan_id=e.scan_id
               WHERE c.status='complete' AND e.role='provider' AND TRIM(e.channel)<>''"""
        ).fetchone()[0])
        summary["ipcConsumerChannels"] = int(db.execute(
            """SELECT COUNT(*) FROM plugin_security_ipc_endpoints e JOIN plugin_security_current c ON c.scan_id=e.scan_id
               WHERE c.status='complete' AND e.role='consumer' AND TRIM(e.channel)<>''"""
        ).fetchone()[0])
        summary["ipcUnresolvedConsumerChannels"] = int(db.execute(
            """SELECT COUNT(*) FROM plugin_security_ipc_endpoints e
               JOIN plugin_security_current c ON c.scan_id=e.scan_id
               LEFT JOIN plugin_security_ipc_registry r ON r.channel=e.channel
               WHERE c.status='complete' AND e.role='consumer' AND TRIM(e.channel)<>'' AND r.channel IS NULL"""
        ).fetchone()[0])
        summary["permissionCandidateRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_permission_candidates").fetchone()[0])
        summary["managedAssemblyRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_managed_assemblies").fetchone()[0])
        summary["managedSymbolRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_managed_symbols").fetchone()[0])
        summary["managedCallRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_managed_calls").fetchone()[0])
        summary["managedReachabilityRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_managed_reachability").fetchone()[0])
        summary["softDependencyRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependencies WHERE requirement='soft'").fetchone()[0])
        summary["dependencyResolutionRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependency_resolutions").fetchone()[0])
        summary["dependencyComponentRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependency_components").fetchone()[0])
        summary["dependencyIssueRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependency_issues").fetchone()[0])
        summary["dependencyAdvisoryMatchRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependency_advisory_matches").fetchone()[0])
        summary["dependencyDriftRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_dependency_drift").fetchone()[0])
        summary["sourceArtifactComparisonRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_source_artifact_comparisons").fetchone()[0])
        summary["scanLineageRows"] = int(db.execute("SELECT COUNT(*) FROM plugin_security_scan_lineage").fetchone()[0])
        write_scan_ledger(ledger_path, ledger, db, ledger_changed)
        summary["scanLedger"] = {
            "schema": SECURITY_LEDGER_SCHEMA,
            "entries": len(ledger.get("variants") or {}),
            "updated": ledger_changed,
        }
        summary["batchElapsedSeconds"] = round(time.monotonic() - batch_started, 3)
    finally:
        db.close()
    summary["finishedAtUtc"] = utc_now()
    Path(args.report).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.bundle and args.descriptor:
        update_descriptor(db_path, Path(args.bundle), Path(args.descriptor))
    return summary



def refresh_current_security_projection(
    db: sqlite3.Connection,
    advisories: list[dict] | None = None,
    advisory_coverage: dict[str, str | int] | None = None,
) -> dict[str, object]:
    """Refresh catalog/Definitions-derived security state without rescanning artifacts.

    This is shared by the 15-minute worker and the daily SQLite compiler. Static
    artifact evidence remains unchanged; only conclusions that legitimately depend on
    the current catalog or frozen Definitions payload are recomputed.
    """
    dependency_graph = refresh_dependency_graph(db, advisories)
    if advisory_coverage:
        coverage_meta = {
            "public_advisory_source": advisory_coverage.get("source", ""),
            "public_advisory_ecosystem": advisory_coverage.get("ecosystem", ""),
            "public_advisory_queried_packages": advisory_coverage.get("queriedPackages", 0),
            "public_advisory_matched_packages": advisory_coverage.get("matchedPackages", 0),
            "public_advisory_generated_at_utc": advisory_coverage.get("generatedAtUtc", ""),
        }
        for key, value in coverage_meta.items():
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES(?,?)", (key, str(value)))
    source_provenance = propagate_source_provenance_by_artifact(db)
    artifact_canonicalization = canonicalize_current_security_by_artifact(db)
    hash_consensus = refresh_cross_source_hash_findings(db)
    recreate_runtime_view(db)
    db.commit()
    return {
        "dependencyGraph": dependency_graph,
        "publicAdvisoryCoverage": dict(advisory_coverage or {}),
        "artifactSourceProvenance": source_provenance,
        "artifactSecurityCanonicalization": artifact_canonicalization,
        "crossSourceHashConsensus": hash_consensus,
    }


def load_source_overrides(path: Path | None) -> dict[str, str]:
    """Load only canonical GitHub repository overrides from the validated map."""
    if path is None or not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(document, dict):
        return {}
    raw = document.get("overrides") if document.get("schema") == "omega.source-overrides.v1" else document
    if not isinstance(raw, dict):
        return {}
    overrides: dict[str, str] = {}
    for key, value in raw.items():
        candidate = github_repository_url(str(value or ""))
        if candidate and str(key).startswith("src-"):
            overrides[str(key)] = candidate
    return overrides


def _build_self_test_managed_pe() -> bytes:
    """Build a tiny deterministic CLI image with real CIL call sites for parser regression tests."""
    strings = bytearray(b"\0")
    string_indexes: dict[str, int] = {}

    def add_string(value: str) -> int:
        if value in string_indexes:
            return string_indexes[value]
        index = len(strings)
        strings.extend(value.encode("utf-8") + b"\0")
        string_indexes[value] = index
        return index

    module_name = add_string("TestPlugin.dll")
    test_name = add_string("TestPlugin")
    fixture_type = add_string("Fixture")
    fixture_namespace = add_string("Omega.Tests")
    execute_method = add_string("OnFrameworkUpdate")
    http_name = add_string("HttpClient")
    http_namespace = add_string("System.Net.Http")
    process_name = add_string("Process")
    process_namespace = add_string("System.Diagnostics")
    get_async = add_string("GetAsync")
    process_start = add_string("Start")
    constructor = add_string(".ctor")
    native_method = add_string("NativeCall")
    native_module = add_string("user32.dll")
    native_entry = add_string("MessageBoxW")
    system_net_http = add_string("System.Net.Http")
    system_diagnostics_process = add_string("System.Diagnostics.Process")

    section_virtual_address = 0x2000
    method_offset_in_section = 0x50
    method_rva = section_virtual_address + method_offset_in_section

    valid_tables = (0, 1, 2, 6, 10, 26, 28, 32, 35)
    row_counts = {0: 1, 1: 2, 2: 1, 6: 2, 10: 3, 26: 1, 28: 1, 32: 1, 35: 2}
    valid_mask = sum(1 << table for table in valid_tables)
    table_stream = bytearray(struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0))
    for table in valid_tables:
        table_stream.extend(struct.pack("<I", row_counts[table]))

    # Module, TypeRef x2, TypeDef, MethodDef x2, MemberRef x2, ModuleRef,
    # ImplMap, Assembly, AssemblyRef x2. Heap indexes are 2-byte in this fixture.
    table_stream.extend(struct.pack("<HHHHH", 0, module_name, 0, 0, 0))
    table_stream.extend(struct.pack("<HHH", (1 << 2) | 2, http_name, http_namespace))
    table_stream.extend(struct.pack("<HHH", (2 << 2) | 2, process_name, process_namespace))
    table_stream.extend(struct.pack("<IHHHHH", 0x00000001, fixture_type, fixture_namespace, 0, 1, 1))
    table_stream.extend(struct.pack("<IHHHHH", method_rva, 0, 0x0016, execute_method, 0, 1))
    table_stream.extend(struct.pack("<IHHHHH", 0, 0, 0x2016, native_method, 0, 1))
    table_stream.extend(struct.pack("<HHH", (1 << 3) | 1, get_async, 0))
    table_stream.extend(struct.pack("<HHH", (2 << 3) | 1, process_start, 0))
    table_stream.extend(struct.pack("<HHH", (1 << 3) | 1, constructor, 0))
    table_stream.extend(struct.pack("<H", native_module))
    table_stream.extend(struct.pack("<HHHH", 0, (2 << 1) | 1, native_entry, 1))
    table_stream.extend(struct.pack("<IHHHHIHHH", 0x8004, 1, 2, 3, 4, 0, 0, test_name, 0))
    table_stream.extend(struct.pack("<HHHHIHHHH", 8, 0, 0, 0, 0, 0, system_net_http, 0, 0))
    table_stream.extend(struct.pack("<HHHHIHHHH", 8, 0, 0, 0, 0, 0, system_diagnostics_process, 0, 0))

    version = b"v4.0.30319\0"
    root = bytearray(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)))
    root.extend(version)
    while len(root) % 4:
        root.append(0)
    root.extend(struct.pack("<HH", 0, 2))

    stream_names = [("#~", bytes(table_stream)), ("#Strings", bytes(strings))]
    descriptor_size = sum(8 + ((len(name) + 1 + 3) & ~3) for name, _ in stream_names)
    next_offset = len(root) + descriptor_size
    descriptors = bytearray()
    payloads = bytearray()
    for name, payload in stream_names:
        while next_offset % 4:
            payloads.append(0)
            next_offset += 1
        descriptors.extend(struct.pack("<II", next_offset, len(payload)))
        encoded_name = name.encode("ascii") + b"\0"
        descriptors.extend(encoded_name)
        descriptors.extend(b"\0" * (((len(encoded_name) + 3) & ~3) - len(encoded_name)))
        payloads.extend(payload)
        next_offset += len(payload)
    metadata = bytes(root + descriptors + payloads)

    # Execute(): newobj HttpClient; callvirt HttpClient.GetAsync; call Process.Start;
    # call local NativeCall (which maps to user32!MessageBoxW); ldftn Process.Start; ret.
    il = bytearray()
    il.extend(b"\x73" + struct.pack("<I", 0x0A000003))
    il.extend(b"\x6f" + struct.pack("<I", 0x0A000001))
    il.extend(b"\x28" + struct.pack("<I", 0x0A000002))
    il.extend(b"\x28" + struct.pack("<I", 0x06000002))
    il.extend(b"\xfe\x06" + struct.pack("<I", 0x0A000002))
    il.append(0x2A)
    method_body = bytes([(len(il) << 2) | 0x02]) + bytes(il)

    file_alignment = 0x200
    section_alignment = 0x2000
    headers_size = 0x200
    cli_offset_in_section = 0
    metadata_offset_in_section = 0x80
    cli_rva = section_virtual_address + cli_offset_in_section
    metadata_rva = section_virtual_address + metadata_offset_in_section
    section_content = bytearray(metadata_offset_in_section + len(metadata))
    struct.pack_into("<IHHII", section_content, cli_offset_in_section, 0x48, 2, 5, metadata_rva, len(metadata))
    struct.pack_into("<II", section_content, cli_offset_in_section + 16, 1, 0)
    section_content[method_offset_in_section:method_offset_in_section + len(method_body)] = method_body
    section_content[metadata_offset_in_section:metadata_offset_in_section + len(metadata)] = metadata
    raw_size = (len(section_content) + file_alignment - 1) & ~(file_alignment - 1)
    section_content.extend(b"\0" * (raw_size - len(section_content)))

    pe_offset = 0x80
    optional_size = 0xF0
    headers = bytearray(headers_size)
    headers[:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, pe_offset)
    headers[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HHIIIHH", headers, coff, 0x8664, 1, 0, 0, 0, optional_size, 0x2022)
    optional = coff + 20
    struct.pack_into("<H", headers, optional, 0x20B)
    struct.pack_into("<I", headers, optional + 16, 0)
    struct.pack_into("<Q", headers, optional + 24, 0x140000000)
    struct.pack_into("<II", headers, optional + 32, section_alignment, file_alignment)
    struct.pack_into("<HHHHHH", headers, optional + 40, 6, 0, 0, 0, 6, 0)
    image_size = section_virtual_address + ((len(section_content) + section_alignment - 1) & ~(section_alignment - 1))
    struct.pack_into("<II", headers, optional + 56, image_size, headers_size)
    struct.pack_into("<H", headers, optional + 68, 3)
    struct.pack_into("<I", headers, optional + 108, 16)
    data_directories = optional + 112
    struct.pack_into("<II", headers, data_directories + 14 * 8, cli_rva, 0x48)
    section = optional + optional_size
    headers[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", headers, section + 8, len(section_content), section_virtual_address, raw_size, headers_size, 0, 0, 0, 0, 0x60000020)
    return bytes(headers + section_content)

def self_test() -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("TestPlugin.dll", _build_self_test_managed_pe())
        archive.writestr("native/helper.dll", b"MZ" + b"native" * 20)
        archive.writestr("TestPlugin.csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="FFXIVClientStructs" Version="7.2.0" />
    <PackageReference Include="DalamudPackager" Version="13.0.0" />
    <ProjectReference Include="../Shared/Shared.csproj" />
  </ItemGroup>
</Project>
""")
        archive.writestr("Services.cs", """
using System.Net.Http;
using System.Runtime.InteropServices;
using Dalamud.Plugin.Services;
using FFXIVClientStructs.FFXIV.Client.Game;

internal sealed class Services {
    private IClientState ClientState = null!;
    private IGameInteropProvider Interop = null!;
    [DllImport("user32.dll")] private static extern int MessageBox();
    void Ipc(dynamic pi) => pi.GetIpcSubscriber<int>("Omega.Test.Channel");
}
""")
        archive.writestr("plugin.json", '{"RequiredPlugins":[{"InternalName":"SomeExternalPlugin","Version":"[2.0.0,3.0.0)"},{"InternalName":"MissingRequiredPlugin","Version":">=1.0.0"}],"OptionalPlugins":[{"InternalName":"NiceToHavePlugin","Version":"<2.0.0"}],"PluginDependencies":[{"InternalName":"FlaggedSoftPlugin","Optional":true}]}')
        archive.writestr("packages.lock.json", '{"version":1,"dependencies":{"net10.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3"}}}}')
        archive.writestr("obj/project.assets.json", '{"libraries":{"Microsoft.Extensions.Http/10.0.0":{"type":"package"},"Shared/1.0.0":{"type":"project"}}}')

    hits: dict[str, list[str]] = defaultdict(list)
    intel = empty_dependency_intelligence("artifact")
    meta = scan_archive(payload.getvalue(), hits, intel)
    finalize_intelligence(intel)
    findings, capabilities = finding_payload(hits, meta)
    ids = {x["ruleId"] for x in findings}
    assert "network.http" in ids
    assert "process.launch" in ids
    assert "native.pinvoke" in ids
    assert "compound.network-execute" in ids
    assert "Network access" in capabilities

    deps = {(x["kind"], x["name"]) for x in intel["dependencies"]}
    assert ("nuget", "FFXIVClientStructs") in deps
    assert ("project-reference", "../Shared/Shared.csproj") in deps
    assert ("external-plugin", "SomeExternalPlugin") in deps
    assert ("external-plugin", "NiceToHavePlugin") in deps
    assert ("external-plugin", "FlaggedSoftPlugin") in deps
    assert any(x["name"] == "SomeExternalPlugin" and x["requirement"] == "required" for x in intel["dependencies"])
    assert any(x["name"] == "NiceToHavePlugin" and x["requirement"] == "soft" for x in intel["dependencies"])
    assert any(x["name"] == "FlaggedSoftPlugin" and x["requirement"] == "soft" for x in intel["dependencies"])
    assert any(x["name"] == "SomeExternalPlugin" and x["versionRequirement"] == "[2.0.0,3.0.0)" for x in intel["dependencies"])
    assert any(x["name"] == "MissingRequiredPlugin" and x["requirement"] == "required" for x in intel["dependencies"])
    assert any(x["kind"] == "ipc" and x["requirement"] == "soft" for x in intel["dependencies"])
    assert intel["coverage"]["requirements"]["soft"] >= 3
    assert ("nuget-lock", "Newtonsoft.Json") in deps
    assert any(x["kind"] == "nuget-lock" and x["name"] == "Newtonsoft.Json" and x["versionRequirement"] == "[13.0.3, )" and x["resolvedVersion"] == "13.0.3" for x in intel["dependencies"])
    assert version_satisfies("13.0.3", "[13.0.3, )") is True
    assert version_satisfies("2.4.0", "[2.0.0,3.0.0)") is True
    assert version_satisfies("3.0.0", "[2.0.0,3.0.0)") is False
    assert version_satisfies("1.5.0", "<2.0.0") is True
    assert version_satisfies("1.2.3", "banana") is None
    assert ("nuget-resolved", "Microsoft.Extensions.Http") in deps
    assert intel["coverage"]["binaryOnly"] >= 1
    assert intel["coverage"]["analyzed"] >= 3
    assert intel["coverage"]["externalPlugin"] >= 2
    assert any(x["kind"] == "native-library" and x["name"] == "helper.dll" for x in intel["dependencies"])
    assert any(x["kind"] == "managed-assembly" and x["name"] == "TestPlugin" and x["version"] == "1.2.3.4" for x in intel["dependencies"])
    assert any(x["kind"] == "managed-assembly-reference" and x["name"] == "System.Net.Http" for x in intel["dependencies"])
    assert any(x["kind"] == "member-reference" and x["declaringType"] == "System.Diagnostics.Process" and x["name"] == "Start" for x in intel["managedSymbols"])
    assert any(x["kind"] == "pinvoke" and x["declaringType"] == "user32.dll" and x["name"] == "MessageBoxW" for x in intel["managedSymbols"])
    assert any(x["opcode"] == "newobj" and x["targetDeclaringType"] == "System.Net.Http.HttpClient" and x["targetName"] == ".ctor" for x in intel["managedCallSites"])
    assert any(x["opcode"] == "callvirt" and x["targetDeclaringType"] == "System.Net.Http.HttpClient" and x["targetName"] == "GetAsync" for x in intel["managedCallSites"])
    assert any(x["opcode"] == "call" and x["targetDeclaringType"] == "System.Diagnostics.Process" and x["targetName"] == "Start" for x in intel["managedCallSites"])
    assert any(x["opcode"] == "ldftn" and x["targetName"] == "Start" for x in intel["managedCallSites"])
    assert any(x["targetKind"] == "pinvoke-method" and x["targetNativeLibrary"] == "user32.dll" and x["targetNativeEntryPoint"] == "MessageBoxW" for x in intel["managedCallSites"])
    assert any(x["sourceMethodName"] == "OnFrameworkUpdate" and x["targetMethodToken"] == "0x06000002" for x in intel["managedCallSites"])
    assert any(x["rootMethodName"] == "OnFrameworkUpdate" and x["methodName"] == "OnFrameworkUpdate" and x["depth"] == 0 for x in intel["managedReachability"])
    assert any(x["rootMethodName"] == "OnFrameworkUpdate" and x["methodName"] == "NativeCall" and x["depth"] == 1 for x in intel["managedReachability"])
    assert any(x["assemblyName"] == "TestPlugin" and x["assemblyVersion"] == "1.2.3.4" for x in intel["managedAssemblies"])
    assert any(x["service"] == "IClientState" for x in intel["dalamudServices"])
    assert any(x["channel"] == "Omega.Test.Channel" and x.get("role") == "consumer" for x in intel["ipcIntegrations"])
    provider_intel = empty_dependency_intelligence("source")
    provider_text = 'void Register(dynamic pi) => pi.GetIpcProvider<int>("Omega.Test.Channel").RegisterFunc(() => 1);'
    scan_source_text("ProviderPlugin/Ipc.cs", provider_text.encode("utf-8"), provider_text, provider_intel, defaultdict(list))
    finalize_intelligence(provider_intel)
    assert any(x["channel"] == "Omega.Test.Channel" and x.get("role") == "provider" for x in provider_intel["ipcIntegrations"])
    assert not any(x["kind"] == "ipc" for x in provider_intel["dependencies"]), "IPC providers must not become dependencies on themselves"

    required_ipc_text = 'class Client { void Initialize(dynamic pi) { var gate = pi.GetIpcSubscriber<int>("Omega.Required.Channel"); gate.InvokeFunc(); } }'
    required_ipc = empty_dependency_intelligence("source")
    scan_source_text("Client/Required.cs", required_ipc_text.encode("utf-8"), required_ipc_text, required_ipc, defaultdict(list))
    finalize_intelligence(required_ipc)
    required_dep = next(x for x in required_ipc["dependencies"] if x.get("kind") == "ipc")
    assert required_dep["relationship"] == "required" and required_dep["relationshipConfidence"] == "High"
    assert any("startup path" in evidence for evidence in required_dep["relationshipEvidence"])

    feature_ipc_text = 'class Client { void Feature(dynamic pi) { var gate = pi.GetIpcSubscriber<int>("Omega.Feature.Channel"); if (!gate.IsValid) return; Config.EnableFeature = true; } }'
    feature_ipc = empty_dependency_intelligence("source")
    scan_source_text("Client/Feature.cs", feature_ipc_text.encode("utf-8"), feature_ipc_text, feature_ipc, defaultdict(list))
    finalize_intelligence(feature_ipc)
    feature_dep = next(x for x in feature_ipc["dependencies"] if x.get("kind") == "ipc")
    assert feature_dep["relationship"] == "feature" and feature_dep["relationshipConfidence"] == "High"

    optional_ipc_text = 'class Client { void TryConnect(dynamic pi) { var gate = pi.GetIpcSubscriber<int>("Omega.Optional.Channel"); if (!gate.IsValid) return; } }'
    optional_ipc = empty_dependency_intelligence("source")
    scan_source_text("Client/Optional.cs", optional_ipc_text.encode("utf-8"), optional_ipc_text, optional_ipc, defaultdict(list))
    finalize_intelligence(optional_ipc)
    optional_dep = next(x for x in optional_ipc["dependencies"] if x.get("kind") == "ipc")
    assert optional_dep["relationship"] == "optional" and optional_dep["relationshipConfidence"] == "High"

    unknown_dep = next(x for x in intel["dependencies"] if x.get("kind") == "ipc")
    assert unknown_dep["relationship"] == "unknown" and unknown_dep["relationshipConfidence"] == "Low"
    assert any(x["library"] == "user32.dll" for x in intel["nativeImports"])
    candidate_ids = {x["permissionId"] for x in intel["permissionCandidates"]}
    assert "network.outbound" in candidate_ids
    assert "native.interop" in candidate_ids
    assert "game.state.read" in candidate_ids
    assert "game.memory.read" in candidate_ids
    assert "process.execute" in candidate_ids
    assert any(x["permissionId"] == "process.execute" and x["confidence"] == "VeryHigh" and "Compiled IL" in x["reason"] for x in intel["permissionCandidates"])
    assert any(x["permissionId"] == "native.interop" and x["confidence"] == "VeryHigh" for x in intel["permissionCandidates"])
    assert intel["fingerprints"]["relevantSourceSha256"]
    assert intel["fingerprints"]["projectDependencySha256"]

    # Exercise the real persistence path, not only parser helpers.
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY, internal_name TEXT NOT NULL DEFAULT '', canonical_name TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY, plugin_id INTEGER NOT NULL, name TEXT NOT NULL DEFAULT '', assembly_version TEXT NOT NULL DEFAULT '', testing_assembly_version TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE sources(source_id INTEGER PRIMARY KEY);
        CREATE TABLE catalog_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO plugins(plugin_id,internal_name,canonical_name) VALUES(1,'TestPlugin','Test Plugin');
        INSERT INTO plugins(plugin_id,internal_name,canonical_name) VALUES(2,'SomeExternalPlugin','Some External Plugin');
        INSERT INTO plugins(plugin_id,internal_name,canonical_name) VALUES(3,'NiceToHavePlugin','Nice To Have Plugin');
        INSERT INTO plugins(plugin_id,internal_name,canonical_name) VALUES(4,'ProviderPlugin','Provider Plugin');
        INSERT INTO plugin_variants(variant_id,plugin_id,name,assembly_version) VALUES(1,1,'Test Plugin','1.2.3.4');
        INSERT INTO plugin_variants(variant_id,plugin_id,name,assembly_version) VALUES(2,2,'Some External Plugin','2.4.0');
        INSERT INTO plugin_variants(variant_id,plugin_id,name,assembly_version) VALUES(3,3,'Nice To Have Plugin','1.5.0');
        INSERT INTO plugin_variants(variant_id,plugin_id,name,assembly_version) VALUES(4,4,'Provider Plugin','4.2.0');
        INSERT INTO sources(source_id) VALUES(1);
    """)
    ensure_schema(db)
    row = db.execute("""SELECT 1 AS plugin_id,1 AS variant_id,1 AS source_id,
                                'TestPlugin' AS internal_name,'Test Plugin' AS name,'Omega' AS author,
                                'Test source' AS source_name""").fetchone()
    counts = {severity: sum(1 for finding in findings if finding["severity"] == severity) for severity in ("informational", "caution", "high", "critical")}
    highest = next((severity for severity in ("critical", "high", "caution", "informational") if counts[severity]), "none")
    source_intel = empty_dependency_intelligence("source")
    add_dependency(source_intel, "external-plugin", "SomeExternalPlugin", "[2.0.0,3.0.0)", "plugin.json", "external-plugin", "source manifest", "required", version_requirement="[2.0.0,3.0.0)")
    add_dependency(source_intel, "nuget", "Newtonsoft.Json", "13.0.3", "TestPlugin.csproj", "known", "source PackageReference", "required", version_requirement="[13.0.3, )", resolved_version="13.0.3")
    finalize_intelligence(source_intel)
    combined_intel = merge_dependency_intelligence(intel, source_intel)
    automation_fixture = derive_automation_capabilities({
        **combined_intel,
        "managedCallSites": list(combined_intel.get("managedCallSites") or []) + [{
            "sourceMethodToken": "0x06000001",
            "targetDeclaringType": "FFXIVClientStructs.FFXIV.Client.Game.ActionManager",
            "targetName": "UseAction",
            "targetNativeEntryPoint": "",
            "evidence": ["il:Fixture.dll:OnFrameworkUpdate+0x10: call ActionManager.UseAction"],
        }],
        "managedReachability": list(combined_intel.get("managedReachability") or []) + [{"methodToken": "0x06000001"}],
        "ipcIntegrations": list(combined_intel.get("ipcIntegrations") or []) + [{"channel": "vnavmesh.Path.MoveTo"}],
    })
    assert automation_fixture["level"] == "full-gameplay-automation"
    assert any(x["capabilityId"] == "game.character.execute_action" and x["reachable"] for x in automation_fixture["capabilities"])
    assert any(x["capabilityId"] == "game.character.move" and x["indirect"] for x in automation_fixture["capabilities"])
    result = {
        "assemblyVersion": "1.2.3.4", "artifactChannel": "stable", "artifactUrl": "https://example.invalid/TestPlugin.zip",
        "artifactSha256": sha256_bytes(payload.getvalue()), "status": "complete", "scannedAtUtc": utc_now(),
        "highestSeverity": highest, "counts": counts, "capabilities": capabilities, "findings": findings,
        "automation": automation_fixture,
        "dependencyIntelligence": combined_intel,
        "package": {"dependencyIntelligence": intel},
        "source": {"available": True, "repository": "https://github.com/example/TestPlugin", "commit": "source-a", "dependencyIntelligence": source_intel},
        "error": "",
    }
    scan_id = save_scan(db, row, result)
    assert scan_id > 0
    assert db.execute("SELECT COUNT(*) FROM plugin_security_managed_assemblies WHERE scan_id=?", (scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_managed_symbols WHERE scan_id=?", (scan_id,)).fetchone()[0] >= 4
    assert db.execute("SELECT COUNT(*) FROM plugin_security_managed_calls WHERE scan_id=?", (scan_id,)).fetchone()[0] >= 5
    assert db.execute("SELECT COUNT(*) FROM plugin_security_managed_calls WHERE scan_id=? AND target_native_library='user32.dll'", (scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_managed_calls WHERE scan_id=? AND target_method_token='0x06000002'", (scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_managed_reachability WHERE scan_id=? AND method_name='NativeCall' AND depth=1", (scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependencies WHERE scan_id=? AND kind='managed-assembly-reference'", (scan_id,)).fetchone()[0] >= 2
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependencies WHERE scan_id=? AND requirement='soft'", (scan_id,)).fetchone()[0] >= 3
    assert db.execute("SELECT COUNT(*) FROM plugin_security_ipc_endpoints WHERE scan_id=? AND role='consumer' AND channel='Omega.Test.Channel'", (scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_permission_candidates WHERE scan_id=? AND permission_id='process.execute'", (scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_automation_capabilities WHERE scan_id=? AND capability_id='game.character.execute_action' AND reachable=1", (scan_id,)).fetchone()[0] == 1
    current_automation = db.execute("SELECT automation_level,automation_capabilities_json FROM plugin_security_current WHERE variant_id=1").fetchone()
    assert current_automation is not None and current_automation["automation_level"] == "full-gameplay-automation"
    comparison = db.execute("SELECT source_available,matched_component_count,comparison_status FROM plugin_security_source_artifact_comparisons WHERE scan_id=?", (scan_id,)).fetchone()
    assert comparison is not None and comparison["source_available"] == 1 and comparison["matched_component_count"] >= 2
    assert comparison["comparison_status"] == "compared-not-verified"
    baseline_lineage = db.execute("SELECT previous_scan_id,change_basis FROM plugin_security_scan_lineage WHERE current_scan_id=?", (scan_id,)).fetchone()
    assert baseline_lineage is not None and baseline_lineage["previous_scan_id"] is None and baseline_lineage["change_basis"] == "baseline"

    # Add a second current plugin using the same package so component cross-reference is exercised.
    cur = db.execute("INSERT INTO plugin_security_scans(plugin_id,variant_id,source_id,status) VALUES(2,2,1,'complete')")
    other_scan_id = int(cur.lastrowid)
    db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,status) VALUES(2,?,'complete')", (other_scan_id,))
    db.execute("""INSERT INTO plugin_security_dependencies(scan_id,origin,kind,name,version,version_requirement,resolved_version,path,status,requirement,evidence_json)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (other_scan_id,'artifact','nuget-lock','Newtonsoft.Json','12.0.3','[12.0.0,13.0.0)','12.0.3','packages.lock.json','known','required','[]'))

    provider_scan = db.execute("INSERT INTO plugin_security_scans(plugin_id,variant_id,source_id,status) VALUES(4,4,1,'complete')")
    provider_scan_id = int(provider_scan.lastrowid)
    db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,status) VALUES(4,?,'complete')", (provider_scan_id,))
    db.execute("""INSERT INTO plugin_security_ipc_endpoints(scan_id,origin,role,channel,signature,path,status)
                  VALUES(?,?,?,?,?,?,?)""", (provider_scan_id,'source','provider','Omega.Test.Channel','System.Int32','ProviderPlugin/Ipc.cs','provider-handle'))

    graph = refresh_dependency_graph(db, [{
        "id": "TEST-ADV-001", "componentKind": "nuget", "name": "Newtonsoft.Json",
        "affectedRange": "<13.0.4", "fixedVersion": "13.0.4", "severity": "high",
        "title": "Synthetic Newtonsoft advisory", "source": "self-test"
    }])
    assert graph["resolvedPluginDependencies"] >= 2
    assert graph["unresolvedPluginDependencies"] >= 2
    assert graph["missingRequiredDependencies"] >= 1
    assert graph["divergentComponents"] >= 1
    assert graph["advisoryMatches"] >= 2
    assert graph["ipcProviderChannels"] >= 1 and graph["resolvedIpcDependencies"] >= 1
    ipc_edge = db.execute("""SELECT resolution_status,target_plugin_id,target_variant_id,target_internal_name,match_basis,target_version
                              FROM plugin_security_dependency_resolutions
                             WHERE scan_id=? AND dependency_kind='ipc' AND dependency_name='Omega.Test.Channel'""", (scan_id,)).fetchone()
    assert ipc_edge is not None and ipc_edge["resolution_status"] == 'resolved-ipc-provider'
    assert ipc_edge["target_plugin_id"] == 4 and ipc_edge["target_variant_id"] == 4 and ipc_edge["target_internal_name"] == 'ProviderPlugin'
    assert ipc_edge["match_basis"] == 'exact-ipc-channel-provider' and ipc_edge["target_version"] == '4.2.0'
    assert db.execute("SELECT COUNT(*) FROM plugin_security_ipc_registry WHERE channel='Omega.Test.Channel' AND provider_plugin_id=4").fetchone()[0] == 1
    required_edge = db.execute("""SELECT resolution_status,target_plugin_id,target_variant_id,requirement,match_basis,version_status,target_version
                                   FROM plugin_security_dependency_resolutions
                                  WHERE scan_id=? AND dependency_name='SomeExternalPlugin'""", (scan_id,)).fetchone()
    assert required_edge is not None and required_edge["resolution_status"] == 'resolved-plugin'
    assert required_edge["target_plugin_id"] == 2 and required_edge["target_variant_id"] == 2
    assert required_edge["requirement"] == 'required' and required_edge["match_basis"] == 'internal-name'
    assert required_edge["version_status"] == 'compatible' and required_edge["target_version"] == '2.4.0'
    soft_edge = db.execute("""SELECT resolution_status,target_plugin_id,requirement FROM plugin_security_dependency_resolutions
                               WHERE scan_id=? AND dependency_name='NiceToHavePlugin'""", (scan_id,)).fetchone()
    assert soft_edge is not None and soft_edge["resolution_status"] == 'resolved-plugin' and soft_edge["target_plugin_id"] == 3
    assert soft_edge["requirement"] == 'soft'
    unresolved = db.execute("""SELECT resolution_status,requirement FROM plugin_security_dependency_resolutions
                                WHERE scan_id=? AND dependency_name='FlaggedSoftPlugin'""", (scan_id,)).fetchone()
    assert unresolved is not None and unresolved["resolution_status"] == 'external-unresolved' and unresolved["requirement"] == 'soft'
    shared = db.execute("""SELECT current_usage_count,source_plugin_count,versions_json,distinct_version_count,version_divergence FROM plugin_security_dependency_components
                            WHERE component_key='nuget:newtonsoft.json'""").fetchone()
    assert shared is not None and shared["current_usage_count"] >= 2 and shared["source_plugin_count"] == 2
    assert '13.0.3' in shared["versions_json"] and '12.0.3' in shared["versions_json"]
    assert shared["distinct_version_count"] >= 2 and shared["version_divergence"] == 'major-version-divergence'
    missing_issue = db.execute("SELECT severity,issue_code FROM plugin_security_dependency_issues WHERE issue_code='missing-required-plugin'").fetchone()
    assert missing_issue is not None and missing_issue["severity"] == 'high'
    soft_issue = db.execute("SELECT severity FROM plugin_security_dependency_issues WHERE issue_code='soft-plugin-unresolved'").fetchone()
    assert soft_issue is not None and soft_issue["severity"] == 'informational'
    divergence_issue = db.execute("SELECT severity FROM plugin_security_dependency_issues WHERE issue_code='major-component-version-divergence'").fetchone()
    assert divergence_issue is not None and divergence_issue["severity"] == 'caution'
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependency_advisory_matches WHERE advisory_id='TEST-ADV-001'").fetchone()[0] >= 2
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependency_components WHERE component_key='plugin:nicetohaveplugin'").fetchone()[0] == 1

    # A later completed scan records immutable lineage and semantic drift.
    changed_artifact = json.loads(json.dumps(intel))
    for dependency in changed_artifact["dependencies"]:
        if dependency["kind"] == "nuget-lock" and dependency["name"] == "Newtonsoft.Json":
            dependency["version"] = "14.0.0"
            dependency["resolvedVersion"] = "14.0.0"
            dependency["versionRequirement"] = "[14.0.0, )"
    add_dependency(changed_artifact, "external-plugin", "NewSoftIntegration", "", "plugin.json", "external-plugin", "new soft integration", "soft")
    add_permission_candidate(changed_artifact, "filesystem.delete", "High", "High", "Deterministic dependency drift test fixture.", "fixture")
    finalize_intelligence(changed_artifact)
    changed_source = json.loads(json.dumps(source_intel))
    add_dependency(changed_source, "external-plugin", "NewSoftIntegration", "", "plugin.json", "external-plugin", "new source soft integration", "soft")
    finalize_intelligence(changed_source)
    changed_combined = merge_dependency_intelligence(changed_artifact, changed_source)
    changed_result = {
        "assemblyVersion": "1.2.4.0", "artifactChannel": "stable", "artifactUrl": "https://example.invalid/TestPlugin-v2.zip",
        "artifactSha256": sha256_bytes(payload.getvalue() + b"dependency-drift-v2"), "status": "complete", "scannedAtUtc": utc_now(),
        "highestSeverity": highest, "counts": counts, "capabilities": capabilities, "findings": findings,
        "automation": automation_fixture,
        "dependencyIntelligence": changed_combined, "package": {"dependencyIntelligence": changed_artifact},
        "source": {"available": True, "repository": "https://github.com/example/TestPlugin", "commit": "source-b", "dependencyIntelligence": changed_source},
        "error": "",
    }
    changed_scan_id = save_scan(db, row, changed_result)
    lineage = db.execute("SELECT previous_scan_id,artifact_changed,source_changed,assembly_version_changed,change_basis FROM plugin_security_scan_lineage WHERE current_scan_id=?", (changed_scan_id,)).fetchone()
    assert lineage is not None and lineage["previous_scan_id"] == scan_id
    assert lineage["artifact_changed"] == 1 and lineage["source_changed"] == 1 and lineage["assembly_version_changed"] == 1
    assert lineage["change_basis"] == "artifact-and-source-changed"
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependency_drift WHERE current_scan_id=? AND change_type='version-changed'", (changed_scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependency_drift WHERE current_scan_id=? AND change_type='dependency-added' AND dependency_name='NewSoftIntegration'", (changed_scan_id,)).fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependency_drift WHERE current_scan_id=? AND change_type='permission-added' AND dependency_name='filesystem.delete'", (changed_scan_id,)).fetchone()[0] >= 1
    changed_comparison = db.execute("SELECT comparison_status,matched_component_count FROM plugin_security_source_artifact_comparisons WHERE scan_id=?", (changed_scan_id,)).fetchone()
    assert changed_comparison is not None and changed_comparison["comparison_status"] == "compared-not-verified" and changed_comparison["matched_component_count"] >= 2
    assert changed_result["sourceArtifactComparison"]["sourceToBinaryVerified"] is False
    assert changed_result["dependencyHistory"]["events"] >= 3
    db.close()

    # A malformed method body is isolated to IL analysis: metadata remains usable
    # and the parser reports bounded IL errors instead of loading/executing anything.
    malformed_il = bytearray(_build_self_test_managed_pe())
    malformed_il[0x200 + 0x50] = 0x03  # fat format with an invalid zero-DWORD header size
    malformed_meta = parse_managed_pe(bytes(malformed_il), "MalformedIl.dll")
    assert malformed_meta is not None
    assert malformed_meta["parseStatus"] == "complete"
    assert malformed_meta["il"]["errors"] == 1
    assert malformed_meta["il"]["errorSamples"]
    assert not malformed_meta["callSites"]

    corrupt_managed = bytearray(_build_self_test_managed_pe())
    corrupt_managed[0x280:0x284] = b"NOPE"
    corrupt_package = io.BytesIO()
    with zipfile.ZipFile(corrupt_package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("BrokenManaged.dll", bytes(corrupt_managed))
    corrupt_intel = empty_dependency_intelligence("artifact")
    corrupt_meta = scan_archive(corrupt_package.getvalue(), defaultdict(list), corrupt_intel)
    finalize_intelligence(corrupt_intel)
    assert corrupt_meta["managedMetadataErrors"]
    assert "BrokenManaged.dll" in corrupt_meta["bundledManagedAssemblies"]
    assert "BrokenManaged.dll" not in corrupt_meta["bundledNativeLibraries"]
    assert any(x["kind"] == "managed-assembly" and x["status"] == "not-analyzed" for x in corrupt_intel["dependencies"])

    try:
        bad = io.BytesIO()
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("../escape.dll", b"MZ")
        scan_archive(bad.getvalue(), defaultdict(list))
        raise AssertionError("path traversal was accepted")
    except ValueError:
        pass
    try:
        validate_public_https_url("https://localhost/plugin.zip")
        raise AssertionError("localhost SSRF target was accepted")
    except ValueError:
        pass
    print("Omega Sigmascope security/dependency self-test passed.")


def hardening_self_test() -> None:
    """Exercise pathological inputs and catalog-scale projection hardening."""
    # Plugin packages may legitimately be large because they bundle media/resources. The
    # download and uncompressed-size guards remain finite while allowing production-sized
    # packages that exceed the former 64 MiB download ceiling.
    assert MAX_ARTIFACT_BYTES == 256 * 1024 * 1024
    assert MAX_ARCHIVE_UNCOMPRESSED == 512 * 1024 * 1024

    # Real plugin packages can legitimately contain thousands of small resources. Keep the
    # central-directory guard bounded, but prove that packages larger than the old 1,024-entry
    # ceiling (including the 2,342-entry production example) remain scannable.
    many_entries = io.BytesIO()
    with zipfile.ZipFile(many_entries, "w", compression=zipfile.ZIP_STORED) as archive:
        for i in range(3000):
            archive.writestr(f"resources/item-{i:04d}.txt", b"x")
    many_metadata = scan_archive(many_entries.getvalue(), defaultdict(list))
    assert many_metadata["archive"] is True and many_metadata["files"] == 3000

    # The entry-count protection itself must remain active. Use a temporarily tiny ceiling so
    # the hardening fixture stays fast while still exercising the rejection path.
    old_archive_entry_limit = MAX_ARCHIVE_ENTRIES
    globals()["MAX_ARCHIVE_ENTRIES"] = 8
    try:
        too_many = io.BytesIO()
        with zipfile.ZipFile(too_many, "w", compression=zipfile.ZIP_STORED) as archive:
            for i in range(9):
                archive.writestr(f"bounded/{i}.txt", b"x")
        try:
            scan_archive(too_many.getvalue(), defaultdict(list))
            raise AssertionError("archive entry hard limit was not enforced")
        except ValueError as exc:
            assert "Archive has 9 entries; limit is 8" in str(exc)
    finally:
        globals()["MAX_ARCHIVE_ENTRIES"] = old_archive_entry_limit

    # Duplicate normalized paths are ambiguous and must never be analyzed differently by case/order.
    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("Plugin/Thing.dll", b"MZ")
        archive.writestr("plugin/thing.dll", b"MZ")
    try:
        scan_archive(duplicate.getvalue(), defaultdict(list))
        raise AssertionError("duplicate normalized ZIP path was accepted")
    except ValueError as exc:
        assert "duplicate normalized path" in str(exc)

    # Symlink-like members are rejected even though Sigmascope never extracts archives.
    link_payload = io.BytesIO()
    with zipfile.ZipFile(link_payload, "w") as archive:
        info = zipfile.ZipInfo("linked.dll")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        archive.writestr(info, b"target.dll")
    try:
        scan_archive(link_payload.getvalue(), defaultdict(list))
        raise AssertionError("ZIP symbolic link was accepted")
    except ValueError as exc:
        assert "symbolic-link" in str(exc)

    # Redirect targets are validated before following, and authorization never crosses hosts.
    handler = ValidatingRedirectHandler()
    request = urllib.request.Request("https://github.com/example/plugin.zip", headers={"Authorization": "Bearer secret"})
    try:
        handler.redirect_request(request, None, 302, "Found", {}, "https://localhost/redirected.zip")
        raise AssertionError("redirect to localhost was accepted")
    except ValueError:
        pass
    redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://8.8.8.8/redirected.zip")
    assert redirected is not None and redirected.get_header("Authorization") is None

    # Per-scan evidence ceilings are explicit rather than silently dropping records.
    intel = empty_dependency_intelligence("source")
    old_limit = INTELLIGENCE_LIST_LIMITS["dependencies"]
    INTELLIGENCE_LIST_LIMITS["dependencies"] = 8
    try:
        for i in range(20):
            add_dependency(intel, "nuget", f"Package{i}", "1.0.0", "fixture.csproj", "known", requirement="required")
        finalize_intelligence(intel)
        assert len(intel["dependencies"]) == 8
        assert intel["limits"]["truncated"] is True
        assert intel["limits"]["droppedByCollection"]["dependencies"] == 12
    finally:
        INTELLIGENCE_LIST_LIMITS["dependencies"] = old_limit

    # A moderate synthetic current graph must be exact, idempotent and suppress framework-version noise.
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE plugins(plugin_id INTEGER PRIMARY KEY,internal_name TEXT,canonical_name TEXT,active INTEGER DEFAULT 1);
        CREATE TABLE sources(source_id INTEGER PRIMARY KEY,name TEXT);
        CREATE TABLE plugin_variants(variant_id INTEGER PRIMARY KEY,plugin_id INTEGER,source_id INTEGER,name TEXT,assembly_version TEXT,testing_assembly_version TEXT,active INTEGER DEFAULT 1);
        CREATE TABLE catalog_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    """)
    ensure_schema(db)
    db.execute("INSERT INTO sources(source_id,name) VALUES(1,'fixture')")
    for i in range(1, 301):
        db.execute("INSERT INTO plugins(plugin_id,internal_name,canonical_name,active) VALUES(?,?,?,1)", (i, f"Plugin{i}", f"Plugin {i}"))
        db.execute("INSERT INTO plugin_variants(variant_id,plugin_id,source_id,name,assembly_version,active) VALUES(?,?,?,?,?,1)", (i, i, 1, f"Plugin {i}", "1.0.0"))
        cur = db.execute("INSERT INTO plugin_security_scans(plugin_id,variant_id,source_id,status,scanner_version) VALUES(?,?,1,'complete',?)", (i, i, SCANNER_VERSION))
        scan_id = int(cur.lastrowid)
        db.execute("INSERT INTO plugin_security_current(variant_id,scan_id,status,scanner_version) VALUES(?,?,'complete',?)", (i, scan_id, SCANNER_VERSION))
        for j in range(30):
            db.execute("""INSERT INTO plugin_security_dependencies(scan_id,origin,kind,name,version,path,status,requirement,evidence_json)
                          VALUES(?,?,?,?,?,'fixture','analyzed','observed','[]')""", (scan_id, "artifact", "nuget", f"Shared{j}", f"{1 + (i % 2)}.0.0"))
        db.execute("""INSERT INTO plugin_security_dependencies(scan_id,origin,kind,name,version,path,status,requirement,evidence_json)
                      VALUES(?,?,?,?,?,'fixture','analyzed','observed','[]')""", (scan_id, "artifact", "managed-assembly-reference", "System.Runtime", f"{6 + (i % 2)}.0.0"))
    db.commit()
    old_graph_limit = MAX_CURRENT_DEPENDENCY_ROWS
    globals()["MAX_CURRENT_DEPENDENCY_ROWS"] = 100
    try:
        try:
            refresh_dependency_graph(db, [])
            raise AssertionError("oversized current dependency graph was accepted")
        except RuntimeError as exc:
            assert "hard limit" in str(exc)
    finally:
        globals()["MAX_CURRENT_DEPENDENCY_ROWS"] = old_graph_limit
    first = refresh_dependency_graph(db, [])
    first_components = db.execute("SELECT component_key,versions_json,version_divergence FROM plugin_security_dependency_components ORDER BY component_key").fetchall()
    first_issues = db.execute("SELECT component_key,issue_code,severity FROM plugin_security_dependency_issues ORDER BY component_key,issue_code,severity").fetchall()
    second = refresh_dependency_graph(db, [])
    second_components = db.execute("SELECT component_key,versions_json,version_divergence FROM plugin_security_dependency_components ORDER BY component_key").fetchall()
    second_issues = db.execute("SELECT component_key,issue_code,severity FROM plugin_security_dependency_issues ORDER BY component_key,issue_code,severity").fetchall()
    assert first["dependencies"] == 9300
    assert first["dependencies"] == second["dependencies"]
    assert [tuple(row) for row in first_components] == [tuple(row) for row in second_components]
    assert [tuple(row) for row in first_issues] == [tuple(row) for row in second_issues]
    platform = db.execute("SELECT version_divergence FROM plugin_security_dependency_components WHERE component_key='assembly:system.runtime'").fetchone()
    assert platform is not None and platform[0] == "platform-version-variation"
    assert db.execute("SELECT COUNT(*) FROM plugin_security_dependency_issues WHERE component_key='assembly:system.runtime'").fetchone()[0] == 0
    health = validate_database_health(db)
    assert health["currentDependencies"] == 9300 and health["dependencyResolutions"] == 9300
    db.close()
    print("Omega Sigmascope hardening self-test passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Omega Sigmascope against plugin artifacts without executing them")
    parser.add_argument("--database", default="catalog/dist/omega-catalog.sqlite")
    parser.add_argument("--bundle", default="")
    parser.add_argument("--descriptor", default="")
    parser.add_argument("--report", default="catalog/security-report.json")
    parser.add_argument("--ledger", default="", help="Optional persistent operational revalidation ledger; it does not define semantic security identity")
    parser.add_argument("--max-scans", type=int, default=60)
    parser.add_argument("--max-batch-seconds", type=int, default=DEFAULT_MAX_BATCH_SECONDS, help="Stop starting new Sigmascope examinations after this wall-clock budget; 0 disables the budget")
    parser.add_argument("--rescan-after-hours", type=int, default=168)
    parser.add_argument("--internal-names", default="")
    parser.add_argument("--variant-ids", default="", help="Optional exact comma-separated variant IDs; used by the persistent production queue")
    parser.add_argument("--advisories", default="", help="Optional local JSON advisory document; Sigmascope does not fetch advisory data itself")
    parser.add_argument("--source-overrides", default="sources/source-overrides.json", help="Optional validated plugin/source-to-GitHub-source override map")
    parser.add_argument("--skip-source", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--hardening-self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.hardening_self_test:
        hardening_self_test()
        return 0
    report = run(args)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
