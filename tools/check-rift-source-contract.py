#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
checks = []

def require(path: Path, needle: str, desc: str):
    text = (root / path).read_text(encoding="utf-8")
    if needle not in text:
        print(f"FAIL: {desc}: {path} missing {needle!r}", file=sys.stderr)
        raise SystemExit(1)
    checks.append(desc)

def forbid(path: Path, needle: str, desc: str):
    text = (root / path).read_text(encoding="utf-8")
    if needle in text:
        print(f"FAIL: {desc}: {path} still contains {needle!r}", file=sys.stderr)
        raise SystemExit(1)
    checks.append(desc)

# Real API-15 contract identity, not generated public shims.
require(Path("InterdimensionalRift/Runtime/DalamudContract.cs"), "RIFT_DALAMUD_CONTRACT_DIR", "frozen real Dalamud contract loader")
require(Path("InterdimensionalRift/Runtime/DalamudContract.cs"), "EnterSandboxFailFastHostMode", "internal service locator fail-fast mode")
require(Path("InterdimensionalRift/Runtime/DalamudContract.cs"), "UnloadCancellationTokenSource", "fail-fast uses Dalamud cancellation path")
require(Path("InterdimensionalRift/Host/PluginLoader.cs"), "DalamudContract.Assembly", "shared exact Dalamud CLR identity")
require(Path("InterdimensionalRift/Host/PluginLoader.cs"), "ArtifactNativeLibraryResolver.Find", "artifact-native resolver active")
require(Path("InterdimensionalRift/Host/ArtifactNativeLibraryResolver.cs"), "runtimes", "RID native layout supported")
forbid(Path("InterdimensionalRift/InterdimensionalRift.csproj"), "InterdimensionalRift.DalamudShim", "active host does not target generated shim")
forbid(Path("InterdimensionalRift/InterdimensionalRift.csproj"), "System.Reflection.Metadata", "static metadata scanner dependency absent")

# Lifecycle/instrumentation.
require(Path("InterdimensionalRift/Host/SandboxHost.cs"), "LoadAsync", "API-15 async lifecycle")
forbid(Path("InterdimensionalRift/Host/SandboxHost.cs"), "InitializeAsync", "obsolete async lifecycle removed")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), "PluginServiceAttribute", "PluginService injection")
require(Path("InterdimensionalRift/Host/SandboxHost.cs"), "dalamud.internal_service_locator", "fail-fast compatibility state recorded")

# Runtime-only report model.
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "rift.runtime-observation.v1", "runtime observation schema version")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), 'ProducerVersion { get; set; } = "0.3.2"', "producer version 0.3.2")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "boundary_profile", "boundary profile provenance")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "tmpfs_tmp_bytes", "tmpfs provenance")
require(Path("InterdimensionalRift/Reporting/RuntimeObservation.cs"), "RuntimeObservationKind", "neutral observation model")
forbid(Path("InterdimensionalRift/Reporting/RuntimeObservation.cs"), "Severity", "runtime report has no severity")
forbid(Path("InterdimensionalRift/Host/SandboxHost.cs"), "HttpReferenceScanner", "Rift host performs no static scan")
if (root / "InterdimensionalRift/Instrumentation/HttpReferenceScanner.cs").exists():
    raise SystemExit("FAIL: transitional HttpReferenceScanner still exists")
checks.append("transitional static scanner source removed")

# Supervisor boundary/profile.
require(Path("tools/run-rift-bwrap.sh"), "--unshare-net", "network namespace isolated")
require(Path("tools/run-rift-bwrap.sh"), "--disable-userns", "nested user namespaces disabled")
require(Path("tools/run-rift-bwrap.sh"), "--cap-drop ALL", "Linux capabilities dropped")
require(Path("tools/run-rift-bwrap.sh"), "--clearenv", "host environment cleared")
require(Path("tools/run-rift-bwrap.sh"), 'MemorySwapMax=0', "swap disabled")
require(Path("tools/run-rift-bwrap.sh"), 'KillMode=control-group', "whole cgroup killed")
require(Path("tools/run-rift-bwrap.sh"), 'SendSIGKILL=yes', "stubborn descendants receive SIGKILL")
require(Path("tools/run-rift-bwrap.sh"), 'rift.supervisor.v3', "supervisor schema v3")
require(Path("tools/run-rift-bwrap.sh"), 'outcome=memory_limit', "memory cgroup supervisor classification")
require(Path("tools/run-rift-bwrap.sh"), 'outcome=tasks_limit', "tasks cgroup supervisor classification")
require(Path("tools/run-rift-bwrap.sh"), 'outcome=process_killed', "signal-kill supervisor classification")
require(Path("tools/exec-rift-scope.sh"), 'memory_oom_kill_delta', "memory.events accounting")
require(Path("tools/exec-rift-scope.sh"), 'pids_max_delta', "pids.events accounting")
require(Path("tools/run-rift-bwrap.sh"), 'RIFT_BOUNDARY_PROFILE', "boundary profile stamped into host")
require(Path("tools/run-rift-bwrap.sh"), 'RIFT_TMPFS_TMP_BYTES', "tmpfs limits stamped into host")
require(Path("tools/run-rift-bwrap.sh"), 'RIFT_MEMORY_SWAP_MAX', "swap policy stamped into host")

# Alpha = suspicious harmless reference subject.
require(Path("tests/fixtures/RiftAlpha/RiftAlpha.csproj"), "Rift.Dalamud.Contract.props", "Alpha compiles against frozen contract")
require(Path("tests/fixtures/RiftAlpha/Plugin.cs"), "RIFT_ALPHA armed inside Rift", "Alpha canonical runtime marker")
require(Path("tests/fixtures/RiftAlpha/Plugin.cs"), "ClientState.IsLoggedIn", "Alpha tracks current API-15 IClientState")
require(Path("tools/check-alpha-contract.py"), "Alpha contract: PASS", "Alpha source safety checker")
require(Path("tools/package-alpha.sh"), "RiftAlpha.dll", "Alpha DLL-only packager")
require(Path(".github/workflows/rift-alpha.yml"), "Rift Alpha reference subject", "Alpha dedicated workflow")

# Canary = environmental sentinel.
require(Path("tests/fixtures/RiftCanary/RiftCanary.csproj"), "Rift.Dalamud.Contract.props", "Canary compiles against frozen contract")
for marker in (
    "boundary.artifact_readonly",
    "boundary.runtime_readonly",
    "boundary.contracts_readonly",
    "boundary.host_secrets_absent",
    "boundary.no_new_privileges",
    "boundary.capabilities_dropped",
    "boundary.network_isolated",
    "boundary.nested_userns_denied",
    "boundary.ptrace_denied",
    "boundary.raw_packet_socket_denied",
    "boundary.tmpfs_tmp_bounded",
    "boundary.tmpfs_home_bounded",
    "boundary.tmpfs_work_bounded",
    "boundary.hostname_isolated",
):
    require(Path("tests/fixtures/RiftCanary/Plugin.cs"), marker, f"Canary probe {marker}")
require(Path("tools/check-canary-contract.py"), "Canary contract: PASS", "Canary source safety checker")
require(Path("tools/package-canary.sh"), "RiftCanary.dll", "Canary DLL-only packager")
require(Path(".github/workflows/rift-canary.yml"), "Rift environmental Canary", "Canary dedicated workflow")

# Containment stress qualification.
for name in ("RiftMemoryPressure", "RiftTaskPressure", "RiftTmpfsPressure", "RiftHangTree"):
    require(Path(f"tests/fixtures/{name}/{name}.csproj"), "Rift.Dalamud.Contract.props", f"{name} frozen-contract build")
    require(Path(f"tests/fixtures/{name}/Plugin.cs"), "RIFT_STRESS", f"{name} stress marker")
require(Path("tests/fixtures/RiftHangTree/rift-hang-child.c"), "SIG_IGN", "hang-tree stubborn child")
require(Path("tools/check-sandbox-fixtures.py"), "Rift containment stress fixture contract: PASS", "stress fixture safety checker")
require(Path("tools/package-sandbox-fixture.sh"), "RiftHangTree", "stress fixture packager")
require(Path("tools/validate-rift-report.py"), '--mode', "central result validator")
require(Path(".github/workflows/rift-containment-stress.yml"), "Rift containment stress qualification", "containment stress workflow")
require(Path(".github/workflows/rift-containment-stress.yml"), "Rift process-tree cleanup: PASS", "stubborn descendant cleanup assertion")

# Unit regressions.
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "Alpha_IsInertOutsideRiftBoundary", "Alpha inert regression")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "Canary_IsInertOutsideRiftBoundary", "Canary inert regression")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "ContainmentStressFixtures_AreInertOutsideRift", "stress fixtures inert regression")
require(Path("tests/InterdimensionalRift.Tests/DalamudInternalServiceFailFastTest.cs"), "InternalDalamudServiceLocator_FailsFastInsteadOfBlocking", "internal service fail-fast regression")
require(Path("tests/InterdimensionalRift.Tests/RuntimeObservationSchemaTest.cs"), 'Assert.False(root.TryGetProperty("findings"', "no findings key regression")
require(Path("tests/InterdimensionalRift.Tests/RuntimeObservationSchemaTest.cs"), 'Assert.DoesNotContain("severity"', "no severity regression")

require(Path("tests/InterdimensionalRift.Tests/AssemblyInfo.cs"), "DisableTestParallelization = true", "process-global Rift tests are serialized")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "host_os", "runtime host OS provenance")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "runtime_identifier", "runtime RID provenance")
require(Path("InterdimensionalRift/Reporting/RuntimeObservation.cs"), "NativeLibrary", "native library observation kind")
require(Path("InterdimensionalRift/Host/PluginLoader.cs"), 'tracker.NativeLibrary(unmanagedDllName, null, "unresolved")', "unresolved native loads are observed")
require(Path("InterdimensionalRift/Host/PluginLoader.cs"), 'tracker.NativeLibrary(unmanagedDllName, resolved, "resolved")', "resolved native loads are observed")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "omega.player-environment-support.v1", "player-environment evidence producer")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "GetImport()", "PInvoke metadata inventory")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), 'TargetRuntime { get; set; } = "windows-dalamud"', "Dalamud target runtime is Windows")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "windows-guest-dependency", "Windows guest native dependency inventory")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "host-native-auxiliary", "host-native auxiliary asset classification")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "analysis-only-not-player-compatibility", "native Rift cannot falsely verify Wine/CrossOver support")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "linux-wine-proton", "Linux player environment is Wine/Proton")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "macos-crossover-wine", "macOS player environment is CrossOver/Wine")
require(Path("schemas/omega-player-environment-support-v1.schema.json"), "omega.player-environment-support.v1", "player-environment support JSON schema")
require(Path(".github/workflows/rift-scan-omega.yml"), "Build player-environment compatibility evidence", "published Omega compatibility evidence step")

# Machine-readable contracts.
require(Path("schemas/rift-runtime-observation-v1.schema.json"), "rift.runtime-observation.v1", "runtime JSON schema")
require(Path("schemas/rift-supervisor-v3.schema.json"), "rift.supervisor.v3", "supervisor JSON schema")
require(Path("docs/RUNTIME-OBSERVATION-SCHEMA.adoc"), "rift.runtime-observation.v1", "runtime schema documentation")


require(Path("tools/hash-artifact-tree.py"), 'sha256(path-nul-file-sha-lf-v1)', "canonical artifact tree hash tool")
require(Path("tools/run-rift-bwrap.sh"), 'OOMPolicy=kill', "systemd OOM policy kills full hostile unit")
require(Path("tools/run-rift-bwrap.sh"), 'systemd_result', "systemd result captured outside hostile cgroup")
require(Path("tools/run-rift-bwrap.sh"), '"oom-kill"', "systemd oom-kill maps to memory_limit")
require(Path("tools/run-rift-bwrap.sh"), 'RIFT_ARTIFACT_TREE_HASH_ALGORITHM', "tree hash algorithm stamped into runtime")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), 'sha256(path-nul-file-sha-lf-v1)', "platform evidence uses canonical tree hash")
require(Path(".github/workflows/rift-scan-omega.yml"), 'Artifact-tree correlation: PASS', "Omega CI enforces cross-report artifact identity")

print(f"Rift source-contract checks: {len(checks)}/{len(checks)} passed")
