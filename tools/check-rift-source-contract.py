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
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), 'ProducerVersion { get; set; } = "0.3.8"', "producer version 0.3.8")
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


# Real-world complex plugin regression scan.
require(Path(".github/workflows/rift-scan-artisan.yml"), "Rift scan published Artisan", "Artisan exact-artifact scan workflow")
require(Path(".github/workflows/rift-scan-artisan.yml"), "https://love.puni.sh/ment.json", "Artisan canonical Puni feed acquisition")
require(Path(".github/workflows/rift-scan-artisan.yml"), "expected exactly one stable Artisan entry", "Artisan stable entry uniqueness gate")
require(Path(".github/workflows/rift-scan-artisan.yml"), "versions/{version}/install/latest.zip", "Artisan version-pinned Puni artifact gate")
require(Path(".github/workflows/rift-scan-artisan.yml"), "summarize-rift-coverage.py", "Artisan engineering coverage-gap projection")
require(Path("tools/summarize-rift-coverage.py"), "rift.coverage-gap.v1", "coverage-gap report schema producer")
require(Path("tools/summarize-rift-coverage.py"), "full_plugin_functionality_proven", "coverage report avoids overstating startup")
require(Path("schemas/rift-coverage-gap-v1.schema.json"), "rift.coverage-gap.v1", "coverage-gap JSON schema")


# Pass 3.3.1: real PluginInterface IoC semantics + canonical Windows ZIP staging.
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), 'case "Create" when method.IsGenericMethod', "PluginInterface Create<T> handled as IoC")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), 'CreateInjectedObject', "Create<T> constructs and injects requested object")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), 'ExtractScopedObjects', "Create/Inject scoped objects preserved")
require(Path("tests/fixtures/RiftCreateSemantics/Plugin.cs"), "RIFT_CREATE semantics complete", "Create<T>/CreateAsync<T> runtime regression fixture")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "PluginInterface_CreateAndCreateAsync_InjectServicesAndScopedObjects", "Create semantics regression test")
require(Path("InterdimensionalRift/Reporting/RuntimeObservation.cs"), "exception_detail", "bounded exception stack/detail evidence")
require(Path("tools/extract-rift-artifact.py"), "duplicate normalized ZIP path", "canonical safe ZIP extractor")
require(Path("tools/extract-rift-artifact.py"), "raw.replace('\\\\','/')", "Windows ZIP separators normalized")
require(Path(".github/workflows/rift-scan-artisan.yml"), "extract-rift-artifact.py", "Artisan uses shared canonical extractor")
require(Path(".github/workflows/rift-scan-omega.yml"), "extract-rift-artifact.py", "Omega uses shared canonical extractor")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), "ArtifactTreeSha256", "platform evidence accepts canonical tree identity")
require(Path(".github/workflows/rift-scan-artisan.yml"), "Artisan artifact-tree correlation: PASS", "Artisan cross-report artifact correlation enforced")


require(Path("tools/test-rift-artifact-tools.py"), "Rift artifact tool self-test: PASS", "canonical artifact extractor/hash regression test")
require(Path(".github/workflows/rift-scan-artisan.yml"), "test-rift-artifact-tools.py", "Artisan scan executes artifact tool regression")
require(Path(".github/workflows/rift-scan-omega.yml"), "test-rift-artifact-tools.py", "Omega scan executes artifact tool regression")


require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), 'return "media-audio"', "Artisan audio/media Windows dependencies classified")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), 'return "windows-filesystem"', "Windows filesystem compatibility dependencies classified")
require(Path("tools/platform/PlatformEvidenceTool/Program.cs"), 'return "windows-dotnet-runtime"', "Windows .NET runtime compatibility dependency classified")


# Pass 3.3.2: published scans use the stable Dalamud release contract and record it.
for workflow in (
    ".github/workflows/rift-alpha.yml",
    ".github/workflows/rift-canary.yml",
    ".github/workflows/rift-containment-stress.yml",
    ".github/workflows/rift-scan-artisan.yml",
    ".github/workflows/rift-scan-omega.yml",
):
    require(Path(workflow), "https://goatcorp.github.io/dalamud-distrib/latest.zip",
            f"{workflow} uses stable Dalamud release contract")
    forbid(Path(workflow), "dalamud-distrib/stg/latest.zip",
           f"{workflow} does not use prerelease staging contract")
    require(Path(workflow), "--contract-track release",
            f"{workflow} stamps release contract track")
require(Path("tools/run-rift-bwrap.sh"), "--contract-track", "Rift supervisor accepts contract track")
require(Path("tools/run-rift-bwrap.sh"), "RIFT_DALAMUD_CONTRACT_TRACK", "contract track stamped into sandbox")
require(Path("tools/run-rift-bwrap.sh"), "RIFT_DALAMUD_CONTRACT_SHA256", "Dalamud.dll SHA stamped into sandbox")
require(Path("tools/run-rift-bwrap.sh"), "RIFT_DALAMUD_CONTRACT_TREE_SHA256", "contract tree SHA stamped into sandbox")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "dalamud_contract_track", "managed report records contract track")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "dalamud_contract_sha256", "managed report records Dalamud.dll SHA")
require(Path("InterdimensionalRift/Reporting/SandboxReport.cs"), "dalamud_contract_tree_sha256", "managed report records contract tree SHA")


# Pass 3.3.3: constrained generic proxy + inert game interop.
require(Path("InterdimensionalRift/Runtime/ConstraintPreservingProxyFactory.cs"), "GenericParameterAttributes", "generic proxy preserves CLR constraints")
require(Path("InterdimensionalRift/Runtime/ConstraintPreservingProxyFactory.cs"), "DefineMethodOverride", "generic proxy implements real Dalamud interface methods")
require(Path("InterdimensionalRift/Runtime/SyntheticHookRuntime.cs"), "GetUninitializedObject", "synthetic Hook<T> avoids real Dalamud hook constructor/backend")
require(Path("InterdimensionalRift/Runtime/SyntheticHookRuntime.cs"), '"native_patch"] = "false"', "synthetic hook records no native patch")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), '"Dalamud.Plugin.Services.IGameInteropProvider"', "game interop uses constraint-preserving proxy")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), "InvokeGameInterop", "game interop has inert runtime semantics")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), "GetOrCreateData", "PluginInterface shared-data semantics implemented")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), "get_AssemblyVersion", "plugin manifest version semantics implemented")
require(Path("InterdimensionalRift/Reporting/RuntimeObservation.cs"), "SignatureScan", "signature scan observation kind")
require(Path("InterdimensionalRift/Reporting/RuntimeObservation.cs"), "Hook", "hook observation kind")
require(Path("tests/fixtures/RiftGameInteropSemantics/Plugin.cs"), "RIFT_GAME_INTEROP semantics complete", "game interop runtime regression fixture")
require(Path("tests/fixtures/RiftGameInteropSemantics/Plugin.cs"), "GetOrCreateData", "shared-data runtime regression")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "GenericHookConstraints_ArePreservedAndHooksRemainInert", "generic hook constraint regression test")
require(Path("tools/summarize-rift-coverage.py"), "emulation_limits", "coverage report preserves synthetic interop limitations")
require(Path("InterdimensionalRift/Runtime/SyntheticHookRuntime.cs"), 'DefineGenericParameters("T")', "synthetic Hook is emitted as an open generic type")
require(Path("InterdimensionalRift/Runtime/SyntheticHookRuntime.cs"), "MakeGenericType(delegateType)", "synthetic Hook closes over plugin-private delegate only at runtime")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "initException?.ExceptionDetail", "game interop regression exposes captured init exception on failure")


# Pass 3.3.3.2: constrained generic service routing + empty Lumina data surface.
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), "RequiresConstraintPreservingProxy", "constrained generic services selected structurally")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), 'serviceName == "IDataManager"', "IDataManager has explicit synthetic semantics")
require(Path("InterdimensionalRift/Runtime/SyntheticGameDataRuntime.cs"), "Lumina.Excel.ExcelSheet`1", "empty typed Lumina sheet support")
require(Path("InterdimensionalRift/Runtime/SyntheticGameDataRuntime.cs"), '"real_game_data"] = "false"', "game-data evidence states no real data")
require(Path("tests/fixtures/RiftGameDataSemantics/Plugin.cs"), "RIFT_GAME_DATA empty sheet semantics complete", "constrained game-data fixture")
require(Path("tests/fixtures/RiftGameDataSemantics/Plugin.cs"), "Lumina.Excel.RawRow", "self-contained core Lumina constrained row fixture")
forbid(Path("tests/fixtures/RiftGameDataSemantics/Plugin.cs"), "Lumina.Excel.Sheets", "game-data fixture must not require generated sheet assembly")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "ConstrainedExcelSheet_IsEmptyEnumerableAndDoesNotLoadGameFiles", "constrained game-data regression test")
require(Path("tools/summarize-rift-coverage.py"), '("idatamanager","game-data")', "coverage report recognizes game-data access")



# Pass 3.3.3.3: bounded FFXIVClientStructs native-state model + preserved exception stacks.
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), "Framework.Instance", "native-state model patches Framework singleton resolver")
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), "GetAgentModuleStub", "native-state model supplies inert UI agent-module virtual call")
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), "GetAgentByInternalIdStub", "native-state model returns absent synthetic agent")
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), '"real_game_memory"] = "false"', "native-state evidence never claims real game memory")
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), '"native_call"] = "false"', "native-state stubs state no game-native call")
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), '"artifact_mutated"] = "false"', "native-state resolver patch does not mutate plugin artifact")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), "SyntheticNativeGameStateRuntime.EnsureInstalled", "native-state model is installed before plugin constructor")
require(Path("InterdimensionalRift/Reporting/RuntimeObservation.cs"), "NativeGameState", "native game-state observation kind")
require(Path("tests/fixtures/RiftNativeGameStateSemantics/Plugin.cs"), "Framework.Instance", "native-state fixture exercises generated FFXIVClientStructs singleton")
require(Path("tests/fixtures/RiftNativeGameStateSemantics/Plugin.cs"), "GetAgentByInternalId", "native-state fixture exercises generated member function")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "FfxivClientStructs_FrameworkAgentChain_IsSyntheticAndNeverCallsGameMemory", "native-state runtime regression test")
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), "ObserveActiveModel(reused: true)", "native-state reuse re-emits per-report model provenance")
require(Path("InterdimensionalRift/Runtime/SyntheticNativeGameStateRuntime.cs"), '["model_state"] = "active"', "native-state reuse labels active process-global model state")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "secondReport", "native-state regression explicitly exercises same-process reuse")
require(Path("InterdimensionalRift/Runtime/RuntimeServiceRegistry.cs"), "ExceptionDispatchInfo.Capture(actual).Throw", "constructor exception preserves original plugin stack")
require(Path("tests/InterdimensionalRift.Tests/SmokeTest.cs"), "ConstructorException_PreservesOriginalPluginFrame", "exception stack preservation regression test")
require(Path("tools/summarize-rift-coverage.py"), "observed_native_game_state_operations", "coverage projection preserves native-state observations")

print(f"Rift source-contract checks: {len(checks)}/{len(checks)} passed")
