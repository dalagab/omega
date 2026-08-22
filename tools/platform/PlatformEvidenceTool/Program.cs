using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace InterdimensionalRift.PlatformEvidence;

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var options = Options.Parse(args);
            var report = CompatibilityEvidenceBuilder.Build(
                options.ArtifactDirectory, options.RiftReport,
                options.ArtifactTreeSha256, options.ArtifactTreeHashAlgorithm);
            Directory.CreateDirectory(Path.GetDirectoryName(options.OutputPath) ?? ".");
            File.WriteAllText(options.OutputPath, JsonSerializer.Serialize(report, JsonOptions) + Environment.NewLine);
            Console.WriteLine($"Player-environment evidence written: {options.OutputPath}");
            Console.WriteLine($"Target runtime: {report.TargetRuntime}");
            foreach (var env in report.PlayerEnvironments)
                Console.WriteLine($"- {env.Id}: {env.Status} ({env.Confidence})");
            if (report.AnalysisRuntimeVerification is not null)
                Console.WriteLine($"- analysis runtime: {report.AnalysisRuntimeVerification.Classification}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"player-environment-evidence error: {ex.Message}");
            return 2;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}

public sealed record Options(
    string ArtifactDirectory,
    string OutputPath,
    string? RiftReport,
    string ArtifactTreeSha256,
    string ArtifactTreeHashAlgorithm)
{
    public static Options Parse(string[] args)
    {
        string? artifact = null, output = null, rift = null, treeSha = null;
        var treeAlgorithm = "sha256(path-nul-file-sha-lf-v1)";
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--artifact-dir" when i + 1 < args.Length: artifact = args[++i]; break;
                case "--out" when i + 1 < args.Length: output = args[++i]; break;
                case "--rift-report" when i + 1 < args.Length: rift = args[++i]; break;
                case "--artifact-tree-sha256" when i + 1 < args.Length: treeSha = args[++i]; break;
                case "--artifact-tree-hash-algorithm" when i + 1 < args.Length: treeAlgorithm = args[++i]; break;
                case "-h" or "--help":
                    throw new ArgumentException("usage: rift-platform-evidence --artifact-dir DIR --artifact-tree-sha256 SHA256 --out FILE [--rift-report FILE]");
                default: throw new ArgumentException($"unknown or incomplete argument: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(artifact) || string.IsNullOrWhiteSpace(output) || string.IsNullOrWhiteSpace(treeSha))
            throw new ArgumentException("--artifact-dir, --artifact-tree-sha256, and --out are required");
        if (!System.Text.RegularExpressions.Regex.IsMatch(treeSha, "^[0-9a-fA-F]{64}$"))
            throw new ArgumentException("--artifact-tree-sha256 must be a 64-character SHA-256 hex digest");

        return new(
            Path.GetFullPath(artifact),
            Path.GetFullPath(output),
            string.IsNullOrWhiteSpace(rift) ? null : Path.GetFullPath(rift),
            treeSha.ToLowerInvariant(),
            treeAlgorithm);
    }
}

public sealed class PlayerEnvironmentSupportReport
{
    public string SchemaVersion { get; set; } = "omega.player-environment-support.v1";
    public string Producer { get; set; } = "rift-platform-evidence";
    public string ProducerVersion { get; set; } = "0.2.2";
    public string GeneratedAt { get; set; } = DateTime.UtcNow.ToString("O");
    public string ArtifactTreeSha256 { get; set; } = string.Empty;
    public string ArtifactTreeHashAlgorithm { get; set; } = "sha256(path-nul-file-sha-lf-v1)";

    /// <summary>
    /// Dalamud plugins are Windows-targeted managed plugins even when the player
    /// launches FFXIV through Wine/Proton/CrossOver on another host OS.
    /// </summary>
    public string TargetRuntime { get; set; } = "windows-dalamud";

    public string ImportantNote { get; set; } =
        "Linux and macOS records describe Windows/Dalamud compatibility environments (Wine/Proton/CrossOver), not native plugin targets. Native Linux Rift execution is analysis evidence only and must not mark Linux player compatibility as verified.";

    public List<PlayerEnvironmentRecord> PlayerEnvironments { get; set; } = new();
    public List<ManagedModuleRecord> ManagedModules { get; set; } = new();
    public List<NativeAssetRecord> NativeAssets { get; set; } = new();
    public List<NativeImportRecord> NativeImports { get; set; } = new();
    public List<WindowsDependencyRecord> WindowsDependencies { get; set; } = new();
    public List<string> PlatformSensitiveAssemblies { get; set; } = new();
    public AnalysisRuntimeVerification? AnalysisRuntimeVerification { get; set; }
}

public sealed class PlayerEnvironmentRecord
{
    public string Id { get; set; } = string.Empty;
    public string DisplayOs { get; set; } = string.Empty;
    public string ExecutionModel { get; set; } = string.Empty;
    public string Status { get; set; } = "unverified";
    public string Confidence { get; set; } = "low";
    public List<CompatibilityEvidenceRecord> Evidence { get; set; } = new();
    public List<string> CompatibilityFactors { get; set; } = new();
    public List<string> Blockers { get; set; } = new();
}

public sealed class CompatibilityEvidenceRecord
{
    public string Kind { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public string? Source { get; set; }
}

public sealed class ManagedModuleRecord
{
    public string Path { get; set; } = string.Empty;
    public string? AssemblyName { get; set; }
    public bool IsManaged { get; set; }
    public List<string> AssemblyReferences { get; set; } = new();
}

public sealed class NativeAssetRecord
{
    public string Path { get; set; } = string.Empty;
    public string Format { get; set; } = "unknown";
    public string? Rid { get; set; }
    public string? PackagedOs { get; set; }
    public string? Architecture { get; set; }

    /// <summary>
    /// windows-guest-dependency: relevant to the Windows process used by Dalamud,
    /// including under Wine/CrossOver.
    /// host-native-auxiliary: native Linux/macOS asset present in the package but
    /// not proof that the Windows Dalamud plugin uses it in the player environment.
    /// </summary>
    public string RuntimeRole { get; set; } = "unknown";
}

public sealed class NativeImportRecord
{
    public string AssemblyPath { get; set; } = string.Empty;
    public string Library { get; set; } = string.Empty;
    public string EntryPoint { get; set; } = string.Empty;
    public string PlatformAffinity { get; set; } = "portable-or-unknown";
    public string CompatibilityCategory { get; set; } = "unknown";
    public bool BundledWindowsMatch { get; set; }
}

public sealed class WindowsDependencyRecord
{
    public string Name { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string CompatibilityCategory { get; set; } = string.Empty;
    public List<string> Sources { get; set; } = new();
    public bool BundledWithArtifact { get; set; }
}

public sealed class AnalysisRuntimeVerification
{
    public string? HostOs { get; set; }
    public string? HostArch { get; set; }
    public string? RuntimeIdentifier { get; set; }
    public string? Executor { get; set; }
    public string? LoadOutcome { get; set; }
    public string? CompatibilityEnvironment { get; set; }
    public string? GuestOs { get; set; }

    /// <summary>
    /// analysis-only means the current Rift host is not representative of a
    /// player compatibility environment. player-environment means a future
    /// qualified executor explicitly identifies Wine/Proton/CrossOver semantics.
    /// </summary>
    public string Classification { get; set; } = "analysis-only";
    public List<string> NativeLibrariesRequested { get; set; } = new();
    public List<string> NativeLibrariesResolved { get; set; } = new();
    public List<string> PlatformExceptions { get; set; } = new();
}

public static class CompatibilityEvidenceBuilder
{
    private static readonly string[] SensitiveAssemblies =
    {
        "Microsoft.Win32.Registry",
        "System.Drawing.Common",
        "System.Windows.Forms",
        "WindowsBase",
        "PresentationCore",
        "PresentationFramework",
        "WindowsFormsIntegration",
        "Microsoft.WindowsDesktop.App",
    };

    private static readonly HashSet<string> WindowsSystemLibraries = new(StringComparer.OrdinalIgnoreCase)
    {
        "advapi32", "advapi32.dll", "bcrypt", "bcrypt.dll", "combase", "combase.dll",
        "comdlg32", "comdlg32.dll", "crypt32", "crypt32.dll",
        "d2d1", "d2d1.dll", "d3d11", "d3d11.dll", "d3d12", "d3d12.dll",
        "dbghelp", "dbghelp.dll", "dsound", "dsound.dll", "dwrite", "dwrite.dll",
        "dxgi", "dxgi.dll", "gdi32", "gdi32.dll",
        "iphlpapi", "iphlpapi.dll", "kernel32", "kernel32.dll", "mpr", "mpr.dll",
        "mf", "mf.dll", "mfplat", "mfplat.dll", "mfreadwrite", "mfreadwrite.dll",
        "mmdevapi", "mmdevapi.dll", "msacm32", "msacm32.dll", "mscoree", "mscoree.dll",
        "msdmo", "msdmo.dll", "ntdll", "ntdll.dll",
        "ole32", "ole32.dll", "oleaut32", "oleaut32.dll",
        "psapi", "psapi.dll", "secur32", "secur32.dll", "setupapi", "setupapi.dll",
        "shell32", "shell32.dll", "shlwapi", "shlwapi.dll", "user32", "user32.dll",
        "version", "version.dll", "winhttp", "winhttp.dll", "wininet", "wininet.dll",
        "winmm", "winmm.dll", "wofutil", "wofutil.dll", "ws2_32", "ws2_32.dll",
    };

    public static PlayerEnvironmentSupportReport Build(string artifactDirectory, string? riftReport, string artifactTreeSha256, string artifactTreeHashAlgorithm)
    {
        if (!Directory.Exists(artifactDirectory))
            throw new DirectoryNotFoundException(artifactDirectory);

        var report = new PlayerEnvironmentSupportReport
        {
            ArtifactTreeSha256 = artifactTreeSha256,
            ArtifactTreeHashAlgorithm = artifactTreeHashAlgorithm,
        };

        foreach (var file in Directory.EnumerateFiles(artifactDirectory, "*", SearchOption.AllDirectories)
                     .OrderBy(x => x, StringComparer.Ordinal))
        {
            var rel = Path.GetRelativePath(artifactDirectory, file).Replace('\\', '/');
            var rid = RidFromPath(rel);
            var (ridOs, ridArch) = RidPlatform(rid);
            var format = BinaryFormat(file);

            if (IsManagedCandidate(file) && TryReadManaged(file, rel, report))
            {
                continue;
            }

            if (format is "pe-native" or "elf" or "mach-o" || IsRidNativePath(rel))
            {
                var packagedOs = ridOs ?? FormatOs(format);
                report.NativeAssets.Add(new NativeAssetRecord
                {
                    Path = rel,
                    Format = format,
                    Rid = rid,
                    PackagedOs = packagedOs,
                    Architecture = ridArch,
                    RuntimeRole = packagedOs switch
                    {
                        "windows" => "windows-guest-dependency",
                        "linux" or "macos" => "host-native-auxiliary",
                        _ => "unknown",
                    },
                });
            }
        }

        MatchBundledWindowsImports(report);
        BuildWindowsDependencyInventory(report);

        report.PlayerEnvironments = BuildPlayerEnvironments(report);

        if (!string.IsNullOrWhiteSpace(riftReport) && File.Exists(riftReport))
        {
            report.AnalysisRuntimeVerification = ParseRiftReport(riftReport);
            ApplyRepresentativeRuntimeVerification(report.AnalysisRuntimeVerification, report.PlayerEnvironments);
        }

        report.PlatformSensitiveAssemblies.Sort(StringComparer.OrdinalIgnoreCase);
        return report;
    }

    private static List<PlayerEnvironmentRecord> BuildPlayerEnvironments(PlayerEnvironmentSupportReport report)
    {
        var windows = new PlayerEnvironmentRecord
        {
            Id = "windows-native",
            DisplayOs = "windows",
            ExecutionModel = "native-windows-dalamud",
            Status = "target-runtime",
            Confidence = "high",
            Evidence =
            {
                new CompatibilityEvidenceRecord
                {
                    Kind = "target-runtime",
                    Detail = "Dalamud plugin target runtime is Windows.",
                },
            },
        };

        var linux = NewCompatibilityEnvironment(
            "linux-wine-proton",
            "linux",
            "windows-dalamud-under-wine-or-proton",
            report);

        var macos = NewCompatibilityEnvironment(
            "macos-crossover-wine",
            "macos",
            "windows-dalamud-under-crossover-or-wine",
            report);

        foreach (var dependency in report.WindowsDependencies)
        {
            var detail = $"{dependency.Name}: {dependency.CompatibilityCategory}" +
                         (dependency.BundledWithArtifact ? "; bundled" : "; environment-provided");
            linux.Evidence.Add(new CompatibilityEvidenceRecord
            {
                Kind = "windows-runtime-dependency",
                Detail = detail,
                Source = dependency.Sources.FirstOrDefault(),
            });
            macos.Evidence.Add(new CompatibilityEvidenceRecord
            {
                Kind = "windows-runtime-dependency",
                Detail = detail,
                Source = dependency.Sources.FirstOrDefault(),
            });
        }

        foreach (var asset in report.NativeAssets.Where(a => a.RuntimeRole == "host-native-auxiliary"))
        {
            var target = asset.PackagedOs == "linux" ? linux : asset.PackagedOs == "macos" ? macos : null;
            if (target is null) continue;
            target.Evidence.Add(new CompatibilityEvidenceRecord
            {
                Kind = "host-native-auxiliary-asset",
                Detail = $"{asset.Rid ?? asset.PackagedOs}: {asset.Path}; presence does not verify player compatibility",
                Source = asset.Path,
            });
        }

        return new() { windows, linux, macos };
    }

    private static PlayerEnvironmentRecord NewCompatibilityEnvironment(
        string id,
        string displayOs,
        string executionModel,
        PlayerEnvironmentSupportReport report)
    {
        var factors = report.WindowsDependencies
            .Select(d => d.CompatibilityCategory)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new PlayerEnvironmentRecord
        {
            Id = id,
            DisplayOs = displayOs,
            ExecutionModel = executionModel,
            Status = factors.Count > 0 ? "compatibility-sensitive-unverified" : "unverified",
            Confidence = factors.Count > 0 ? "medium" : "low",
            CompatibilityFactors = factors,
            Evidence =
            {
                new CompatibilityEvidenceRecord
                {
                    Kind = "compatibility-layer-required",
                    Detail = "The plugin still runs as a Windows/Dalamud process; host OS compatibility depends on the Windows compatibility layer and its available APIs/libraries.",
                },
            },
        };
    }

    private static bool TryReadManaged(string path, string rel, PlayerEnvironmentSupportReport report)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
            if (!pe.HasMetadata) return false;

            var reader = pe.GetMetadataReader();
            var module = new ManagedModuleRecord { Path = rel, IsManaged = true };
            if (reader.IsAssembly)
            {
                var definition = reader.GetAssemblyDefinition();
                module.AssemblyName = reader.GetString(definition.Name);
            }

            foreach (var handle in reader.AssemblyReferences)
            {
                var reference = reader.GetAssemblyReference(handle);
                var name = reader.GetString(reference.Name);
                module.AssemblyReferences.Add(name);
                if (SensitiveAssemblies.Contains(name, StringComparer.OrdinalIgnoreCase) &&
                    !report.PlatformSensitiveAssemblies.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    report.PlatformSensitiveAssemblies.Add(name);
                }
            }

            foreach (var handle in reader.MethodDefinitions)
            {
                var method = reader.GetMethodDefinition(handle);
                if ((method.Attributes & MethodAttributes.PinvokeImpl) == 0) continue;

                var import = method.GetImport();
                if (import.Module.IsNil) continue;

                var moduleRef = reader.GetModuleReference(import.Module);
                var lib = reader.GetString(moduleRef.Name);
                var entry = import.Name.IsNil ? reader.GetString(method.Name) : reader.GetString(import.Name);
                report.NativeImports.Add(new NativeImportRecord
                {
                    AssemblyPath = rel,
                    Library = lib,
                    EntryPoint = entry,
                    PlatformAffinity = NativeLibraryAffinity(lib),
                    CompatibilityCategory = CompatibilityCategory(lib),
                });
            }

            module.AssemblyReferences.Sort(StringComparer.OrdinalIgnoreCase);
            report.ManagedModules.Add(module);
            return true;
        }
        catch (BadImageFormatException) { return false; }
        catch (IOException) { return false; }
    }

    private static void MatchBundledWindowsImports(PlayerEnvironmentSupportReport report)
    {
        var bundled = report.NativeAssets
            .Where(a => a.RuntimeRole == "windows-guest-dependency")
            .Select(a => NormalizeLibraryName(Path.GetFileName(a.Path)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var import in report.NativeImports)
            import.BundledWindowsMatch = bundled.Contains(NormalizeLibraryName(import.Library));
    }

    private static void BuildWindowsDependencyInventory(PlayerEnvironmentSupportReport report)
    {
        var byName = new Dictionary<string, WindowsDependencyRecord>(StringComparer.OrdinalIgnoreCase);

        foreach (var import in report.NativeImports)
        {
            var normalized = NormalizeLibraryName(import.Library);
            var isWindows = import.PlatformAffinity == "windows" ||
                            import.BundledWindowsMatch ||
                            WindowsSystemLibraries.Contains(import.Library) ||
                            WindowsSystemLibraries.Contains(normalized);

            if (!isWindows) continue;

            if (!byName.TryGetValue(normalized, out var dep))
            {
                dep = new WindowsDependencyRecord
                {
                    Name = import.Library,
                    Kind = WindowsSystemLibraries.Contains(import.Library) || WindowsSystemLibraries.Contains(normalized)
                        ? "windows-api"
                        : "native-third-party",
                    CompatibilityCategory = CompatibilityCategory(import.Library),
                    BundledWithArtifact = import.BundledWindowsMatch,
                };
                byName[normalized] = dep;
            }

            if (!dep.Sources.Contains(import.AssemblyPath, StringComparer.OrdinalIgnoreCase))
                dep.Sources.Add(import.AssemblyPath);
            dep.BundledWithArtifact |= import.BundledWindowsMatch;
        }

        foreach (var asset in report.NativeAssets.Where(a => a.RuntimeRole == "windows-guest-dependency"))
        {
            var normalized = NormalizeLibraryName(Path.GetFileName(asset.Path));
            if (byName.ContainsKey(normalized)) continue;

            byName[normalized] = new WindowsDependencyRecord
            {
                Name = Path.GetFileName(asset.Path),
                Kind = "bundled-windows-native-asset",
                CompatibilityCategory = "bundled-native",
                BundledWithArtifact = true,
                Sources = { asset.Path },
            };
        }

        foreach (var assembly in report.PlatformSensitiveAssemblies)
        {
            var key = "managed:" + assembly;
            byName[key] = new WindowsDependencyRecord
            {
                Name = assembly,
                Kind = "windows-sensitive-managed-reference",
                CompatibilityCategory = "windows-managed-api",
                BundledWithArtifact = false,
            };
        }

        report.WindowsDependencies = byName.Values
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static AnalysisRuntimeVerification ParseRiftReport(string path)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        var result = new AnalysisRuntimeVerification();

        if (root.TryGetProperty("execution", out var execution))
        {
            result.HostOs = GetString(execution, "host_os");
            result.HostArch = GetString(execution, "host_arch");
            result.RuntimeIdentifier = GetString(execution, "runtime_identifier");
            result.Executor = GetString(execution, "executor");
            result.CompatibilityEnvironment = GetString(execution, "compatibility_environment");
            result.GuestOs = GetString(execution, "guest_os");
        }

        if (root.TryGetProperty("plugin", out var plugin))
            result.LoadOutcome = GetString(plugin, "load_outcome");

        if (root.TryGetProperty("observations", out var observations) &&
            observations.ValueKind == JsonValueKind.Array)
        {
            foreach (var observation in observations.EnumerateArray())
            {
                var kind = GetString(observation, "kind") ?? string.Empty;
                var message = GetString(observation, "message");
                var outcome = GetString(observation, "outcome");

                if (kind.Equals("native_library", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(message))
                {
                    AddUnique(result.NativeLibrariesRequested, message);
                    if (outcome == "resolved")
                        AddUnique(result.NativeLibrariesResolved, message);
                }

                var exceptionType = GetString(observation, "exception_type");
                if (exceptionType is not null && IsPlatformException(exceptionType))
                    AddUnique(result.PlatformExceptions, exceptionType);

                var exceptionMessage = GetString(observation, "exception_message");
                if (exceptionMessage is not null && LooksPlatformSpecific(exceptionMessage))
                    AddUnique(result.PlatformExceptions, exceptionMessage);
            }
        }

        var representative =
            !string.IsNullOrWhiteSpace(result.CompatibilityEnvironment) &&
            string.Equals(result.GuestOs, "windows", StringComparison.OrdinalIgnoreCase);

        result.Classification = representative
            ? "player-environment"
            : "analysis-only-not-player-compatibility";

        return result;
    }

    private static void ApplyRepresentativeRuntimeVerification(
        AnalysisRuntimeVerification runtime,
        List<PlayerEnvironmentRecord> environments)
    {
        if (runtime.Classification != "player-environment" ||
            string.IsNullOrWhiteSpace(runtime.CompatibilityEnvironment))
        {
            return;
        }

        var env = environments.FirstOrDefault(e =>
            e.Id.Equals(runtime.CompatibilityEnvironment, StringComparison.OrdinalIgnoreCase));
        if (env is null) return;

        env.Evidence.Add(new CompatibilityEvidenceRecord
        {
            Kind = "qualified-player-environment-runtime",
            Detail =
                $"guest_os={runtime.GuestOs}; host_os={runtime.HostOs}; executor={runtime.Executor}; rid={runtime.RuntimeIdentifier}; outcome={runtime.LoadOutcome}",
        });

        if (runtime.LoadOutcome == "ok")
        {
            env.Status = "verified";
            env.Confidence = "high";
        }
        else if (runtime.LoadOutcome == "init_threw" && runtime.PlatformExceptions.Count > 0)
        {
            env.Status = "blocked";
            env.Confidence = "high";
            env.Blockers.AddRange(runtime.PlatformExceptions);
        }
    }

    private static string? GetString(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static void AddUnique(List<string> list, string value)
    {
        if (!list.Contains(value, StringComparer.OrdinalIgnoreCase))
            list.Add(value);
    }

    private static bool IsPlatformException(string type)
        => type.EndsWith("PlatformNotSupportedException", StringComparison.Ordinal) ||
           type.EndsWith("DllNotFoundException", StringComparison.Ordinal) ||
           type.EndsWith("EntryPointNotFoundException", StringComparison.Ordinal) ||
           type.EndsWith("BadImageFormatException", StringComparison.Ordinal);

    private static bool LooksPlatformSpecific(string message)
        => message.Contains(".dll", StringComparison.OrdinalIgnoreCase) ||
           message.Contains(".so", StringComparison.OrdinalIgnoreCase) ||
           message.Contains(".dylib", StringComparison.OrdinalIgnoreCase) ||
           message.Contains("not supported on this platform", StringComparison.OrdinalIgnoreCase);

    private static string NativeLibraryAffinity(string library)
    {
        var x = library.Trim().ToLowerInvariant();

        if (x.EndsWith(".dylib") ||
            x.Contains("/system/library/frameworks/") ||
            x is "libsystem" or "libobjc")
            return "macos";

        if (x.EndsWith(".so") ||
            x.StartsWith("libc.so") ||
            x.StartsWith("libdl.so") ||
            x.StartsWith("libpthread.so") ||
            x is "libc" or "libdl" or "libpthread" or "librt")
            return "linux";

        if (x.EndsWith(".dll") ||
            WindowsSystemLibraries.Contains(x) ||
            WindowsSystemLibraries.Contains(NormalizeLibraryName(x)))
            return "windows";

        return "portable-or-unknown";
    }

    private static string CompatibilityCategory(string library)
    {
        var x = NormalizeLibraryName(library);

        if (x is "kernel32" or "ntdll" or "bcrypt" or "version")
            return "core-win32";
        if (x is "user32" or "gdi32" or "winmm")
            return "windowing-input";
        if (x is "d2d1" or "dwrite" or "dxgi" or "d3d11" or "d3d12")
            return "graphics-overlay";
        if (x is "dsound" or "mmdevapi" or "mf" or "mfplat" or "mfreadwrite" or "msacm32" or "msdmo")
            return "media-audio";
        if (x is "advapi32" or "secur32" or "crypt32")
            return "registry-security";
        if (x is "ole32" or "oleaut32" or "combase")
            return "com";
        if (x is "shell32" or "shlwapi" or "comdlg32")
            return "windows-shell";
        if (x is "wofutil")
            return "windows-filesystem";
        if (x is "mscoree")
            return "windows-dotnet-runtime";
        if (x is "ws2_32" or "winhttp" or "wininet" or "iphlpapi")
            return "networking";
        if (x.EndsWith(".so", StringComparison.OrdinalIgnoreCase) || x.StartsWith("libc"))
            return "host-native-linux";
        if (x.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase))
            return "host-native-macos";
        return "bundled-native";
    }

    private static string NormalizeLibraryName(string library)
    {
        var name = Path.GetFileName(library.Trim()).ToLowerInvariant();
        if (name.EndsWith(".dll")) name = name[..^4];
        else if (name.EndsWith(".so")) name = name[..^3];
        else if (name.EndsWith(".dylib")) name = name[..^6];

        if (name.StartsWith("lib") && name.Length > 3)
            name = name[3..];

        return name;
    }

    private static bool IsManagedCandidate(string file)
        => Path.GetExtension(file).Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
           Path.GetExtension(file).Equals(".exe", StringComparison.OrdinalIgnoreCase);

    private static bool IsRidNativePath(string rel)
        => rel.Contains("/native/", StringComparison.OrdinalIgnoreCase) ||
           rel.Contains("/nativeassets/", StringComparison.OrdinalIgnoreCase);

    private static string? RidFromPath(string rel)
    {
        var parts = rel.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2 &&
            parts[0].Equals("runtimes", StringComparison.OrdinalIgnoreCase))
            return parts[1];

        return null;
    }

    private static (string? os, string? arch) RidPlatform(string? rid)
    {
        if (string.IsNullOrWhiteSpace(rid))
            return (null, null);

        var x = rid.ToLowerInvariant();
        string? os =
            x.StartsWith("win-") ? "windows" :
            x.StartsWith("linux-") || x.StartsWith("linux-musl-") ? "linux" :
            x.StartsWith("osx-") || x.StartsWith("maccatalyst-") ? "macos" :
            null;

        var arch = x.Split('-').LastOrDefault();
        return (os, arch);
    }

    private static string? FormatOs(string format) => format switch
    {
        "pe-native" => "windows",
        "elf" => "linux",
        "mach-o" => "macos",
        _ => null,
    };

    private static string BinaryFormat(string file)
    {
        try
        {
            using var stream = File.OpenRead(file);
            Span<byte> head = stackalloc byte[256];
            var count = stream.Read(head);

            if (count >= 4 &&
                head[0] == 0x7F &&
                head[1] == (byte)'E' &&
                head[2] == (byte)'L' &&
                head[3] == (byte)'F')
                return "elf";

            if (count >= 4)
            {
                var magic = BitConverter.ToUInt32(head[..4]);
                if (magic is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE or 0xCAFEBABE or 0xBEBAFECA)
                    return "mach-o";
            }

            if (count >= 64 && head[0] == (byte)'M' && head[1] == (byte)'Z')
            {
                stream.Position = 0;
                try
                {
                    using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
                    return pe.HasMetadata ? "pe-managed" : "pe-native";
                }
                catch
                {
                    return "pe";
                }
            }
        }
        catch
        {
            // Package inventory should not fail the entire evidence run because a
            // random data file cannot be opened as an executable.
        }

        return "unknown";
    }

}
