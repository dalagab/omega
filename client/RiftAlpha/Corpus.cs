using System.Text.Json;
using System.Text.RegularExpressions;

namespace Omega.RiftAlpha;

internal static class AlphaCorpus
{
    private static readonly Regex IdPattern = new(@"^alpha\.[a-z0-9][a-z0-9._-]+$", RegexOptions.Compiled);
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public static string FindRoot(string? explicitRoot)
    {
        if (!string.IsNullOrWhiteSpace(explicitRoot))
        {
            var full = Path.GetFullPath(explicitRoot);
            EnsureCorpus(full);
            return full;
        }

        var current = new DirectoryInfo(Environment.CurrentDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "registry", "registry.json")) && Directory.Exists(Path.Combine(current.FullName, "tests")))
                return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Alpha corpus not found. Run inside the alpha checkout or pass --corpus <path>.");
    }

    private static void EnsureCorpus(string root)
    {
        if (!File.Exists(Path.Combine(root, "registry", "registry.json")) || !Directory.Exists(Path.Combine(root, "tests")))
            throw new InvalidOperationException($"Not an Alpha corpus: {root}");
    }

    public static IReadOnlyList<AlphaManifest> LoadAll(string root)
    {
        var manifests = Directory.EnumerateFiles(Path.Combine(root, "tests"), "alpha.json", SearchOption.AllDirectories)
            .Select(LoadManifest)
            .OrderBy(x => x.Id, StringComparer.Ordinal)
            .ToArray();
        var duplicate = manifests.GroupBy(x => x.Id, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (duplicate is not null)
            throw new InvalidOperationException($"Duplicate Alpha id: {duplicate.Key}");
        return manifests;
    }

    public static AlphaManifest Resolve(string root, string selector)
    {
        if (Directory.Exists(selector) || File.Exists(selector))
        {
            var path = Directory.Exists(selector) ? Path.Combine(selector, "alpha.json") : selector;
            if (!string.Equals(Path.GetFileName(path), "alpha.json", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("A local Alpha path must point to a folder containing alpha.json or to alpha.json itself.");
            return LoadManifest(Path.GetFullPath(path));
        }
        return LoadAll(root).SingleOrDefault(x => x.Id == selector)
               ?? throw new InvalidOperationException($"Unknown Alpha id: {selector}");
    }

    public static AlphaManifest LoadManifest(string path)
    {
        var manifest = JsonSerializer.Deserialize<AlphaManifest>(File.ReadAllText(path), JsonOptions)
                       ?? throw new InvalidOperationException($"Unable to parse {path}");
        manifest.ManifestPath = Path.GetFullPath(path);
        ValidateManifest(manifest);
        return manifest;
    }

    public static void ValidateManifest(AlphaManifest m)
    {
        var errors = new List<string>();
        if (m.Schema != "omega.alpha.test.v1") errors.Add("schema must be omega.alpha.test.v1");
        if (!IdPattern.IsMatch(m.Id)) errors.Add("id must match alpha.<lowercase-id>");
        if (string.IsNullOrWhiteSpace(m.Title)) errors.Add("title is required");
        if (!(new[] { "draft", "candidate", "active", "retired" }).Contains(m.Status)) errors.Add("invalid status");
        if (Path.IsPathRooted(m.Project) || m.Project.Contains("..", StringComparison.Ordinal) || !m.Project.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)) errors.Add("project must be a local .csproj filename");
        if (!File.Exists(m.ProjectPath)) errors.Add($"project not found: {m.ProjectPath}");
        if (!(new[] { "static-only", "sandbox-runtime" }).Contains(m.Mode)) errors.Add("invalid mode");
        if (!(new[] { "inert-static", "sandbox-local-runtime" }).Contains(m.SafetyClass)) errors.Add("invalid safetyClass");
        if (m.Mode == "static-only" && m.SafetyClass != "inert-static") errors.Add("static-only requires inert-static");
        if (m.Mode == "sandbox-runtime" && (m.SafetyClass != "sandbox-local-runtime" || !m.Engines.Contains("rift"))) errors.Add("sandbox-runtime requires sandbox-local-runtime and Rift");
        if (m.Engines.Length == 0 || m.Engines.Any(x => x is not ("sigmascope" or "rift" or "srl"))) errors.Add("invalid engines");
        if (!string.Equals(m.EntryAssembly, m.AssemblyName + ".dll", StringComparison.Ordinal)) errors.Add("entryAssembly must match assemblyName + .dll");

        var projectText = File.Exists(m.ProjectPath) ? File.ReadAllText(m.ProjectPath) : "";
        var sourceText = Directory.Exists(m.FolderPath)
            ? string.Join("\n", Directory.EnumerateFiles(m.FolderPath, "*.cs", SearchOption.AllDirectories).Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")).Select(File.ReadAllText))
            : "";
        if (m.Mode == "sandbox-runtime")
        {
            if (!projectText.Contains("Omega.Alpha.Sdk", StringComparison.Ordinal)) errors.Add("runtime Alpha must reference Omega.Alpha.Sdk");
            if (!sourceText.Contains("IAlphaScenario", StringComparison.Ordinal)) errors.Add("runtime Alpha must implement IAlphaScenario");
            if (projectText.Contains("Dalamud", StringComparison.OrdinalIgnoreCase) || sourceText.Contains("Dalamud", StringComparison.OrdinalIgnoreCase)) errors.Add("runtime Alpha must not reference Dalamud");
        }
        if (errors.Count > 0) throw new InvalidOperationException($"{m.Id}: " + string.Join("; ", errors));
    }
}
