using System.Text.Json;

namespace Omega.RiftAlpha;

internal static class AlphaRegistryWriter
{
    public static void Build(string root)
    {
        var entries = AlphaCorpus.LoadAll(root).Select(m => new
        {
            id = m.Id,
            title = m.Title,
            description = m.Description,
            status = m.Status,
            assemblyName = m.AssemblyName,
            entryAssembly = m.EntryAssembly,
            mode = m.Mode,
            safetyClass = m.SafetyClass,
            engines = m.Engines,
            tags = m.Tags,
            expected = m.Expected,
            manifestPath = Rel(root, m.ManifestPath),
            projectPath = Rel(root, m.ProjectPath)
        }).OrderBy(x => x.id, StringComparer.Ordinal).ToArray();
        var doc = new
        {
            schema = "omega.alpha.registry.v1",
            branch = "alpha",
            description = "Harmless adversarial Alpha scenarios and static fixtures. Runtime Alphas execute only in the dedicated Rift Alpha boundary.",
            entries
        };
        var path = Path.Combine(root, "registry", "registry.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(doc, JsonDefaults.Pretty) + Environment.NewLine);
    }

    private static string Rel(string root, string path) => Path.GetRelativePath(root, path).Replace('\\', '/');
}
