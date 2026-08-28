using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;
using Omega.Alpha;

namespace Omega.RiftAlpha;

internal static class ScenarioHost
{
    public static int Run(string assemblyPath, string alphaId, string outPath, string runId)
    {
        if (!AlphaGuard.IsRiftAlphaSandbox)
        {
            Console.Error.WriteLine("refusing Alpha scenario execution outside the dedicated Rift Alpha sandbox");
            return 2;
        }

        var report = new AlphaRuntimeReport { RunId = runId, AlphaId = alphaId };
        try
        {
            var full = Path.GetFullPath(assemblyPath);
            var alc = new AlphaScenarioLoadContext(full);
            var assembly = alc.LoadFromAssemblyPath(full);
            var candidates = assembly.GetTypes()
                .Where(t => !t.IsAbstract && typeof(IAlphaScenario).IsAssignableFrom(t))
                .Select(t => new { Type = t, Attr = t.GetCustomAttribute<AlphaTestAttribute>() })
                .Where(x => x.Attr is not null && string.Equals(x.Attr.Id, alphaId, StringComparison.Ordinal))
                .ToArray();
            if (candidates.Length != 1)
                throw new InvalidOperationException($"Expected exactly one IAlphaScenario tagged {alphaId}; found {candidates.Length}.");

            var scenario = (IAlphaScenario?)Activator.CreateInstance(candidates[0].Type)
                           ?? throw new InvalidOperationException("Alpha scenario requires a public parameterless constructor.");
            var reporter = new AlphaReporter(report.Events);
            var context = new AlphaContext(runId, alphaId, reporter);
            scenario.Execute(context);
            report.Outcome = "completed";
        }
        catch (Exception ex)
        {
            report.Outcome = "failed";
            report.Error = ex.GetType().Name + ": " + ex.Message;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath))!);
        File.WriteAllText(outPath, JsonSerializer.Serialize(report, JsonDefaults.Pretty));
        return report.Outcome == "completed" ? 0 : 1;
    }

    private sealed class AlphaScenarioLoadContext(string mainAssemblyPath) : AssemblyLoadContext(isCollectible: false)
    {
        private readonly AssemblyDependencyResolver _resolver = new(mainAssemblyPath);
        protected override Assembly? Load(AssemblyName assemblyName)
        {
            if (string.Equals(assemblyName.Name, typeof(IAlphaScenario).Assembly.GetName().Name, StringComparison.Ordinal))
                return typeof(IAlphaScenario).Assembly;
            var path = _resolver.ResolveAssemblyToPath(assemblyName);
            return path is null ? null : LoadFromAssemblyPath(path);
        }
    }

    private sealed class AlphaContext(string runId, string alphaId, IAlphaReporter reporter) : IAlphaContext
    {
        public string RunId { get; } = runId;
        public string AlphaId { get; } = alphaId;
        public IAlphaReporter Report { get; } = reporter;
    }

    private sealed class AlphaReporter(List<AlphaReportedEvent> events) : IAlphaReporter
    {
        public void Attempt(string operation, string? detail = null) => Add("attempt", operation, detail);
        public void Observed(string operation, string? detail = null) => Add("observed", operation, detail);
        public void Note(string operation, string? detail = null) => Add("note", operation, detail);
        private void Add(string kind, string operation, string? detail)
        {
            var normalized = operation.StartsWith("ALPHA:", StringComparison.Ordinal) ? operation : "ALPHA:" + operation.TrimStart(':');
            events.Add(new AlphaReportedEvent(normalized, kind, detail, DateTimeOffset.UtcNow));
        }
    }
}

internal static class JsonDefaults
{
    public static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
}
