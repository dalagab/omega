using System.Text.Json;

namespace Omega.RiftAlpha;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "-h" or "--help" or "/?") { PrintUsage(); return args.Length == 0 ? 2 : 0; }
            return args[0] switch
            {
                "doctor" => Doctor(),
                "list" => List(args[1..]),
                "validate" => Validate(args[1..]),
                "build" => Build(args[1..]),
                "run" => Run(args[1..]),
                "inspect" => Inspect(args[1..]),
                "new" => New(args[1..]),
                "registry" => Registry(args[1..]),
                "__host" => HiddenHost(args[1..]),
                "__sandbox-run" => HiddenSandbox(args[1..]),
                _ => Fail($"unknown command: {args[0]}")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return 2;
        }
    }

    private static int Doctor()
    {
        Console.WriteLine("Rift Alpha local offensive-security runner");
        Console.WriteLine("------------------------------------------");
        Console.WriteLine($"platform             : {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
        Console.WriteLine($"dotnet SDK           : {(ProcessUtil.Exists("dotnet") ? "available" : "MISSING")}");
        if (OperatingSystem.IsWindows())
        {
            Console.WriteLine($"WSL2 controller      : {(ProcessUtil.Exists("wsl.exe") ? "available" : "MISSING")}");
            var worker = Path.Combine(AppContext.BaseDirectory, "linux-x64", "rift-alpha");
            var policy = Path.Combine(AppContext.BaseDirectory, "linux-x64", "rift-alpha-seccomp.bpf");
            Console.WriteLine($"bundled Linux worker : {(File.Exists(worker) ? "available" : "MISSING")}");
            Console.WriteLine($"bundled seccomp      : {(File.Exists(policy) ? "available" : "MISSING")}");
            if (ProcessUtil.Exists("wsl.exe"))
            {
                var probe = ProcessUtil.Run("wsl.exe", ["--exec", "sh", "-lc", "command -v bwrap >/dev/null && command -v systemd-run >/dev/null && test -f /sys/fs/cgroup/cgroup.controllers && systemd-run --user --scope --quiet --collect true >/dev/null"], timeoutSeconds: 15);
                Console.WriteLine($"WSL Rift boundary    : {(probe.ExitCode == 0 ? "available" : "NOT READY")}");
            }
        }
        else if (OperatingSystem.IsLinux())
        {
            try { RiftAlphaSandbox.RequireLinuxBoundary(); Console.WriteLine("Rift boundary        : ready"); }
            catch (Exception ex) { Console.WriteLine("Rift boundary        : NOT READY (" + ex.Message + ")"); }
        }
        else Console.WriteLine("Rift boundary        : unsupported platform");
        Console.WriteLine("normal plugin loader : NOT PRESENT");
        return 0;
    }

    private static int List(string[] args)
    {
        var parsed = ParseSelectorArgs(args, selectorRequired: false);
        var root = AlphaCorpus.FindRoot(parsed.Corpus);
        foreach (var m in AlphaCorpus.LoadAll(root))
            Console.WriteLine($"{m.Id,-42} {m.Mode,-16} {m.Status,-10} {string.Join(',', m.Engines)}");
        return 0;
    }

    private static int Validate(string[] args)
    {
        var parsed = ParseSelectorArgs(args, selectorRequired: true);
        var root = AlphaCorpus.FindRoot(parsed.Corpus);
        var m = AlphaCorpus.Resolve(root, parsed.Selector!);
        AlphaCorpus.ValidateManifest(m);
        Console.WriteLine($"PASS {m.Id} ({m.Mode}, {m.SafetyClass})");
        return 0;
    }

    private static int Build(string[] args)
    {
        var parsed = ParseSelectorArgs(args, selectorRequired: true);
        var root = AlphaCorpus.FindRoot(parsed.Corpus);
        var m = AlphaCorpus.Resolve(root, parsed.Selector!);
        var runDir = CreateRunDirectory(root, "build-" + m.Id);
        var build = AlphaBuilder.Build(m, runDir);
        Console.WriteLine(build.EntryAssemblyPath);
        Console.WriteLine("sha256=" + build.Sha256);
        return 0;
    }

    private static int Run(string[] args)
    {
        var parsed = ParseSelectorArgs(args, selectorRequired: true);
        var root = AlphaCorpus.FindRoot(parsed.Corpus);
        var m = AlphaCorpus.Resolve(root, parsed.Selector!);
        if (m.Mode != "sandbox-runtime")
            throw new InvalidOperationException($"{m.Id} is static-only and cannot be executed by Rift Alpha. Submit its artifact to SigmaScope/SRL instead.");
        var runId = "alpha-" + DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffZ") + "-" + Guid.NewGuid().ToString("N")[..8];
        var runDir = CreateRunDirectory(root, runId);
        var build = AlphaBuilder.Build(m, runDir);
        var evidence = RiftAlphaSandbox.Run(m, build, runDir, runId);
        Console.WriteLine($"Alpha       : {m.Id}");
        Console.WriteLine($"Run         : {runId}");
        Console.WriteLine($"Backend     : {evidence.Backend}");
        Console.WriteLine($"Outcome     : {evidence.Outcome}");
        Console.WriteLine($"Evidence    : {Path.Combine(runDir, "alpha-run.json")}");
        if (evidence.Offensive is not null)
            foreach (var ev in evidence.Offensive.Events) Console.WriteLine($"  {ev.Kind,-9} {ev.Id} {ev.Detail}");
        return evidence.Outcome == "completed" ? 0 : 1;
    }

    private static int Inspect(string[] args)
    {
        var parsed = ParseSelectorArgs(args, selectorRequired: true);
        var root = AlphaCorpus.FindRoot(parsed.Corpus);
        var path = Path.Combine(root, ".alpha", "runs", parsed.Selector!, "alpha-run.json");
        if (!File.Exists(path)) throw new FileNotFoundException("Alpha run not found", path);
        Console.WriteLine(File.ReadAllText(path));
        return 0;
    }

    private static int New(string[] args)
    {
        var parsed = ParseSelectorArgs(args, selectorRequired: true);
        var root = AlphaCorpus.FindRoot(parsed.Corpus);
        var id = parsed.Selector!;
        if (!System.Text.RegularExpressions.Regex.IsMatch(id, @"^alpha\.[a-z0-9][a-z0-9._-]+$")) throw new InvalidOperationException("Alpha id must match alpha.<lowercase-id>.");
        var leaf = id["alpha.".Length..].Replace('.', '-');
        var folder = Path.Combine(root, "tests", leaf);
        if (Directory.Exists(folder)) throw new InvalidOperationException("Target Alpha folder already exists: " + folder);
        Directory.CreateDirectory(folder);
        var className = string.Concat(leaf.Split('-', '_').Where(x => x.Length > 0).Select(x => char.ToUpperInvariant(x[0]) + x[1..])) + "Scenario";
        var assembly = className.Replace("Scenario", "Alpha");
        var manifest = new AlphaManifest { Schema="omega.alpha.test.v1", Id=id, Title=id, Description="New local Alpha candidate.", Status="draft", Project=assembly+".csproj", AssemblyName=assembly, EntryAssembly=assembly+".dll", Mode="sandbox-runtime", SafetyClass="sandbox-local-runtime", Engines=["rift","srl"], Tags=["candidate"] };
        File.WriteAllText(Path.Combine(folder, "alpha.json"), JsonSerializer.Serialize(manifest, JsonDefaults.Pretty));
        var projectText = string.Join(Environment.NewLine,
            "<Project Sdk=\"Microsoft.NET.Sdk\">",
            "  <PropertyGroup>",
            "    <TargetFramework>net10.0</TargetFramework>",
            "    <Nullable>enable</Nullable>",
            "    <ImplicitUsings>enable</ImplicitUsings>",
            $"    <AssemblyName>{assembly}</AssemblyName>",
            "  </PropertyGroup>",
            "  <ItemGroup>",
            "    <ProjectReference Include=\"../../sdk/Omega.Alpha.Sdk/Omega.Alpha.Sdk.csproj\" />",
            "  </ItemGroup>",
            "</Project>",
            "");
        File.WriteAllText(Path.Combine(folder, assembly + ".csproj"), projectText);

        var sourceText = string.Join(Environment.NewLine,
            "using Omega.Alpha;",
            "",
            $"[AlphaTest(\"{id}\")]",
            $"public sealed class {className} : IAlphaScenario",
            "{",
            "    public void Execute(IAlphaContext context)",
            "    {",
            "        AlphaGuard.RequireRiftAlphaSandbox();",
            "        context.Report.Note(\"scenario.start\", \"Implement bounded offensive behavior here.\");",
            "    }",
            "}",
            "");
        File.WriteAllText(Path.Combine(folder, className + ".cs"), sourceText);
        Console.WriteLine(folder);
        Console.WriteLine("Next: rift-alpha validate " + folder);
        AlphaRegistryWriter.Build(root);
        Console.WriteLine("Registry rebuilt: " + Path.Combine(root, "registry", "registry.json"));
        Console.WriteLine("Then: rift-alpha run " + folder);
        return 0;
    }

    private static int Registry(string[] args)
    {
        if (args.Length == 0 || args[0] != "build") return Fail("registry currently supports: registry build [--corpus <path>]");
        string? corpus = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] == "--corpus" && i + 1 < args.Length) corpus = args[++i];
            else return Fail("unknown registry argument: " + args[i]);
        }
        var root = AlphaCorpus.FindRoot(corpus);
        AlphaRegistryWriter.Build(root);
        Console.WriteLine(Path.Combine(root, "registry", "registry.json"));
        return 0;
    }

    private static int HiddenHost(string[] args)
    {
        var dict = ParsePairs(args);
        return ScenarioHost.Run(Need(dict,"--assembly"), Need(dict,"--id"), Need(dict,"--out"), Need(dict,"--run-id"));
    }

    private static int HiddenSandbox(string[] args)
    {
        if (!OperatingSystem.IsLinux()) return Fail("internal sandbox supervisor is Linux-only");
        var dict = ParsePairs(args);
        var assembly = Need(dict,"--assembly"); var id = Need(dict,"--id"); var outDir=Need(dict,"--out-dir"); var runId=Need(dict,"--run-id");
        var manifest = new AlphaManifest { Id=id, Mode="sandbox-runtime", SafetyClass="sandbox-local-runtime", Engines=["rift"], EntryAssembly=Path.GetFileName(assembly), AssemblyName=Path.GetFileNameWithoutExtension(assembly) };
        var result = RiftAlphaSandbox.RunLinuxSupervisor(manifest, assembly, outDir, runId);
        Console.Out.Write(result.Stdout); Console.Error.Write(result.Stderr); return result.ExitCode;
    }

    private static Dictionary<string,string> ParsePairs(string[] args)
    {
        var d = new Dictionary<string,string>(StringComparer.Ordinal);
        for (var i=0;i<args.Length;i+=2)
        {
            if (i+1>=args.Length || !args[i].StartsWith("--",StringComparison.Ordinal)) throw new InvalidOperationException("invalid internal arguments");
            d[args[i]]=args[i+1];
        }
        return d;
    }
    private static string Need(Dictionary<string,string> d,string k)=>d.TryGetValue(k,out var v)?v:throw new InvalidOperationException("missing "+k);

    private sealed record SelectorArgs(string? Selector, string? Corpus);
    private static SelectorArgs ParseSelectorArgs(string[] args, bool selectorRequired)
    {
        string? selector=null, corpus=null;
        for (int i=0;i<args.Length;i++)
        {
            if (args[i]=="--corpus") { if (++i>=args.Length) throw new InvalidOperationException("--corpus requires a path"); corpus=args[i]; }
            else if (selector is null) selector=args[i];
            else throw new InvalidOperationException("unexpected argument: "+args[i]);
        }
        if (selectorRequired && string.IsNullOrWhiteSpace(selector)) throw new InvalidOperationException("an Alpha id or Alpha folder is required");
        return new SelectorArgs(selector,corpus);
    }

    private static string CreateRunDirectory(string root, string name)
    {
        var safe = string.Concat(name.Select(ch => char.IsLetterOrDigit(ch) || ch is '.' or '-' or '_' ? ch : '-'));
        var dir=Path.Combine(root,".alpha","runs",safe); Directory.CreateDirectory(dir); return dir;
    }

    private static int Fail(string message) { Console.Error.WriteLine("error: "+message); return 2; }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("Rift Alpha — local offensive-security scenario runner (cannot execute normal plugins)");
        Console.Error.WriteLine();
        Console.Error.WriteLine("rift-alpha doctor");
        Console.Error.WriteLine("rift-alpha list [--corpus <path>]");
        Console.Error.WriteLine("rift-alpha validate <alpha-id|folder> [--corpus <path>]");
        Console.Error.WriteLine("rift-alpha build <alpha-id|folder> [--corpus <path>]");
        Console.Error.WriteLine("rift-alpha run <alpha-id|folder> [--corpus <path>]");
        Console.Error.WriteLine("rift-alpha inspect <run-id> [--corpus <path>]");
        Console.Error.WriteLine("rift-alpha new <alpha-id> [--corpus <path>]");
        Console.Error.WriteLine("rift-alpha registry build [--corpus <path>]");
        Console.Error.WriteLine();
        Console.Error.WriteLine("Runtime execution requires WSL2 on Windows or Linux plus bubblewrap, systemd user scopes and cgroup v2.");
        Console.Error.WriteLine("Static-only Alpha artifacts are never executed by this client.");
    }
}
