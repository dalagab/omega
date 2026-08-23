using System.Diagnostics;
using InterdimensionalRift.Host;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift;

internal static class Program
{
    public static int Main(string[] args)
    {
        // The managed host is instrumentation, not the security boundary.
        // Production/untrusted execution must arrive through the fail-closed
        // Bubblewrap supervisor, which stamps RIFT_EXECUTOR. Developers may
        // explicitly opt into an unsafe direct run for local fixture work.
        var executor = Environment.GetEnvironmentVariable("RIFT_EXECUTOR");
        var allowUnsafeDirect = Environment.GetEnvironmentVariable("RIFT_ALLOW_UNSANDBOXED") == "1";
        if (!string.Equals(executor, "bubblewrap-v2", StringComparison.Ordinal) && !allowUnsafeDirect)
        {
            Console.Error.WriteLine("refusing direct plugin execution: use tools/run-rift-bwrap.sh");
            Console.Error.WriteLine("development fixtures only: set RIFT_ALLOW_UNSANDBOXED=1 to bypass this guard");
            return 2;
        }

        if (args.Length == 0 || args[0] is "-h" or "--help" or "/?")
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        // AssemblyLoadContext.LoadFromAssemblyPath requires an absolute path; resolve
        // any relative input against the current working directory before we hand it on.
        var pluginPath = Path.GetFullPath(args[0]);
        string? outPath = null;
        TimeSpan timeout = TimeSpan.FromSeconds(10);
        bool noColor = false;
        int frameworkTicks = 3;
        string exerciseProfile = "post-init-safe-v1";

        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--out":
                case "-o":
                    if (i + 1 >= args.Length) { Console.Error.WriteLine("--out requires a path"); return 2; }
                    outPath = args[++i];
                    break;
                case "--timeout":
                case "-t":
                    if (i + 1 >= args.Length || !double.TryParse(args[++i], out var sec) || sec <= 0)
                    {
                        Console.Error.WriteLine("--timeout requires a positive number of seconds");
                        return 2;
                    }
                    timeout = TimeSpan.FromSeconds(sec);
                    break;
                case "--framework-ticks":
                    if (i + 1 >= args.Length || !int.TryParse(args[++i], out frameworkTicks) || frameworkTicks < 0 || frameworkTicks > 32)
                    {
                        Console.Error.WriteLine("--framework-ticks requires an integer from 0 to 32");
                        return 2;
                    }
                    break;
                case "--exercise-profile":
                    if (i + 1 >= args.Length) { Console.Error.WriteLine("--exercise-profile requires a value"); return 2; }
                    exerciseProfile = args[++i];
                    if (exerciseProfile != "post-init-safe-v1" && exerciseProfile != "none")
                    {
                        Console.Error.WriteLine("--exercise-profile must be post-init-safe-v1 or none");
                        return 2;
                    }
                    break;
                case "--no-color":
                    noColor = true;
                    break;
                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    return 2;
            }
        }

        var sw = Stopwatch.StartNew();
        var host = new SandboxHost();
        SandboxReport report;
        try
        {
            report = host.Run(pluginPath, timeout, frameworkTicks, exerciseProfile);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"sandbox tool error: {ex.GetType().Name}: {ex.Message}");
            return 2;
        }
        sw.Stop();

        var json = RuntimeObservationReporter.Serialize(report);

        if (outPath is not null)
        {
            try
            {
                File.WriteAllText(outPath, json);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"failed to write report to {outPath}: {ex.Message}");
                return 2;
            }
        }
        else
        {
            Console.Out.WriteLine(json);
        }

        PrintHumanSummary(report, sw.Elapsed, noColor);

        return report.Plugin.LoadOutcome == "ok" ? 0 : 1;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("interdimensional-rift <plugin.dll> [--out <path>] [--timeout <seconds>] [--exercise-profile post-init-safe-v1|none] [--framework-ticks 0..32] [--no-color]");
        Console.Error.WriteLine();
        Console.Error.WriteLine("Loads a plugin targeting Dalamud.Plugin into a sandbox and");
        Console.Error.WriteLine("emits a neutral JSON runtime-observation report to --out (or stdout).");
    }

    private static void PrintHumanSummary(SandboxReport report, TimeSpan elapsed, bool noColor)
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine($"plugin         : {report.Plugin.Path}");
        Console.Error.WriteLine($"internal name  : {report.Plugin.InternalName}");
        Console.Error.WriteLine($"load outcome   : {report.Plugin.LoadOutcome}{(report.Plugin.LoadError is null ? "" : " (" + report.Plugin.LoadError + ")")}");
        Console.Error.WriteLine($"init duration  : {report.Plugin.InitDurationMs} ms");
        Console.Error.WriteLine($"dispose outcome: {report.Plugin.DisposeOutcome}{(report.Plugin.DisposeError is null ? "" : " (" + report.Plugin.DisposeError + ")")}");
        Console.Error.WriteLine($"exercise       : {report.Exercise.Profile} ({report.Exercise.Status}) {report.Exercise.RegistrationsExercised}/{report.Exercise.RegistrationsDiscovered} registrations exercised");
        Console.Error.WriteLine($"observations   : {report.Summary.TotalObservations} total");
        Console.Error.WriteLine($"by kind        : {string.Join(", ", report.Summary.ByKind.Select(kv => $"{kv.Key}={kv.Value}"))}");
        Console.Error.WriteLine($"wall time      : {elapsed.TotalMilliseconds:F0} ms");
    }
}
