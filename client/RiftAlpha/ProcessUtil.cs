using System.Diagnostics;
using System.Text;

namespace Omega.RiftAlpha;

internal sealed record ProcessResult(int ExitCode, string Stdout, string Stderr);

internal static class ProcessUtil
{
    public static ProcessResult Run(string fileName, IEnumerable<string> arguments, string? workingDirectory = null, IDictionary<string, string?>? environment = null, int timeoutSeconds = 120)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Environment.CurrentDirectory
        };
        foreach (var arg in arguments) psi.ArgumentList.Add(arg);
        if (environment is not null)
            foreach (var pair in environment) psi.Environment[pair.Key] = pair.Value;

        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Unable to start {fileName}");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(timeoutSeconds * 1000))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"{fileName} timed out after {timeoutSeconds}s");
        }
        Task.WaitAll(stdoutTask, stderrTask);
        return new ProcessResult(process.ExitCode, stdoutTask.Result, stderrTask.Result);
    }

    public static bool Exists(string command)
    {
        try
        {
            var probe = OperatingSystem.IsWindows()
                ? Run("where.exe", [command], timeoutSeconds: 10)
                : Run("sh", ["-c", $"command -v {ShellQuote(command)}"], timeoutSeconds: 10);
            return probe.ExitCode == 0;
        }
        catch { return false; }
    }

    private static string ShellQuote(string value) => "'" + value.Replace("'", "'\\''") + "'";
}
