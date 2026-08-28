using Omega.Alpha;
using System.Text.Json;

namespace Omega.RiftAlpha;

internal static class RiftAlphaSandbox
{
    public static RiftAlphaRunEvidence Run(AlphaManifest manifest, AlphaBuild build, string runDirectory, string runId)
    {
        if (manifest.Mode != "sandbox-runtime")
            throw new InvalidOperationException($"{manifest.Id} is {manifest.Mode}; static Alpha fixtures are analyzed by defensive scanners and are never executed.");

        var started = DateTimeOffset.UtcNow;
        var request = new RiftAlphaExecutionRequest { RunId = runId, AlphaId = manifest.Id, ScenarioSha256 = build.Sha256, EntryAssembly = manifest.EntryAssembly };
        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, JsonDefaults.Pretty);
        File.WriteAllBytes(Path.Combine(runDirectory, "request.json"), requestBytes);
        var requestSha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(requestBytes)).ToLowerInvariant();
        ProcessResult result;
        string backend;
        if (OperatingSystem.IsWindows())
        {
            backend = "wsl2-bwrap";
            result = RunViaWsl(manifest, build, runDirectory, runId);
        }
        else if (OperatingSystem.IsLinux())
        {
            backend = "linux-bwrap";
            result = RunLinuxSupervisor(manifest, build.EntryAssemblyPath, runDirectory, runId);
        }
        else
        {
            throw new PlatformNotSupportedException("Rift Alpha local execution supports Windows through WSL2 and Linux native execution only.");
        }

        var runtimePath = Path.Combine(runDirectory, "scenario-result.json");
        AlphaRuntimeReport? runtime = null;
        if (File.Exists(runtimePath))
            runtime = JsonSerializer.Deserialize<AlphaRuntimeReport>(File.ReadAllText(runtimePath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        var evidence = new RiftAlphaRunEvidence
        {
            RunId = runId,
            AlphaId = manifest.Id,
            Backend = backend,
            ScenarioSha256 = build.Sha256,
            RequestSha256 = requestSha,
            StartedAt = started,
            CompletedAt = DateTimeOffset.UtcNow,
            ExitCode = result.ExitCode,
            Outcome = result.ExitCode == 0 && runtime?.Outcome == "completed" ? "completed" : "failed",
            Offensive = runtime,
            Rift = new RiftAlphaBoundaryEvidence { StandardError = string.IsNullOrWhiteSpace(result.Stderr) ? null : result.Stderr.Trim() }
        };
        File.WriteAllText(Path.Combine(runDirectory, "alpha-run.json"), JsonSerializer.Serialize(evidence, JsonDefaults.Pretty));
        return evidence;
    }

    public static ProcessResult RunLinuxSupervisor(AlphaManifest manifest, string assemblyPath, string runDirectory, string runId)
    {
        RequireLinuxBoundary();
        var self = Environment.ProcessPath ?? throw new InvalidOperationException("Unable to resolve Rift Alpha executable path.");
        var buildDir = Path.GetDirectoryName(Path.GetFullPath(assemblyPath))!;
        var outDir = Path.GetFullPath(runDirectory);
        Directory.CreateDirectory(outDir);
        var policy = ResolveSeccompPolicy();

        var bwrap = new List<string>
        {
            "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts",
            "--die-with-parent", "--new-session", "--clearenv",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/work", "--dir", "/rift", "--dir", "/scenario", "--dir", "/out", "--dir", "/etc",
            "--ro-bind", "/usr", "/usr"
        };
        foreach (var systemDir in new[] { "/lib", "/lib64" })
            if (Directory.Exists(systemDir)) { bwrap.Add("--ro-bind"); bwrap.Add(systemDir); bwrap.Add(systemDir); }
        if (File.Exists("/etc/ld.so.cache")) { bwrap.Add("--ro-bind"); bwrap.Add("/etc/ld.so.cache"); bwrap.Add("/etc/ld.so.cache"); }
        bwrap.AddRange([
            "--ro-bind", self, "/rift/rift-alpha",
            "--ro-bind", buildDir, "/scenario",
            "--bind", outDir, "/out",
            "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "HOME", "/tmp",
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "DOTNET_BUNDLE_EXTRACT_BASE_DIR", "/tmp/.net",
            "--setenv", "RIFT_ALPHA_EXECUTOR", AlphaGuard.ExecutorName,
            "--chdir", "/work",
            "/rift/rift-alpha", "__host",
            "--assembly", "/scenario/" + Path.GetFileName(assemblyPath),
            "--id", manifest.Id,
            "--out", "/out/scenario-result.json",
            "--run-id", runId
        ]);

        var systemdArgs = new List<string>
        {
            "--user", "--scope", "--quiet", "--collect",
            "-p", "MemoryMax=512M", "-p", "TasksMax=64", "-p", "CPUQuota=100%",
            "--", "sh", "-c",
            "policy=\"$1\"; shift; exec 3<\"$policy\"; exec bwrap --seccomp 3 \"$@\"",
            "rift-alpha-seccomp", policy
        };
        systemdArgs.AddRange(bwrap);
        return ProcessUtil.Run("systemd-run", systemdArgs, timeoutSeconds: 45);
    }

    private static ProcessResult RunViaWsl(AlphaManifest manifest, AlphaBuild build, string runDirectory, string runId)
    {
        if (!ProcessUtil.Exists("wsl.exe")) throw new InvalidOperationException("WSL2 is required for Rift Alpha on Windows.");
        var windowsSelf = AppContext.BaseDirectory;
        var bundledWorker = Path.Combine(windowsSelf, "linux-x64", "rift-alpha");
        if (!File.Exists(bundledWorker)) throw new InvalidOperationException("Bundled Linux Rift Alpha worker missing. Download the complete RiftAlphaClient bundle.");

        string WslPath(string path)
        {
            var converted = ProcessUtil.Run("wsl.exe", ["--exec", "wslpath", "-a", "-u", Path.GetFullPath(path)], timeoutSeconds: 15);
            if (converted.ExitCode != 0) throw new InvalidOperationException("Unable to translate path into WSL: " + converted.Stderr);
            return converted.Stdout.Trim();
        }

        var bundledPolicy = Path.Combine(windowsSelf, "linux-x64", "rift-alpha-seccomp.bpf");
        if (!File.Exists(bundledPolicy)) throw new InvalidOperationException("Bundled Rift Alpha seccomp policy missing. Download the complete RiftAlphaClient bundle.");
        var workerSource = WslPath(bundledWorker);
        var policySource = WslPath(bundledPolicy);
        var assembly = WslPath(build.EntryAssemblyPath);
        var output = WslPath(runDirectory);
        const string worker = "/tmp/omega-rift-alpha/rift-alpha";
        var prep1 = ProcessUtil.Run("wsl.exe", ["--exec", "mkdir", "-p", "/tmp/omega-rift-alpha"], timeoutSeconds: 15);
        if (prep1.ExitCode != 0) throw new InvalidOperationException("Unable to prepare Rift Alpha WSL worker directory: " + prep1.Stderr);
        var prep2 = ProcessUtil.Run("wsl.exe", ["--exec", "cp", workerSource, worker], timeoutSeconds: 15);
        if (prep2.ExitCode != 0) throw new InvalidOperationException("Unable to stage Rift Alpha WSL worker: " + prep2.Stderr);
        var prep3 = ProcessUtil.Run("wsl.exe", ["--exec", "chmod", "0755", worker], timeoutSeconds: 15);
        if (prep3.ExitCode != 0) throw new InvalidOperationException("Unable to arm Rift Alpha WSL worker: " + prep3.Stderr);
        var prep4 = ProcessUtil.Run("wsl.exe", ["--exec", "cp", policySource, "/tmp/omega-rift-alpha/rift-alpha-seccomp.bpf"], timeoutSeconds: 15);
        if (prep4.ExitCode != 0) throw new InvalidOperationException("Unable to stage Rift Alpha seccomp policy: " + prep4.Stderr);

        return ProcessUtil.Run("wsl.exe", ["--exec", worker, "__sandbox-run", "--assembly", assembly, "--id", manifest.Id, "--out-dir", output, "--run-id", runId], timeoutSeconds: 60);
    }

    private static string ResolveSeccompPolicy()
    {
        var explicitPolicy = Environment.GetEnvironmentVariable("RIFT_ALPHA_SECCOMP_POLICY");
        if (!string.IsNullOrWhiteSpace(explicitPolicy) && File.Exists(explicitPolicy)) return Path.GetFullPath(explicitPolicy);
        var bundled = Path.Combine(AppContext.BaseDirectory, "rift-alpha-seccomp.bpf");
        if (File.Exists(bundled)) return bundled;
        var staged = "/tmp/omega-rift-alpha/rift-alpha-seccomp.bpf";
        if (File.Exists(staged)) return staged;
        throw new InvalidOperationException("Rift Alpha seccomp policy is missing.");
    }

    public static void RequireLinuxBoundary()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        foreach (var tool in new[] { "bwrap", "systemd-run", "sh" })
            if (!ProcessUtil.Exists(tool)) throw new InvalidOperationException($"{tool} is required for Rift Alpha local execution.");
        _ = ResolveSeccompPolicy();
        if (!File.Exists("/sys/fs/cgroup/cgroup.controllers")) throw new InvalidOperationException("cgroup v2 is required for Rift Alpha local execution.");
        var scope = ProcessUtil.Run("systemd-run", ["--user", "--scope", "--quiet", "--collect", "true"], timeoutSeconds: 15);
        if (scope.ExitCode != 0) throw new InvalidOperationException("A working systemd user scope is required for Rift Alpha local execution: " + scope.Stderr.Trim());
    }
}
