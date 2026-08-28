namespace Omega.Alpha;

/// <summary>Marks a type as an Alpha offensive-security scenario. Alpha metadata has calibration authority only.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class AlphaTestAttribute(string id) : Attribute
{
    public string Id { get; } = id;
}

/// <summary>Documents an expected independent defensive finding. Alpha code cannot assert that the finding happened.</summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = true, Inherited = false)]
public sealed class ExpectedFindingAttribute(string findingId) : Attribute
{
    public string FindingId { get; } = findingId;
}

/// <summary>The only executable workload contract understood by Rift Alpha.</summary>
public interface IAlphaScenario
{
    void Execute(IAlphaContext context);
}

public interface IAlphaContext
{
    string RunId { get; }
    string AlphaId { get; }
    IAlphaReporter Report { get; }
}

/// <summary>
/// Reports what the offensive scenario attempted or observed from its own point of view.
/// These records are always ALPHA-prefixed and never become defensive findings by themselves.
/// </summary>
public interface IAlphaReporter
{
    void Attempt(string operation, string? detail = null);
    void Observed(string operation, string? detail = null);
    void Note(string operation, string? detail = null);
}

public static class AlphaGuard
{
    public const string ExecutorName = "rift-alpha-bubblewrap-v1";

    /// <summary>Active Alpha scenarios are armed only inside the dedicated Rift Alpha sandbox.</summary>
    public static bool IsRiftAlphaSandbox =>
        string.Equals(Environment.GetEnvironmentVariable("RIFT_ALPHA_EXECUTOR"), ExecutorName, StringComparison.Ordinal);

    /// <summary>Compatibility alias for early Alpha fixtures.</summary>
    public static bool IsRiftSandbox => IsRiftAlphaSandbox;

    public static void RequireRiftAlphaSandbox()
    {
        if (!IsRiftAlphaSandbox)
            throw new InvalidOperationException("Omega Alpha runtime scenarios require the dedicated Rift Alpha sandbox.");
    }

    public static void RequireRiftSandbox() => RequireRiftAlphaSandbox();
}
