namespace InterdimensionalRift.Runtime;

internal sealed class ExerciseCandidate
{
    public string Id { get; init; } = string.Empty;
    public string Kind { get; init; } = string.Empty;
    public string Component { get; init; } = string.Empty;
    public string Operation { get; init; } = string.Empty;
    public string? Target { get; init; }
    public Delegate Handler { get; init; } = null!;
    public object?[] Arguments { get; init; } = Array.Empty<object?>();
    public bool EnabledByProfile { get; init; }
    public string? UnexercisedReason { get; init; }
    public int Repeat { get; init; } = 1;
    public int DueTick { get; init; }
    public bool RequiresActiveRegistration { get; init; } = true;
}

internal sealed class RegisteredDelegate
{
    public string Id { get; init; } = string.Empty;
    public Delegate Handler { get; init; } = null!;
}

internal sealed class CommandRegistration
{
    public string Id { get; init; } = string.Empty;
    public string Command { get; init; } = string.Empty;
    public Delegate Handler { get; init; } = null!;
}

internal sealed class ScheduledCallbackRegistration
{
    public string Id { get; init; } = string.Empty;
    public string Operation { get; init; } = string.Empty;
    public Delegate Callback { get; init; } = null!;
    public Dictionary<string, string?> Parameters { get; init; } = new(StringComparer.Ordinal);
    public int DueTick { get; init; } = 1;
    public string? UnexercisedReason { get; init; }
}

internal sealed class IpcEndpointState
{
    public string Id { get; init; } = string.Empty;
    public string Key { get; init; } = string.Empty;
    public string Channel { get; init; } = string.Empty;
    public string Direction { get; init; } = string.Empty;
    public Type InterfaceType { get; init; } = null!;
    public object Proxy { get; init; } = null!;
    public List<RegisteredDelegate> Subscribers { get; } = new();
    public RegisteredDelegate? ProviderAction { get; set; }
    public RegisteredDelegate? ProviderFunc { get; set; }
}
