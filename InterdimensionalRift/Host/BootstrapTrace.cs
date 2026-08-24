namespace InterdimensionalRift.Host;

internal static class BootstrapTrace
{
    private static readonly bool Enabled = string.Equals(
        Environment.GetEnvironmentVariable("RIFT_BOOTSTRAP_TRACE"),
        "1",
        StringComparison.Ordinal);
    private static int count;

    public static void Record(string stage)
    {
        if (Enabled && Interlocked.Increment(ref count) <= 256)
            Console.Error.WriteLine($"rift.bootstrap stage={stage}");
    }
}
