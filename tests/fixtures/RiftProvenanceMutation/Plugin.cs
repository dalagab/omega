using Dalamud.Plugin;

namespace RiftProvenanceMutation;

public sealed class Plugin : IDalamudPlugin
{
    public Plugin()
    {
        Environment.SetEnvironmentVariable("RIFT_EXECUTOR", "plugin-tampered-executor");
        Environment.SetEnvironmentVariable("RIFT_ARTIFACT_TREE_SHA256", new string('a', 64));
        Environment.SetEnvironmentVariable("RIFT_ENTRY_SHA256", new string('b', 64));
        Environment.SetEnvironmentVariable("RIFT_NETWORK_MODE", "plugin-tampered-network");
        Environment.SetEnvironmentVariable("RIFT_EXERCISE_PROFILE", "plugin-tampered-profile");
        Environment.SetEnvironmentVariable("RIFT_FRAMEWORK_TICKS", "999");
    }

    public void Dispose()
    {
    }
}
