using InterdimensionalRift.Artifacts;
using Xunit;

namespace InterdimensionalRift.Tests;

public sealed class ArtifactInventoryTest
{
    [Fact]
    public void TrustedHeadlessUiShim_IsExcludedFromPluginInventory()
    {
        var root = Path.Combine(Path.GetTempPath(), $"rift-artifact-{Guid.NewGuid():N}");
        var previousPath = Environment.GetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_PATH");
        var previousSha = Environment.GetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_SHA256");
        try
        {
            Directory.CreateDirectory(root);
            var plugin = Path.Combine(root, "Plugin.dll");
            var shim = Path.Combine(root, "cimgui.dll");
            File.WriteAllBytes(plugin, [0x01, 0x02]);
            File.WriteAllBytes(shim, [0x03, 0x04]);
            var shimHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(shim))).ToLowerInvariant();

            Environment.SetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_PATH", "cimgui.dll");
            Environment.SetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_SHA256", shimHash);

            var inventory = ArtifactInventory.Build(root);

            Assert.Contains(inventory.Files, file => file.Path == "Plugin.dll");
            Assert.DoesNotContain(inventory.Files, file => file.Path == "cimgui.dll");
        }
        finally
        {
            Environment.SetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_PATH", previousPath);
            Environment.SetEnvironmentVariable("RIFT_HEADLESS_UI_SHIM_SHA256", previousSha);
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }
}
