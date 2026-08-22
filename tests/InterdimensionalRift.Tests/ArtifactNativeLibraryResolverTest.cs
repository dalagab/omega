using Xunit;
using InterdimensionalRift.Host;

namespace InterdimensionalRift.Tests;

public sealed class ArtifactNativeLibraryResolverTest
{
    [Fact]
    public void FindsLinuxRidNativeLibraryFromArtifact()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var root = Path.Combine(Path.GetTempPath(), "rift-native-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var nativeDir = Path.Combine(root, "runtimes", "linux-x64", "native");
            Directory.CreateDirectory(nativeDir);
            var expected = Path.Combine(nativeDir, "libe_sqlite3.so");
            File.WriteAllBytes(expected, new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F' });

            var resolved = ArtifactNativeLibraryResolver.Find(root, "e_sqlite3");

            Assert.Equal(Path.GetFullPath(expected), resolved);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public void DoesNotResolveOutsideArtifactRoot()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var root = Path.Combine(Path.GetTempPath(), "rift-native-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var resolved = ArtifactNativeLibraryResolver.Find(root, "../../libc.so.6");
            Assert.Null(resolved);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }
}
