using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Runtime;
using Xunit;

namespace InterdimensionalRift.Tests;

public sealed class SyntheticGameDataFixtureStoreTest
{
    [Fact]
    public void ServesOnlyExactStagedFixtureFiles()
    {
        var root = Path.Combine(Path.GetTempPath(), $"rift-fixture-{Guid.NewGuid():N}");
        var previous = Environment.GetEnvironmentVariable("RIFT_GAME_DATA_FIXTURE_DIR");
        try
        {
            var expected = new byte[] { 0x66, 0x63, 0x73, 0x76 };
            var target = Path.Combine(root, "common", "font", "axis_12.fdt");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllBytes(target, expected);
            Environment.SetEnvironmentVariable("RIFT_GAME_DATA_FIXTURE_DIR", root);

            var tracker = new AccessTracker();
            var store = new SyntheticGameDataFixtureStore(tracker);

            Assert.True(store.Contains("common/font/axis_12.fdt"));
            Assert.False(store.Contains("../common/font/axis_12.fdt"));
            Assert.True(store.TryCreateFileResource("common/font/axis_12.fdt", out var file));
            var data = (byte[])file!.GetType().GetProperty("Data")!.GetValue(file)!;
            Assert.Equal(expected, data);
            Assert.Contains(tracker.Snapshot(), observation =>
                observation.Component == "IDataManager" &&
                observation.Operation == "GetFile" &&
                observation.Outcome == "synthetic_fixture");
        }
        finally
        {
            Environment.SetEnvironmentVariable("RIFT_GAME_DATA_FIXTURE_DIR", previous);
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }
}
