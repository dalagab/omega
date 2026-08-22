using System.Reflection;
using InterdimensionalRift.Runtime;
using Xunit;

namespace InterdimensionalRift.Tests;

public sealed class DalamudInternalServiceFailFastTest
{
    [Fact]
    public void InternalDalamudServiceLocator_FailsFastInsteadOfBlocking()
    {
        DalamudContract.EnsureLoaded();
        DalamudContract.EnterSandboxFailFastHostMode();

        var dalamud = DalamudContract.Assembly;
        var serviceOpenType = dalamud.GetType("Dalamud.Service`1", throwOnError: true)!;
        var configurationType = dalamud.GetType(
            "Dalamud.Configuration.Internal.DalamudConfiguration",
            throwOnError: true)!;

        var closed = serviceOpenType.MakeGenericType(configurationType);
        var get = closed.GetMethod(
            "Get",
            BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(closed.FullName, "Get");

        Exception? observed = null;
        var attempt = Task.Run(() =>
        {
            try
            {
                _ = get.Invoke(null, null);
            }
            catch (Exception ex)
            {
                observed = ex;
            }
        });

        Assert.True(
            attempt.Wait(TimeSpan.FromSeconds(2)),
            "Dalamud.Service<DalamudConfiguration>.Get() blocked instead of failing fast inside Rift.");

        Assert.NotNull(observed);
    }
}
