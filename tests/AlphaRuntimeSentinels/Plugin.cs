using Omega.Alpha;

namespace AlphaRuntimeSentinels;

[AlphaTest("alpha.runtime.sentinels")]
public sealed class RuntimeSentinelsScenario : IAlphaScenario
{
    public void Execute(IAlphaContext context)
    {
        AlphaGuard.RequireRiftAlphaSandbox();
        context.Report.Note("runtime.sentinels", "starting bounded Alpha safe probes");
        AlphaSafeProbes.RunDefault(context.Report);
        context.Report.Note("runtime.sentinels", "completed bounded Alpha safe probes");
    }
}
