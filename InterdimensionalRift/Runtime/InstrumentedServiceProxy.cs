using System.Reflection;

namespace InterdimensionalRift.Runtime;

public class InstrumentedServiceProxy : DispatchProxy
{
    private Type? serviceType;
    private RuntimeServiceRegistry? registry;
    private string? instanceTag;

    internal void Initialize(Type type, RuntimeServiceRegistry serviceRegistry, string? tag = null)
    {
        serviceType = type;
        registry = serviceRegistry;
        instanceTag = tag;
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        if (targetMethod is null || serviceType is null || registry is null)
            throw new InvalidOperationException("Rift service proxy was invoked before initialization.");
        return registry.Invoke(serviceType, targetMethod, args, instanceTag);
    }
}
