using System.Reflection;

namespace InterdimensionalRift.Runtime;

public class InstrumentedServiceProxy : DispatchProxy
{
    private Type? serviceType;
    private RuntimeServiceRegistry? registry;

    internal void Initialize(Type type, RuntimeServiceRegistry serviceRegistry)
    {
        serviceType = type;
        registry = serviceRegistry;
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        if (targetMethod is null || serviceType is null || registry is null)
            throw new InvalidOperationException("Rift service proxy was invoked before initialization.");
        return registry.Invoke(serviceType, targetMethod, args);
    }
}
