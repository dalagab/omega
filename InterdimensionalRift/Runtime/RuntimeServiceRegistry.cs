using System.Collections.Concurrent;
using System.Reflection;
using InterdimensionalRift.Instrumentation;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Creates instrumentation-first implementations of Dalamud service interfaces
/// on demand. DispatchProxy lets Rift follow the frozen API surface without
/// maintaining a hand-written implementation for every interface member.
/// </summary>
public sealed class RuntimeServiceRegistry : IServiceProvider
{
    private readonly AccessTracker tracker;
    private readonly ConcurrentDictionary<Type, object> services = new();
    private readonly ConcurrentDictionary<(Type ServiceType, string EventName), List<Delegate>> eventHandlers = new();
    private readonly string internalName;
    private readonly FileInfo assemblyLocation;
    private readonly DirectoryInfo configDirectory;
    private readonly FileInfo configFile;

    public RuntimeServiceRegistry(AccessTracker tracker, string internalName, string pluginPath)
    {
        this.tracker = tracker;
        this.internalName = internalName;
        assemblyLocation = new FileInfo(pluginPath);
        configDirectory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "rift-config"));
        configFile = new FileInfo(Path.Combine(configDirectory.FullName, $"{internalName}.json"));
    }

    public object? GetService(Type serviceType)
    {
        if (serviceType == typeof(IServiceProvider))
            return this;

        if (!serviceType.IsInterface)
            return DefaultValueFactory.Create(serviceType, this);

        return services.GetOrAdd(serviceType, CreateProxy);
    }

    public T GetRequiredService<T>() where T : class =>
        (T)(GetService(typeof(T)) ?? throw new InvalidOperationException($"Rift cannot provide {typeof(T).FullName}"));

    public bool TryGetService(Type serviceType, out object? service)
    {
        service = GetService(serviceType);
        return service is not null;
    }

    public bool InjectPluginServices(Type pluginType)
    {
        var injected = false;
        for (var type = pluginType; type is not null; type = type.BaseType)
        {
            const BindingFlags flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;

            foreach (var property in type.GetProperties(flags))
            {
                if (!HasPluginServiceAttribute(property))
                    continue;

                var setter = property.GetSetMethod(nonPublic: true);
                if (setter is null)
                    throw new InvalidOperationException($"[PluginService] property {type.FullName}.{property.Name} has no setter");

                var value = GetService(property.PropertyType)
                    ?? throw new InvalidOperationException($"Rift has no service for {property.PropertyType.FullName}");
                setter.Invoke(null, new[] { value });
                tracker.ServiceInjection(property.PropertyType.FullName ?? property.PropertyType.Name,
                    $"{type.FullName}.{property.Name}", "static_property");
                injected = true;
            }

            foreach (var field in type.GetFields(flags))
            {
                if (!HasPluginServiceAttribute(field))
                    continue;
                if (field.IsInitOnly)
                    throw new InvalidOperationException($"[PluginService] field {type.FullName}.{field.Name} is readonly");

                var value = GetService(field.FieldType)
                    ?? throw new InvalidOperationException($"Rift has no service for {field.FieldType.FullName}");
                field.SetValue(null, value);
                tracker.ServiceInjection(field.FieldType.FullName ?? field.FieldType.Name,
                    $"{type.FullName}.{field.Name}", "static_field");
                injected = true;
            }
        }

        return injected;
    }

    public object CreatePluginInstance(Type pluginType)
    {
        InjectPluginServices(pluginType);

        var candidates = pluginType
            .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(c => !c.IsPrivate)
            .OrderByDescending(c => c.GetParameters().Length)
            .ToArray();

        foreach (var ctor in candidates)
        {
            var parameters = ctor.GetParameters();
            var args = new object?[parameters.Length];
            var supported = true;
            for (var i = 0; i < parameters.Length; i++)
            {
                var p = parameters[i];
                var value = GetService(p.ParameterType);
                if (value is null && !p.HasDefaultValue && p.ParameterType.IsValueType)
                {
                    supported = false;
                    break;
                }
                args[i] = value ?? (p.HasDefaultValue ? p.DefaultValue : null);
            }

            if (!supported)
                continue;

            tracker.Lifecycle("constructor", "begin", pluginType.FullName);
            try
            {
                var instance = ctor.Invoke(args);
                tracker.Lifecycle("constructor", "completed", pluginType.FullName);
                return instance;
            }
            catch (TargetInvocationException ex)
            {
                tracker.Lifecycle("constructor", "threw", pluginType.FullName, ex.InnerException ?? ex);
                throw ex.InnerException ?? ex;
            }
        }

        throw new InvalidOperationException($"No constructible constructor was found for {pluginType.FullName}.");
    }

    internal object? Invoke(Type serviceType, MethodInfo method, object?[]? args)
    {
        args ??= Array.Empty<object?>();
        var serviceName = serviceType.Name;

        if (method.IsSpecialName && (method.Name.StartsWith("add_", StringComparison.Ordinal) || method.Name.StartsWith("remove_", StringComparison.Ordinal)))
        {
            var add = method.Name.StartsWith("add_", StringComparison.Ordinal);
            var eventName = method.Name.Substring(add ? 4 : 7);
            if (args.FirstOrDefault() is Delegate handler)
                ChangeEventHandler(serviceType, eventName, handler, add);
            tracker.ServiceTouch(serviceName, method.Name);
            return null;
        }

        if (serviceType.FullName == "Dalamud.Plugin.IDalamudPluginInterface")
        {
            var special = InvokePluginInterface(method, args);
            if (special.Handled)
                return special.Value;
        }

        if (serviceName == "IPluginLog")
        {
            tracker.Log(method.Name, ExtractLogMessage(args));
            return DefaultValueFactory.Create(method.ReturnType, this);
        }

        tracker.ServiceTouch(serviceName, method.Name, parameters: SnapshotParameters(method, args));
        return DefaultValueFactory.Create(method.ReturnType, this);
    }

    public void FireFrameworkTick()
    {
        var frameworkType = DalamudContract.Assembly.GetType("Dalamud.Plugin.Services.IFramework");
        if (frameworkType is null)
            return;

        var framework = GetService(frameworkType);
        FireEvent(frameworkType, "Update", framework);
    }

    private object CreateProxy(Type interfaceType)
    {
        var proxy = DispatchProxy.Create(interfaceType, typeof(InstrumentedServiceProxy));
        ((InstrumentedServiceProxy)proxy).Initialize(interfaceType, this);
        return proxy;
    }

    private (bool Handled, object? Value) InvokePluginInterface(MethodInfo method, object?[] args)
    {
        switch (method.Name)
        {
            case "GetService" when args.Length == 1 && args[0] is Type requested:
                tracker.ServiceTouch("IDalamudPluginInterface", "GetService",
                    parameters: new Dictionary<string, string?> { ["type"] = requested.FullName });
                return (true, GetService(requested));
            case "GetPluginConfig":
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name);
                return (true, null);
            case "SavePluginConfig":
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name);
                return (true, null);
            case "GetPluginConfigDirectory":
                return (true, configDirectory.FullName);
            case "GetPluginLocDirectory":
                return (true, assemblyLocation.Directory?.FullName ?? string.Empty);
            case "get_InternalName":
                return (true, internalName);
            case "get_AssemblyLocation":
                return (true, assemblyLocation);
            case "get_ConfigDirectory":
                return (true, configDirectory);
            case "get_ConfigFile":
                return (true, configFile);
            case "get_DalamudAssetDirectory":
                return (true, new DirectoryInfo(AppContext.BaseDirectory));
            case "get_InstalledPlugins":
                return (true, DefaultValueFactory.Create(method.ReturnType, this));
            case "Inject" when args.FirstOrDefault() is object target:
                InjectInstance(target);
                return (true, true);
            case "InjectAsync" when args.FirstOrDefault() is object asyncTarget:
                InjectInstance(asyncTarget);
                return (true, Task.CompletedTask);
            default:
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name,
                    parameters: SnapshotParameters(method, args));
                return (true, DefaultValueFactory.Create(method.ReturnType, this));
        }
    }

    private void InjectInstance(object target)
    {
        var type = target.GetType();
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        foreach (var property in type.GetProperties(flags))
        {
            if (!HasPluginServiceAttribute(property)) continue;
            var setter = property.GetSetMethod(true);
            if (setter is null) continue;
            var value = GetService(property.PropertyType);
            if (value is null) continue;
            setter.Invoke(target, new[] { value });
            tracker.ServiceInjection(property.PropertyType.FullName ?? property.PropertyType.Name,
                $"{type.FullName}.{property.Name}", "instance_property");
        }
    }

    private static bool HasPluginServiceAttribute(MemberInfo member) =>
        member.CustomAttributes.Any(a => a.AttributeType.FullName == "Dalamud.IoC.PluginServiceAttribute");

    private void ChangeEventHandler(Type serviceType, string eventName, Delegate handler, bool add)
    {
        var list = eventHandlers.GetOrAdd((serviceType, eventName), _ => new List<Delegate>());
        lock (list)
        {
            if (add) list.Add(handler);
            else list.Remove(handler);
        }
    }

    private void FireEvent(Type serviceType, string eventName, params object?[] args)
    {
        if (!eventHandlers.TryGetValue((serviceType, eventName), out var list))
            return;

        Delegate[] snapshot;
        lock (list) snapshot = list.ToArray();
        foreach (var handler in snapshot)
        {
            try
            {
                handler.DynamicInvoke(args);
                tracker.Lifecycle($"event:{serviceType.Name}.{eventName}", "completed");
            }
            catch (TargetInvocationException ex)
            {
                tracker.Lifecycle($"event:{serviceType.Name}.{eventName}", "threw", exception: ex.InnerException ?? ex);
            }
        }
    }

    private static string ExtractLogMessage(object?[] args)
    {
        foreach (var arg in args)
        {
            if (arg is string text)
                return text;
        }
        return string.Join(" ", args.Where(a => a is not null).Select(a => a!.ToString()));
    }

    private static Dictionary<string, string?> SnapshotParameters(MethodInfo method, object?[] args)
    {
        var result = new Dictionary<string, string?>(StringComparer.Ordinal);
        var parameters = method.GetParameters();
        for (var i = 0; i < Math.Min(parameters.Length, args.Length); i++)
        {
            var value = args[i];
            result[parameters[i].Name ?? $"arg{i}"] = value switch
            {
                null => null,
                string s => s.Length <= 512 ? s : s[..512],
                Type t => t.FullName,
                Delegate d => d.Method.DeclaringType?.FullName + "." + d.Method.Name,
                _ when value.GetType().IsPrimitive || value is Enum => value.ToString(),
                _ => value.GetType().FullName,
            };
        }
        return result;
    }
}
