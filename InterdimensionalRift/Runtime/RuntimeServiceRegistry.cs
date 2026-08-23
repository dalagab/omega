using System.Collections.Concurrent;
using System.Reflection;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

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
    private readonly ConcurrentDictionary<string, object> sharedData = new(StringComparer.Ordinal);
    private readonly string internalName;
    private readonly FileInfo assemblyLocation;
    private readonly DirectoryInfo configDirectory;
    private readonly FileInfo configFile;
    private readonly Version assemblyVersion;

    public RuntimeServiceRegistry(AccessTracker tracker, string internalName, string pluginPath)
    {
        this.tracker = tracker;
        this.internalName = internalName;
        assemblyLocation = new FileInfo(pluginPath);
        configDirectory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "rift-config"));
        configFile = new FileInfo(Path.Combine(configDirectory.FullName, $"{internalName}.json"));
        assemblyVersion = AssemblyName.GetAssemblyName(pluginPath).Version ?? new Version(0, 0, 0, 0);
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

        if (serviceType.FullName == "Dalamud.Plugin.Internal.Types.Manifest.IPluginManifest")
        {
            tracker.ServiceTouch("IPluginManifest", method.Name, parameters: SnapshotParameters(method, args));
            return method.Name switch
            {
                "get_InternalName" => internalName,
                "get_AssemblyVersion" => assemblyVersion,
                _ => DefaultValueFactory.Create(method.ReturnType, this),
            };
        }

        if (serviceName == "ISigScanner")
        {
            var special = InvokeSigScanner(method, args);
            if (special.Handled)
                return special.Value;
        }

        if (serviceName == "IDataManager")
        {
            var special = InvokeDataManager(method, args);
            if (special.Handled)
                return special.Value;
        }

        if (serviceName == "IGameInteropProvider")
        {
            var special = InvokeGameInterop(method, args);
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
        if (RequiresConstraintPreservingProxy(interfaceType))
            return ConstraintPreservingProxyFactory.Create(interfaceType, this);

        var proxy = DispatchProxy.Create(interfaceType, typeof(InstrumentedServiceProxy));
        ((InstrumentedServiceProxy)proxy).Initialize(interfaceType, this);
        return proxy;
    }

    private static bool RequiresConstraintPreservingProxy(Type interfaceType)
    {
        // DispatchProxy is fine for most Dalamud interfaces, but it can generate
        // invalid CLR signatures when a generic return type embeds a constrained
        // method parameter (Hook<T>, ExcelSheet<T>, SubrowExcelSheet<T>, etc.).
        // Keep interfaces with by-ref parameters on DispatchProxy until the Rift
        // emitter supports copy-back semantics for ref/out parameters.
        var methods = interfaceType.GetMethods();
        if (methods.Any(m => m.GetParameters().Any(p => p.ParameterType.IsByRef)))
            return interfaceType.FullName == "Dalamud.Plugin.Services.IGameInteropProvider";

        return methods.Any(MethodRequiresConstraintPreservation);
    }

    private static bool MethodRequiresConstraintPreservation(MethodInfo method)
    {
        if (!method.IsGenericMethodDefinition)
            return false;

        foreach (var parameter in method.GetGenericArguments())
        {
            var hasSpecialConstraint = parameter.GenericParameterAttributes != GenericParameterAttributes.None;
            var hasTypeConstraint = parameter.GetGenericParameterConstraints().Length > 0;
            if ((hasSpecialConstraint || hasTypeConstraint) && TypeContains(method.ReturnType, parameter))
                return true;
        }

        return false;
    }

    private static bool TypeContains(Type type, Type genericParameter)
    {
        if (type == genericParameter)
            return true;
        if (type.IsArray || type.IsByRef || type.IsPointer)
            return TypeContains(type.GetElementType()!, genericParameter);
        return type.IsGenericType && type.GetGenericArguments().Any(t => TypeContains(t, genericParameter));
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
            case "get_Manifest":
            {
                var manifestType = method.ReturnType;
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name);
                return (true, GetService(manifestType));
            }
            case "get_LoadTime":
            case "get_LoadTimeUTC":
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name);
                return (true, DateTime.UtcNow);
            case "get_LoadTimeDelta":
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name);
                return (true, TimeSpan.Zero);
            case "GetOrCreateData" when method.IsGenericMethod && args.Length >= 2 && args[0] is string tag && args[1] is Delegate generator:
            {
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name,
                    parameters: new Dictionary<string, string?> { ["tag"] = tag, ["dataGenerator"] = generator.Method.DeclaringType?.FullName + "." + generator.Method.Name });
                var value = sharedData.GetOrAdd(tag, _ => generator.DynamicInvoke()
                    ?? throw new InvalidOperationException($"Data generator for {tag} returned null."));
                return (true, value);
            }
            case "GetData" when method.IsGenericMethod && args.Length >= 1 && args[0] is string getTag:
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name,
                    parameters: new Dictionary<string, string?> { ["tag"] = getTag });
                return (true, sharedData.TryGetValue(getTag, out var getValue) ? getValue : null);
            case "RelinquishData" when args.Length >= 1 && args[0] is string relinquishTag:
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name,
                    parameters: new Dictionary<string, string?> { ["tag"] = relinquishTag });
                sharedData.TryRemove(relinquishTag, out _);
                return (true, null);
            case "Create" when method.IsGenericMethod:
            {
                var requested = method.GetGenericArguments()[0];
                var scoped = ExtractScopedObjects(args);
                tracker.ServiceTouch("IDalamudPluginInterface", "Create",
                    parameters: new Dictionary<string, string?>
                    {
                        ["type"] = requested.FullName,
                        ["scoped_count"] = scoped.Length.ToString(),
                    });
                try
                {
                    return (true, CreateInjectedObject(requested, scoped));
                }
                catch (Exception ex)
                {
                    tracker.Record(RuntimeObservationKind.ServiceAccess,
                        "IDalamudPluginInterface", "Create", "failed", exception: ex,
                        parameters: new Dictionary<string, string?> { ["type"] = requested.FullName });
                    return (true, null);
                }
            }
            case "CreateAsync" when method.IsGenericMethod:
            {
                var requested = method.GetGenericArguments()[0];
                var scoped = ExtractScopedObjects(args);
                tracker.ServiceTouch("IDalamudPluginInterface", "CreateAsync",
                    parameters: new Dictionary<string, string?>
                    {
                        ["type"] = requested.FullName,
                        ["scoped_count"] = scoped.Length.ToString(),
                    });
                try
                {
                    var created = CreateInjectedObject(requested, scoped);
                    var task = typeof(Task).GetMethod(nameof(Task.FromResult))!
                        .MakeGenericMethod(requested)
                        .Invoke(null, new[] { created });
                    return (true, task);
                }
                catch (Exception ex)
                {
                    tracker.Record(RuntimeObservationKind.ServiceAccess,
                        "IDalamudPluginInterface", "CreateAsync", "failed", exception: ex,
                        parameters: new Dictionary<string, string?> { ["type"] = requested.FullName });
                    var fromException = typeof(Task).GetMethods(BindingFlags.Public | BindingFlags.Static)
                        .Single(m => m.Name == nameof(Task.FromException) && m.IsGenericMethodDefinition &&
                                     m.GetGenericArguments().Length == 1 && m.GetParameters().Length == 1);
                    var task = fromException.MakeGenericMethod(requested)
                        .Invoke(null, new object[] { ex });
                    return (true, task);
                }
            }
            case "Inject" when args.FirstOrDefault() is object target:
                InjectInstance(target, ExtractScopedObjects(args.Skip(1).ToArray()));
                return (true, true);
            case "InjectAsync" when args.FirstOrDefault() is object asyncTarget:
                InjectInstance(asyncTarget, ExtractScopedObjects(args.Skip(1).ToArray()));
                return (true, Task.CompletedTask);
            default:
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name,
                    parameters: SnapshotParameters(method, args));
                return (true, DefaultValueFactory.Create(method.ReturnType, this));
        }
    }

    private (bool Handled, object? Value) InvokeSigScanner(MethodInfo method, object?[] args)
    {
        if (method.Name is "ScanText" or "GetStaticAddressFromSig" or "ScanModule" or "TryScanText" or "TryGetStaticAddressFromSig")
        {
            var signature = args.OfType<string>().FirstOrDefault() ?? string.Empty;
            tracker.Signature(method.Name, signature, "synthetic_zero", 0);
            tracker.ServiceTouch("ISigScanner", method.Name, parameters: SnapshotParameters(method, args));

            // Keep all signature results inert. Out-parameter APIs are not used by
            // the constraint-preserving interop path yet and remain on the normal
            // DispatchProxy implementation.
            if (method.ReturnType == typeof(IntPtr))
                return (true, IntPtr.Zero);
            if (method.ReturnType == typeof(UIntPtr))
                return (true, UIntPtr.Zero);
        }
        return (false, null);
    }

    private (bool Handled, object? Value) InvokeDataManager(MethodInfo method, object?[] args)
    {
        tracker.ServiceTouch("IDataManager", method.Name, parameters: SnapshotParameters(method, args));

        if (method.IsGenericMethod &&
            method.Name is "GetExcelSheet" or "GetSubrowExcelSheet" &&
            method.ReturnType.IsGenericType)
        {
            var definitionName = method.ReturnType.GetGenericTypeDefinition().FullName;
            if (definitionName is "Lumina.Excel.ExcelSheet`1" or "Lumina.Excel.SubrowExcelSheet`1")
                return (true, SyntheticGameDataRuntime.CreateEmptySheet(method.ReturnType, tracker, method.Name));
        }

        if (method.Name == "FileExists")
            return (true, false);

        // GetFile/GetFileAsync and direct GameData/Excel access remain unavailable
        // until a later, explicitly modeled game-data fixture is introduced.
        return (true, DefaultValueFactory.Create(method.ReturnType, this));
    }

    private (bool Handled, object? Value) InvokeGameInterop(MethodInfo method, object?[] args)
    {
        tracker.ServiceTouch("IGameInteropProvider", method.Name, parameters: SnapshotParameters(method, args));

        if (method.Name == "InitializeFromAttributes")
        {
            var self = args.FirstOrDefault();
            tracker.Record(RuntimeObservationKind.Hook, "IGameInteropProvider", method.Name, "observed_inert",
                message: self?.GetType().FullName,
                parameters: new Dictionary<string, string?>
                {
                    ["native_patch"] = "false",
                    ["attribute_initialization"] = "not_applied",
                });
            return (true, null);
        }

        if (method.IsGenericMethod && method.ReturnType.IsGenericType &&
            method.ReturnType.GetGenericTypeDefinition().FullName == "Dalamud.Hooking.Hook`1")
        {
            var detour = args.OfType<Delegate>().FirstOrDefault();
            if (detour is null)
                return (true, null);

            var descriptor = method.Name;
            var signature = args.OfType<string>().FirstOrDefault();
            if (!string.IsNullOrEmpty(signature))
                descriptor += $" signature={signature}";
            else
            {
                var address = args.FirstOrDefault(x => x is IntPtr || x is UIntPtr);
                if (address is not null) descriptor += $" address={address}";
            }

            return (true, SyntheticHookRuntime.Create(method.ReturnType, detour, tracker, method.Name, descriptor));
        }

        return (true, DefaultValueFactory.Create(method.ReturnType, this));
    }

    private object CreateInjectedObject(Type objectType, object?[] scopedObjects)
    {
        // Dalamud Create<T> is an IoC creation operation. Static [PluginService]
        // members (ECommons.Svc is a major real-world example) must be populated
        // even though they are not members of the newly-created instance.
        InjectPluginServices(objectType);

        object? instance = null;
        Exception? lastError = null;
        var constructors = objectType
            .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(c => !c.IsPrivate)
            .OrderBy(c => c.GetParameters().Length)
            .ToArray();

        foreach (var ctor in constructors)
        {
            var parameters = ctor.GetParameters();
            var ctorArgs = new object?[parameters.Length];
            var supported = true;
            for (var i = 0; i < parameters.Length; i++)
            {
                if (!TryResolve(parameters[i].ParameterType, scopedObjects, out var value))
                {
                    if (parameters[i].HasDefaultValue)
                        value = parameters[i].DefaultValue;
                    else
                    {
                        supported = false;
                        break;
                    }
                }
                ctorArgs[i] = value;
            }
            if (!supported)
                continue;
            try
            {
                instance = ctor.Invoke(ctorArgs);
                break;
            }
            catch (TargetInvocationException ex)
            {
                lastError = ex.InnerException ?? ex;
            }
        }

        if (instance is null)
        {
            if (lastError is not null)
                throw lastError;
            throw new InvalidOperationException($"Rift could not construct IoC object {objectType.FullName}.");
        }

        InjectInstance(instance, scopedObjects);
        return instance;
    }

    private static object?[] ExtractScopedObjects(object?[] args)
    {
        if (args.Length == 0 || args[0] is null)
            return Array.Empty<object?>();
        if (args.Length == 1 && args[0] is object[] array)
            return array;
        return args;
    }

    private bool TryResolve(Type requestedType, object?[] scopedObjects, out object? value)
    {
        foreach (var candidate in scopedObjects)
        {
            if (candidate is not null && requestedType.IsInstanceOfType(candidate))
            {
                value = candidate;
                return true;
            }
        }
        value = GetService(requestedType);
        return value is not null;
    }

    private void InjectInstance(object target, object?[]? scopedObjects = null)
    {
        scopedObjects ??= Array.Empty<object?>();
        var type = target.GetType();
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        foreach (var property in type.GetProperties(flags))
        {
            if (!HasPluginServiceAttribute(property)) continue;
            var setter = property.GetSetMethod(true);
            if (setter is null) continue;
            if (!TryResolve(property.PropertyType, scopedObjects, out var value) || value is null) continue;
            setter.Invoke(target, new[] { value });
            tracker.ServiceInjection(property.PropertyType.FullName ?? property.PropertyType.Name,
                $"{type.FullName}.{property.Name}", "instance_property");
        }
        foreach (var field in type.GetFields(flags))
        {
            if (!HasPluginServiceAttribute(field) || field.IsInitOnly) continue;
            if (!TryResolve(field.FieldType, scopedObjects, out var value) || value is null) continue;
            field.SetValue(target, value);
            tracker.ServiceInjection(field.FieldType.FullName ?? field.FieldType.Name,
                $"{type.FullName}.{field.Name}", "instance_field");
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
