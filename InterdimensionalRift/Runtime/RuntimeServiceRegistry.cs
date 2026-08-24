using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.ExceptionServices;
using InterdimensionalRift.Host;
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
    private readonly ConcurrentDictionary<(Type ServiceType, string EventName), List<RegisteredDelegate>> eventHandlers = new();
    private readonly ConcurrentDictionary<string, CommandRegistration> commandHandlers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, IpcEndpointState> ipcEndpoints = new(StringComparer.Ordinal);
    private readonly List<ScheduledCallbackRegistration> scheduledCallbacks = new();
    private readonly object scheduledCallbacksLock = new();
    private readonly AsyncLocal<int?> frameworkInvocationThreadId = new();
    private int syntheticTick;
    private readonly ConcurrentDictionary<string, object> sharedData = new(StringComparer.Ordinal);
    private long registrationSequence;
    private readonly string internalName;
    private readonly FileInfo assemblyLocation;
    private readonly DirectoryInfo configDirectory;
    private readonly FileInfo configFile;
    private readonly Version assemblyVersion;
    private readonly SyntheticGameDataFixtureStore gameDataFixtures;
    private object? sandboxPluginConfiguration;

    public RuntimeServiceRegistry(AccessTracker tracker, string internalName, string pluginPath)
    {
        this.tracker = tracker;
        this.internalName = internalName;
        assemblyLocation = new FileInfo(pluginPath);
        configDirectory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "rift-config"));
        configFile = new FileInfo(Path.Combine(configDirectory.FullName, $"{internalName}.json"));
        SeedConfigurationDirectory();
        gameDataFixtures = new SyntheticGameDataFixtureStore(tracker);
        assemblyVersion = AssemblyName.GetAssemblyName(pluginPath).Version ?? new Version(0, 0, 0, 0);
        SyntheticNativeGameStateRuntime.EnsureInstalled(tracker);
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

    private void SeedConfigurationDirectory()
    {
        var source = Environment.GetEnvironmentVariable("RIFT_SEED_CONFIG_DIR");
        if (string.IsNullOrWhiteSpace(source))
            return;

        var sourceDirectory = new DirectoryInfo(Path.GetFullPath(source));
        if (!sourceDirectory.Exists || sourceDirectory.LinkTarget is not null)
            throw new InvalidOperationException("Rift seed configuration directory is unavailable or resolves through a link.");

        var filesCopied = 0;
        long bytesCopied = 0;
        foreach (var sourceFile in sourceDirectory.EnumerateFiles("*", SearchOption.AllDirectories))
        {
            if (sourceFile.LinkTarget is not null)
                throw new InvalidOperationException($"Rift seed configuration file resolves through a link: {sourceFile.FullName}");

            var relative = Path.GetRelativePath(sourceDirectory.FullName, sourceFile.FullName);
            if (Path.IsPathRooted(relative) || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(part => part == ".."))
                throw new InvalidOperationException($"Rift seed configuration file escapes its root: {sourceFile.FullName}");

            if (sourceFile.Length > 64 * 1024 * 1024 || bytesCopied + sourceFile.Length > 128 * 1024 * 1024)
                throw new InvalidOperationException("Rift seed configuration exceeds the 128 MiB bounded input limit.");

            var destination = Path.Combine(configDirectory.FullName, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(sourceFile.FullName, destination, overwrite: false);
            filesCopied++;
            bytesCopied += sourceFile.Length;
        }

        tracker.ServiceTouch("RiftSeededConfiguration", "copy", parameters: new Dictionary<string, string?>
        {
            ["files_copied"] = filesCopied.ToString(),
            ["bytes_copied"] = bytesCopied.ToString(),
            ["source_tree_sha256"] = Environment.GetEnvironmentVariable("RIFT_SEED_CONFIG_TREE_SHA256"),
            ["source_writable"] = "false",
            ["plugin_config_writable"] = "true",
        });
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
                var actual = ex.InnerException ?? ex;
                tracker.Lifecycle("constructor", "threw", pluginType.FullName, actual);
                ExceptionDispatchInfo.Capture(actual).Throw();
                throw; // unreachable
            }
        }

        throw new InvalidOperationException($"No constructible constructor was found for {pluginType.FullName}.");
    }

    internal object? Invoke(Type serviceType, MethodInfo method, object?[]? args, string? instanceTag = null)
    {
        args ??= Array.Empty<object?>();
        var serviceName = serviceType.Name;
        BootstrapTrace.Record($"service.invoke service={serviceName} method={method.Name}");

        if (method.IsSpecialName && (method.Name.StartsWith("add_", StringComparison.Ordinal) || method.Name.StartsWith("remove_", StringComparison.Ordinal)))
        {
            var add = method.Name.StartsWith("add_", StringComparison.Ordinal);
            var eventName = method.Name.Substring(add ? 4 : 7);
            if (args.FirstOrDefault() is Delegate handler)
                ChangeEventHandler(serviceType, eventName, handler, add);
            tracker.ServiceTouch(serviceName, method.Name);
            return null;
        }

        if (serviceType.FullName?.StartsWith("Dalamud.Plugin.Ipc.ICallGate", StringComparison.Ordinal) == true && instanceTag is not null)
        {
            var special = InvokeIpcEndpoint(serviceType, method, args, instanceTag);
            if (special.Handled)
                return special.Value;
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

        if (serviceName == "ICommandManager")
        {
            var special = InvokeCommandManager(method, args);
            if (special.Handled)
                return special.Value;
        }

        if (serviceName == "IFramework")
        {
            var special = InvokeFramework(method, args);
            if (special.Handled)
                return special.Value;
        }

        if (serviceName == "IPluginLog")
        {
            var message = ExtractLogMessage(args);
            var exception = args.OfType<Exception>().FirstOrDefault();
            BootstrapTrace.Record($"plugin.log level={method.Name} message={message} exception={exception?.GetType().Name}:{exception?.Message}");
            if (exception?.StackTrace is { Length: > 0 } stackTrace)
                BootstrapTrace.Record($"plugin.log_stack {stackTrace.Replace(Environment.NewLine, " | ", StringComparison.Ordinal)}");
            tracker.Log(method.Name, message);
            return DefaultValueFactory.Create(method.ReturnType, this);
        }

        tracker.ServiceTouch(serviceName, method.Name, parameters: SnapshotParameters(method, args));
        return DefaultValueFactory.Create(method.ReturnType, this);
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
                sandboxPluginConfiguration ??= SandboxConfigurationFactory.CreateForCallingPlugin();
                return (true, sandboxPluginConfiguration);
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
            case "GetIpcSubscriber" when method.IsGenericMethod && args.Length >= 1 && args[0] is string subscriberChannel:
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name,
                    parameters: new Dictionary<string, string?> { ["channel"] = subscriberChannel });
                return (true, GetOrCreateIpcEndpoint(method.ReturnType, subscriberChannel, "subscriber"));
            case "GetIpcProvider" when method.IsGenericMethod && args.Length >= 1 && args[0] is string providerChannel:
                tracker.ServiceTouch("IDalamudPluginInterface", method.Name,
                    parameters: new Dictionary<string, string?> { ["channel"] = providerChannel });
                return (true, GetOrCreateIpcEndpoint(method.ReturnType, providerChannel, "provider"));
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

        var requestedPath = args.OfType<string>().FirstOrDefault();
        if (method.Name == "FileExists")
            return (true, gameDataFixtures.Contains(requestedPath));

        if (method.Name == "GetFile" && !method.IsGenericMethod &&
            gameDataFixtures.TryCreateFileResource(requestedPath, out var fixture) &&
            fixture is not null && method.ReturnType.IsInstanceOfType(fixture))
            return (true, fixture);

        if (method.Name == "GetFileAsync" && method.ReturnType.IsGenericType &&
            method.ReturnType.GetGenericTypeDefinition() == typeof(Task<>) &&
            gameDataFixtures.TryCreateFileResource(requestedPath, out fixture) &&
            fixture is not null && method.ReturnType.GetGenericArguments()[0].IsInstanceOfType(fixture))
        {
            var complete = typeof(Task).GetMethod(nameof(Task.FromResult))!
                .MakeGenericMethod(method.ReturnType.GetGenericArguments()[0])
                .Invoke(null, new object?[] { fixture });
            return (true, complete);
        }

        // GetFile/GetFileAsync and direct GameData/Excel access remain unavailable
        // unless an exact staged synthetic fixture was supplied. Record this
        // separately from a plugin exception so coverage gaps remain obvious.
        if (method.Name is "GetFile" or "GetFileAsync" or "get_GameData" or "get_Excel")
        {
            tracker.Record(RuntimeObservationKind.ServiceAccess, "IDataManager", method.Name, "synthetic_unavailable",
                message: "Rift does not mount game data in this profile",
                parameters: SnapshotParameters(method, args));
        }
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

    private (bool Handled, object? Value) InvokeCommandManager(MethodInfo method, object?[] args)
    {
        tracker.ServiceTouch("ICommandManager", method.Name, parameters: SnapshotParameters(method, args));

        if (method.Name == "AddHandler" && args.Length >= 2 && args[0] is string command && args[1] is not null)
        {
            var info = args[1];
            var handler = info.GetType().GetProperty("Handler", BindingFlags.Public | BindingFlags.Instance)?.GetValue(info) as Delegate;
            if (handler is null)
                return (true, false);

            var registration = new CommandRegistration
            {
                Id = NextRegistrationId("command"),
                Command = command,
                Handler = handler,
            };
            commandHandlers[command] = registration;
            tracker.Registration("command", "ICommandManager", command, "registered", HandlerTarget(handler),
                new Dictionary<string, string?> { ["registration_id"] = registration.Id, ["synthetic_arguments"] = "empty" });
            return (true, true);
        }

        if (method.Name == "RemoveHandler" && args.Length >= 1 && args[0] is string removeCommand)
        {
            var removed = commandHandlers.TryRemove(removeCommand, out var registration);
            tracker.Registration("command", "ICommandManager", removeCommand, removed ? "unregistered" : "not_found",
                registration is null ? null : HandlerTarget(registration.Handler),
                new Dictionary<string, string?> { ["registration_id"] = registration?.Id });
            return (true, removed);
        }

        if (method.Name == "ProcessCommand")
            return (true, false);

        return (false, null);
    }

    private (bool Handled, object? Value) InvokeFramework(MethodInfo method, object?[] args)
    {
        tracker.ServiceTouch("IFramework", method.Name, parameters: SnapshotParameters(method, args));

        if (method.Name == "GetTaskFactory")
            return (true, Task.Factory);

        // Startup DelayTicks remains a completed neutral task so constructor timing is
        // not silently changed. Calls are still observed; explicit synthetic tick
        // fidelity is provided for retained Run/RunOnFrameworkThread/RunOnTick work.
        if (method.Name == "DelayTicks")
            return (true, Task.CompletedTask);

        if (method.Name is "Run" or "RunOnFrameworkThread" or "RunOnTick")
        {
            var callback = args.OfType<Delegate>().FirstOrDefault();
            if (callback is not null)
            {
                var parameters = SnapshotParameters(method, args);
                var delayTicks = ParseDelayTicks(parameters);
                var wallDelay = args.OfType<TimeSpan>().FirstOrDefault(x => x > TimeSpan.Zero);
                var cancelled = args.OfType<CancellationToken>().Any(x => x.IsCancellationRequested);
                var reason = cancelled
                    ? "scheduled_callback_cancelled"
                    : wallDelay > TimeSpan.Zero
                        ? "timespan_delay_not_modeled"
                        : null;
                var dueTick = reason is null
                    ? Math.Max(1, Volatile.Read(ref syntheticTick) + Math.Max(1, delayTicks))
                    : int.MaxValue;
                var registration = new ScheduledCallbackRegistration
                {
                    Id = NextRegistrationId("framework-callback"),
                    Operation = method.Name,
                    Callback = callback,
                    Parameters = parameters,
                    DueTick = dueTick,
                    UnexercisedReason = reason,
                };
                lock (scheduledCallbacksLock) scheduledCallbacks.Add(registration);
                tracker.Registration("framework_callback", "IFramework", method.Name, "registered", HandlerTarget(callback),
                    new Dictionary<string, string?>(parameters, StringComparer.Ordinal)
                    {
                        ["registration_id"] = registration.Id,
                        ["execution_semantics"] = "deferred_to_synthetic_framework_tick",
                        ["due_tick"] = dueTick.ToString(),
                    });
            }

            return (true, DefaultValueFactory.Create(method.ReturnType, this));
        }

        if (method.Name == "get_IsInFrameworkUpdateThread")
            return (true, frameworkInvocationThreadId.Value == Environment.CurrentManagedThreadId);
        if (method.Name == "get_IsFrameworkUnloading")
            return (true, false);
        if (method.Name is "get_LastUpdate" or "get_LastUpdateUTC")
            return (true, DateTime.UtcNow);
        if (method.Name == "get_UpdateDelta")
            return (true, TimeSpan.Zero);

        return (false, null);
    }

    private static int ParseDelayTicks(IReadOnlyDictionary<string, string?> parameters)
    {
        foreach (var (key, value) in parameters)
        {
            if (!key.Contains("tick", StringComparison.OrdinalIgnoreCase))
                continue;
            if (int.TryParse(value, out var parsed) && parsed >= 0)
                return parsed;
        }
        return 0;
    }

    internal IDisposable EnterSyntheticFrameworkTick(int tick)
    {
        Volatile.Write(ref syntheticTick, tick);
        return new RegistryScope(() => { });
    }

    internal IDisposable EnterFrameworkInvocation()
    {
        var previous = frameworkInvocationThreadId.Value;
        frameworkInvocationThreadId.Value = Environment.CurrentManagedThreadId;
        return new RegistryScope(() => frameworkInvocationThreadId.Value = previous);
    }

    private object GetOrCreateIpcEndpoint(Type interfaceType, string channel, string direction)
    {
        var key = $"{direction}|{channel}|{interfaceType.AssemblyQualifiedName}";
        return ipcEndpoints.GetOrAdd(key, _ =>
        {
            var proxy = ConstraintPreservingProxyFactory.Create(interfaceType, this, key);
            var endpointId = NextRegistrationId("ipc-endpoint");
            tracker.Registration("ipc_endpoint", "IDalamudPluginInterface", channel, "created", interfaceType.FullName,
                new Dictionary<string, string?>
                {
                    ["registration_id"] = endpointId,
                    ["direction"] = direction,
                    ["endpoint_type"] = interfaceType.FullName,
                });
            return new IpcEndpointState
            {
                Id = endpointId,
                Key = key,
                Channel = channel,
                Direction = direction,
                InterfaceType = interfaceType,
                Proxy = proxy,
            };
        }).Proxy;
    }

    private (bool Handled, object? Value) InvokeIpcEndpoint(Type serviceType, MethodInfo method, object?[] args, string key)
    {
        if (!ipcEndpoints.TryGetValue(key, out var endpoint))
            return (false, null);

        tracker.ServiceTouch(serviceType.Name, method.Name,
            new Dictionary<string, string?>(SnapshotParameters(method, args), StringComparer.Ordinal)
            {
                ["channel"] = endpoint.Channel,
                ["direction"] = endpoint.Direction,
            });

        if (method.Name == "Subscribe" && args.FirstOrDefault() is Delegate subscriber)
        {
            lock (endpoint.Subscribers)
            {
                var registration = new RegisteredDelegate { Id = NextRegistrationId("ipc-subscription"), Handler = subscriber };
                endpoint.Subscribers.Add(registration);
                tracker.Registration("ipc_subscription", serviceType.Name, endpoint.Channel, "registered", HandlerTarget(subscriber),
                    new Dictionary<string, string?> { ["registration_id"] = registration.Id, ["endpoint_id"] = endpoint.Id, ["direction"] = endpoint.Direction });
            }
            return (true, null);
        }

        if (method.Name == "Unsubscribe" && args.FirstOrDefault() is Delegate unsubscribe)
        {
            RegisteredDelegate? removed = null;
            lock (endpoint.Subscribers)
            {
                removed = endpoint.Subscribers.FirstOrDefault(x => x.Handler.Equals(unsubscribe));
                if (removed is not null) endpoint.Subscribers.Remove(removed);
            }
            tracker.Registration("ipc_subscription", serviceType.Name, endpoint.Channel,
                removed is null ? "not_found" : "unregistered", HandlerTarget(unsubscribe),
                new Dictionary<string, string?> { ["registration_id"] = removed?.Id, ["endpoint_id"] = endpoint.Id, ["direction"] = endpoint.Direction });
            return (true, null);
        }

        if ((method.Name == "RegisterAction" || method.Name == "RegisterFunc") && args.FirstOrDefault() is Delegate provider)
        {
            var registration = new RegisteredDelegate { Id = NextRegistrationId("ipc-provider"), Handler = provider };
            if (method.Name == "RegisterAction") endpoint.ProviderAction = registration;
            else endpoint.ProviderFunc = registration;
            tracker.Registration("ipc_provider", serviceType.Name, endpoint.Channel, "registered", HandlerTarget(provider),
                new Dictionary<string, string?>
                {
                    ["registration_id"] = registration.Id,
                    ["endpoint_id"] = endpoint.Id,
                    ["provider_kind"] = method.Name == "RegisterAction" ? "action" : "func",
                });
            return (true, null);
        }

        if (method.Name == "UnregisterAction")
        {
            var old = endpoint.ProviderAction;
            endpoint.ProviderAction = null;
            tracker.Registration("ipc_provider", serviceType.Name, endpoint.Channel, old is null ? "not_found" : "unregistered",
                old is null ? null : HandlerTarget(old.Handler), new Dictionary<string, string?> { ["registration_id"] = old?.Id, ["endpoint_id"] = endpoint.Id });
            return (true, null);
        }
        if (method.Name == "UnregisterFunc")
        {
            var old = endpoint.ProviderFunc;
            endpoint.ProviderFunc = null;
            tracker.Registration("ipc_provider", serviceType.Name, endpoint.Channel, old is null ? "not_found" : "unregistered",
                old is null ? null : HandlerTarget(old.Handler), new Dictionary<string, string?> { ["registration_id"] = old?.Id, ["endpoint_id"] = endpoint.Id });
            return (true, null);
        }

        if (method.Name == "get_HasAction")
            return (true, ipcEndpoints.Values.Any(x => x.Channel == endpoint.Channel && x.ProviderAction is not null));
        if (method.Name == "get_HasFunction")
            return (true, ipcEndpoints.Values.Any(x => x.Channel == endpoint.Channel && x.ProviderFunc is not null));
        if (method.Name == "get_SubscriptionCount")
        {
            var count = ipcEndpoints.Values.Where(x => x.Channel == endpoint.Channel).Sum(x =>
            {
                lock (x.Subscribers) return x.Subscribers.Count;
            });
            return (true, count);
        }

        // Plugin-initiated IPC calls have no external broker in Rift. They are
        // observed but return neutral defaults. Post-init exercise separately
        // invokes zero-argument registrations as synthetic inbound activity.
        if (method.Name.StartsWith("Invoke", StringComparison.Ordinal) || method.Name == "SendMessage")
            return (true, DefaultValueFactory.Create(method.ReturnType, this));

        return (true, DefaultValueFactory.Create(method.ReturnType, this));
    }

    internal IReadOnlyList<ExerciseCandidate> SnapshotExerciseCandidates(int frameworkTicks)
    {
        var result = new List<ExerciseCandidate>();

        foreach (var ((serviceType, eventName), registrations) in eventHandlers.OrderBy(k => k.Key.ServiceType.FullName).ThenBy(k => k.Key.EventName))
        {
            RegisteredDelegate[] snapshot;
            lock (registrations) snapshot = registrations.ToArray();
            foreach (var registration in snapshot)
            {
                var serviceName = serviceType.Name;
                var target = HandlerTarget(registration.Handler);
                var enabled = false;
                var reason = "event_not_modeled_by_post_init_safe_v1";
                var repeat = 1;
                object?[] arguments = Array.Empty<object?>();

                if (serviceName == "IFramework" && eventName == "Update")
                {
                    enabled = frameworkTicks > 0;
                    reason = enabled ? null : "framework_ticks_disabled";
                    repeat = Math.Max(0, frameworkTicks);
                    arguments = new[] { GetService(serviceType) };
                }
                else if (serviceType.FullName == "Dalamud.Interface.IUiBuilder" && eventName is "OpenConfigUi" or "OpenMainUi" or "ShowUi" or "HideUi")
                {
                    enabled = true;
                    reason = null;
                }
                else if (serviceType.FullName == "Dalamud.Interface.IUiBuilder" && eventName == "Draw")
                {
                    reason = "ui_render_callback_requires_rendering_profile";
                }

                result.Add(new ExerciseCandidate
                {
                    Id = registration.Id,
                    Kind = "event",
                    Component = serviceName,
                    Operation = eventName,
                    Target = target,
                    Handler = registration.Handler,
                    Arguments = arguments,
                    EnabledByProfile = enabled,
                    UnexercisedReason = reason,
                    Repeat = repeat,
                });
            }
        }

        foreach (var registration in commandHandlers.Values.OrderBy(x => x.Command, StringComparer.OrdinalIgnoreCase))
        {
            result.Add(new ExerciseCandidate
            {
                Id = registration.Id,
                Kind = "command",
                Component = "ICommandManager",
                Operation = registration.Command,
                Target = HandlerTarget(registration.Handler),
                Handler = registration.Handler,
                Arguments = new object?[] { registration.Command, string.Empty },
                EnabledByProfile = true,
                Repeat = 1,
            });
        }

        foreach (var endpoint in ipcEndpoints.Values.OrderBy(x => x.Channel, StringComparer.Ordinal).ThenBy(x => x.Direction, StringComparer.Ordinal))
        {
            RegisteredDelegate[] subscribers;
            lock (endpoint.Subscribers) subscribers = endpoint.Subscribers.ToArray();
            foreach (var registration in subscribers)
                result.Add(IpcCandidate(endpoint, registration, "subscriber"));
            if (endpoint.ProviderAction is not null)
                result.Add(IpcCandidate(endpoint, endpoint.ProviderAction, "provider_action"));
            if (endpoint.ProviderFunc is not null)
                result.Add(IpcCandidate(endpoint, endpoint.ProviderFunc, "provider_func"));
        }

        return result;
    }

    internal IReadOnlyList<ExerciseCandidate> SnapshotScheduledCallbacks()
    {
        ScheduledCallbackRegistration[] snapshot;
        lock (scheduledCallbacksLock) snapshot = scheduledCallbacks.ToArray();
        return snapshot.OrderBy(x => x.DueTick).ThenBy(x => x.Id, StringComparer.Ordinal).Select(ToScheduledCandidate).ToArray();
    }

    internal IReadOnlyList<ExerciseCandidate> DequeueScheduledCallbacksDue(int tick, int maxCount)
    {
        var selected = new List<ScheduledCallbackRegistration>();
        lock (scheduledCallbacksLock)
        {
            foreach (var registration in scheduledCallbacks
                         .Where(x => x.DueTick <= tick)
                         .OrderBy(x => x.DueTick)
                         .ThenBy(x => x.Id, StringComparer.Ordinal)
                         .Take(Math.Max(0, maxCount))
                         .ToArray())
            {
                scheduledCallbacks.Remove(registration);
                selected.Add(registration);
            }
        }
        return selected.Select(ToScheduledCandidate).ToArray();
    }

    private static ExerciseCandidate ToScheduledCandidate(ScheduledCallbackRegistration registration) => new()
    {
        Id = registration.Id,
        Kind = "framework_callback",
        Component = "IFramework",
        Operation = registration.Operation,
        Target = HandlerTarget(registration.Callback),
        Handler = registration.Callback,
        Arguments = Array.Empty<object?>(),
        EnabledByProfile = registration.UnexercisedReason is null,
        UnexercisedReason = registration.UnexercisedReason,
        Repeat = 1,
        DueTick = registration.DueTick,
        RequiresActiveRegistration = false,
    };

    internal bool IsRegistrationActive(ExerciseCandidate candidate)
    {
        if (!candidate.RequiresActiveRegistration)
            return true;

        if (candidate.Kind == "event")
        {
            foreach (var list in eventHandlers.Values)
            {
                lock (list)
                {
                    if (list.Any(x => x.Id == candidate.Id)) return true;
                }
            }
            return false;
        }
        if (candidate.Kind == "command")
            return commandHandlers.Values.Any(x => x.Id == candidate.Id);
        if (candidate.Kind == "ipc")
        {
            foreach (var endpoint in ipcEndpoints.Values)
            {
                lock (endpoint.Subscribers)
                {
                    if (endpoint.Subscribers.Any(x => x.Id == candidate.Id)) return true;
                }
                if (endpoint.ProviderAction?.Id == candidate.Id || endpoint.ProviderFunc?.Id == candidate.Id) return true;
            }
            return false;
        }
        return true;
    }

    private static ExerciseCandidate IpcCandidate(IpcEndpointState endpoint, RegisteredDelegate registration, string operation)
    {
        var parameters = registration.Handler.Method.GetParameters();
        var zeroArgument = parameters.Length == 0;
        return new ExerciseCandidate
        {
            Id = registration.Id,
            Kind = "ipc",
            Component = endpoint.InterfaceType.Name,
            Operation = $"{endpoint.Channel}:{operation}",
            Target = HandlerTarget(registration.Handler),
            Handler = registration.Handler,
            Arguments = Array.Empty<object?>(),
            EnabledByProfile = zeroArgument,
            UnexercisedReason = zeroArgument ? null : "ipc_callback_requires_external_arguments",
            Repeat = 1,
        };
    }

    private string NextRegistrationId(string prefix) => $"{prefix}-{Interlocked.Increment(ref registrationSequence):D4}";

    private static string HandlerTarget(Delegate handler) =>
        handler.Method.DeclaringType?.FullName + "." + handler.Method.Name;

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
        var list = eventHandlers.GetOrAdd((serviceType, eventName), _ => new List<RegisteredDelegate>());
        if (add)
        {
            var registration = new RegisteredDelegate { Id = NextRegistrationId("event"), Handler = handler };
            lock (list) list.Add(registration);
            tracker.Registration("event", serviceType.Name, eventName, "registered", HandlerTarget(handler),
                new Dictionary<string, string?> { ["registration_id"] = registration.Id });
            return;
        }

        RegisteredDelegate? removed = null;
        lock (list)
        {
            removed = list.FirstOrDefault(x => x.Handler.Equals(handler));
            if (removed is not null) list.Remove(removed);
        }
        tracker.Registration("event", serviceType.Name, eventName, removed is null ? "not_found" : "unregistered", HandlerTarget(handler),
            new Dictionary<string, string?> { ["registration_id"] = removed?.Id });
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
                TimeSpan ts => ts.ToString("c"),
                CancellationToken ct => ct.IsCancellationRequested ? "cancelled" : "active",
                _ when value.GetType().IsPrimitive || value is Enum => value.ToString(),
                _ => value.GetType().FullName,
            };
        }
        return result;
    }
    private sealed class RegistryScope : IDisposable
    {
        private Action? onDispose;
        public RegistryScope(Action onDispose) => this.onDispose = onDispose;
        public void Dispose() => Interlocked.Exchange(ref onDispose, null)?.Invoke();
    }

}
