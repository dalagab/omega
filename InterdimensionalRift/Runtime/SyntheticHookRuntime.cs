using System.Collections.Concurrent;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using InterdimensionalRift.Instrumentation;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Creates inert concrete subclasses of Dalamud.Hooking.Hook&lt;T&gt; without
/// installing or calling a native hook. Objects are allocated without invoking
/// the real Hook constructor/backend. All lifecycle calls are observations only.
/// </summary>
public static class SyntheticHookRuntime
{
    private sealed record State(AccessTracker Tracker, string Operation, string Descriptor, Delegate Original)
    {
        public bool Enabled;
    }

    private static readonly AssemblyBuilder Assembly = AssemblyBuilder.DefineDynamicAssembly(
        new AssemblyName("InterdimensionalRift.SyntheticHooks"), AssemblyBuilderAccess.Run);
    private static readonly ModuleBuilder Module = Assembly.DefineDynamicModule("RiftSyntheticHooks");
    private static readonly ConcurrentDictionary<Type, Type> HookTypes = new();
    private static readonly ConditionalWeakTable<object, State> States = new();
    private static int nextTypeId;

    public static object Create(Type closedHookType, Delegate detour, AccessTracker tracker, string operation, string descriptor)
    {
        if (!closedHookType.IsGenericType || closedHookType.GetGenericTypeDefinition().FullName != "Dalamud.Hooking.Hook`1")
            throw new ArgumentException($"Expected closed Dalamud Hook<T>, got {closedHookType}.", nameof(closedHookType));

        var delegateType = closedHookType.GetGenericArguments()[0];
        if (!typeof(Delegate).IsAssignableFrom(delegateType))
            throw new ArgumentException($"Hook delegate type is not a Delegate: {delegateType}.", nameof(closedHookType));

        var syntheticType = HookTypes.GetOrAdd(closedHookType, BuildSyntheticHookType);
        var hook = RuntimeHelpers.GetUninitializedObject(syntheticType);
        var original = CreateNoOpDelegate(delegateType);
        States.Add(hook, new State(tracker, operation, descriptor, original));
        tracker.Record(RuntimeObservationKind.Hook, "IGameInteropProvider", operation, "synthetic_created",
            message: descriptor,
            parameters: new Dictionary<string, string?>
            {
                ["delegate_type"] = delegateType.FullName,
                ["detour"] = detour.Method.DeclaringType?.FullName + "." + detour.Method.Name,
                ["native_patch"] = "false",
            });
        return hook;
    }

    public static Delegate GetOriginal(object hook)
    {
        var state = GetState(hook);
        state.Tracker.Record(RuntimeObservationKind.Hook, "synthetic_hook", "get_Original", "synthetic_noop",
            message: state.Descriptor);
        return state.Original;
    }

    public static bool GetIsEnabled(object hook) => GetState(hook).Enabled;

    public static string GetBackendName(object hook) => "InterdimensionalRift.synthetic-inert";

    public static void Enable(object hook)
    {
        var state = GetState(hook);
        state.Enabled = true;
        state.Tracker.Record(RuntimeObservationKind.Hook, "synthetic_hook", "Enable", "observed_inert",
            message: state.Descriptor,
            parameters: new Dictionary<string, string?> { ["native_patch"] = "false" });
    }

    public static void Disable(object hook)
    {
        var state = GetState(hook);
        state.Enabled = false;
        state.Tracker.Record(RuntimeObservationKind.Hook, "synthetic_hook", "Disable", "observed_inert",
            message: state.Descriptor,
            parameters: new Dictionary<string, string?> { ["native_patch"] = "false" });
    }

    public static void Dispose(object hook)
    {
        if (!States.TryGetValue(hook, out var state))
            return;
        state.Enabled = false;
        state.Tracker.Record(RuntimeObservationKind.Hook, "synthetic_hook", "Dispose", "observed_inert",
            message: state.Descriptor,
            parameters: new Dictionary<string, string?> { ["native_patch"] = "false" });
    }

    private static State GetState(object hook) =>
        States.TryGetValue(hook, out var state)
            ? state
            : throw new InvalidOperationException("Synthetic Rift hook state is unavailable.");

    private static Type BuildSyntheticHookType(Type closedHookType)
    {
        var delegateType = closedHookType.GetGenericArguments()[0];
        var tb = Module.DefineType(
            $"RiftSyntheticHook_{Sanitize(delegateType.FullName ?? delegateType.Name)}_{Interlocked.Increment(ref nextTypeId)}",
            TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.Class,
            closedHookType);

        // The base constructor is internal to Dalamud. This constructor is never
        // invoked; RuntimeHelpers.GetUninitializedObject allocates the inert
        // object directly. It exists only to make the emitted concrete type valid.
        var baseCtor = closedHookType.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic)
            .FirstOrDefault(c => c.GetParameters().Length == 1 && c.GetParameters()[0].ParameterType == typeof(IntPtr))
            ?? throw new MissingMethodException(closedHookType.FullName, ".ctor(IntPtr)");
        var ctor = tb.DefineConstructor(MethodAttributes.Private, CallingConventions.Standard, Type.EmptyTypes);
        var cil = ctor.GetILGenerator();
        cil.Emit(OpCodes.Ldarg_0);
        cil.Emit(OpCodes.Ldc_I4_0);
        cil.Emit(OpCodes.Conv_I);
        cil.Emit(OpCodes.Call, baseCtor);
        cil.Emit(OpCodes.Ret);

        OverrideGetter(tb, closedHookType, "get_Original", typeof(SyntheticHookRuntime).GetMethod(nameof(GetOriginal))!, delegateType);
        OverrideGetter(tb, closedHookType, "get_IsEnabled", typeof(SyntheticHookRuntime).GetMethod(nameof(GetIsEnabled))!, typeof(bool));
        OverrideGetter(tb, closedHookType, "get_BackendName", typeof(SyntheticHookRuntime).GetMethod(nameof(GetBackendName))!, typeof(string));
        OverrideVoid(tb, closedHookType, "Enable", typeof(SyntheticHookRuntime).GetMethod(nameof(Enable))!);
        OverrideVoid(tb, closedHookType, "Disable", typeof(SyntheticHookRuntime).GetMethod(nameof(Disable))!);
        OverrideVoid(tb, closedHookType, "Dispose", typeof(SyntheticHookRuntime).GetMethod(nameof(Dispose))!);

        return tb.CreateType()!;
    }

    private static void OverrideGetter(TypeBuilder tb, Type baseType, string methodName, MethodInfo helper, Type returnType)
    {
        var baseMethod = baseType.GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public)!;
        var mb = tb.DefineMethod(methodName,
            MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig | MethodAttributes.SpecialName,
            returnType, Type.EmptyTypes);
        var il = mb.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, helper);
        if (returnType != helper.ReturnType)
            il.Emit(OpCodes.Castclass, returnType);
        il.Emit(OpCodes.Ret);
        tb.DefineMethodOverride(mb, baseMethod);
    }

    private static void OverrideVoid(TypeBuilder tb, Type baseType, string methodName, MethodInfo helper)
    {
        var baseMethod = baseType.GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public)!;
        var mb = tb.DefineMethod(methodName,
            MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig,
            typeof(void), Type.EmptyTypes);
        var il = mb.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Call, helper);
        il.Emit(OpCodes.Ret);
        tb.DefineMethodOverride(mb, baseMethod);
    }

    private static Delegate CreateNoOpDelegate(Type delegateType)
    {
        var invoke = delegateType.GetMethod("Invoke") ?? throw new MissingMethodException(delegateType.FullName, "Invoke");
        var parameterTypes = invoke.GetParameters().Select(p => p.ParameterType).ToArray();
        var dm = new DynamicMethod(
            $"RiftNoOp_{Sanitize(delegateType.FullName ?? delegateType.Name)}",
            invoke.ReturnType,
            parameterTypes,
            typeof(SyntheticHookRuntime).Module,
            skipVisibility: true);
        var il = dm.GetILGenerator();
        EmitDefaultReturn(il, invoke.ReturnType);
        return dm.CreateDelegate(delegateType);
    }

    private static void EmitDefaultReturn(ILGenerator il, Type returnType)
    {
        if (returnType == typeof(void))
        {
            il.Emit(OpCodes.Ret);
            return;
        }

        if (returnType.IsPointer || returnType == typeof(IntPtr) || returnType == typeof(UIntPtr))
        {
            il.Emit(OpCodes.Ldc_I4_0);
            il.Emit(OpCodes.Conv_I);
            il.Emit(OpCodes.Ret);
            return;
        }

        if (!returnType.IsValueType)
        {
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ret);
            return;
        }

        var local = il.DeclareLocal(returnType);
        il.Emit(OpCodes.Ldloca_S, local);
        il.Emit(OpCodes.Initobj, returnType);
        il.Emit(OpCodes.Ldloc, local);
        il.Emit(OpCodes.Ret);
    }

    private static string Sanitize(string value) => new(value.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_').ToArray());
}
