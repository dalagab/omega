using System.Collections.Concurrent;
using System.Reflection;
using System.Reflection.Emit;

namespace InterdimensionalRift.Runtime;

/// <summary>
/// Reflection.Emit proxy used for Dalamud interfaces whose generic methods carry
/// constraints that DispatchProxy does not faithfully preserve in generated
/// return signatures (notably IGameInteropProvider where T : Delegate and the
/// return type is Hook&lt;T&gt;).
/// </summary>
public static class ConstraintPreservingProxyFactory
{
    private static readonly ConcurrentDictionary<Type, Func<RuntimeServiceRegistry, string?, object>> Factories = new();
    private static readonly ConcurrentDictionary<int, MethodInfo> Methods = new();
    private static int nextMethodId;
    private static int nextTypeId;

    public static object Create(Type interfaceType, RuntimeServiceRegistry registry, string? instanceTag = null)
    {
        if (!interfaceType.IsInterface)
            throw new ArgumentException("Constraint-preserving proxy target must be an interface.", nameof(interfaceType));
        return Factories.GetOrAdd(interfaceType, BuildFactory)(registry, instanceTag);
    }

    public static object? Invoke(RuntimeServiceRegistry registry, int methodId, string? instanceTag, Type[] genericArguments, object?[] arguments)
    {
        if (!Methods.TryGetValue(methodId, out var definition))
            throw new MissingMethodException($"Rift dynamic proxy method {methodId} is not registered.");

        var method = definition;
        if (definition.IsGenericMethodDefinition)
            method = definition.MakeGenericMethod(genericArguments);

        return registry.Invoke(definition.DeclaringType!, method, arguments, instanceTag);
    }

    private static Func<RuntimeServiceRegistry, string?, object> BuildFactory(Type interfaceType)
    {
        var typeName = $"RiftProxy_{Sanitize(interfaceType.FullName ?? interfaceType.Name)}_{Interlocked.Increment(ref nextTypeId)}";
        var assembly = AssemblyBuilder.DefineDynamicAssembly(
            new AssemblyName($"InterdimensionalRift.DynamicProxies.{nextTypeId}"),
            AssemblyBuilderAccess.RunAndCollect);
        var module = assembly.DefineDynamicModule("RiftDynamicProxies");
        ConfigureAccessChecks(assembly, module, interfaceType);
        var tb = module.DefineType(typeName,
            TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.Class);
        tb.AddInterfaceImplementation(interfaceType);

        var registryField = tb.DefineField("_registry", typeof(RuntimeServiceRegistry), FieldAttributes.Private | FieldAttributes.InitOnly);
        var instanceTagField = tb.DefineField("_instanceTag", typeof(string), FieldAttributes.Private | FieldAttributes.InitOnly);
        var ctor = tb.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, new[] { typeof(RuntimeServiceRegistry), typeof(string) });
        var cil = ctor.GetILGenerator();
        cil.Emit(OpCodes.Ldarg_0);
        cil.Emit(OpCodes.Call, typeof(object).GetConstructor(Type.EmptyTypes)!);
        cil.Emit(OpCodes.Ldarg_0);
        cil.Emit(OpCodes.Ldarg_1);
        cil.Emit(OpCodes.Stfld, registryField);
        cil.Emit(OpCodes.Ldarg_0);
        cil.Emit(OpCodes.Ldarg_2);
        cil.Emit(OpCodes.Stfld, instanceTagField);
        cil.Emit(OpCodes.Ret);

        foreach (var method in GetInterfaceMethods(interfaceType))
            ImplementMethod(tb, registryField, instanceTagField, method);

        var proxyType = tb.CreateType()!;
        var proxyCtor = proxyType.GetConstructor(new[] { typeof(RuntimeServiceRegistry), typeof(string) })!;
        return (registry, instanceTag) => proxyCtor.Invoke(new object?[] { registry, instanceTag });
    }

    private static void ConfigureAccessChecks(AssemblyBuilder assembly, ModuleBuilder module, Type interfaceType)
    {
        var targetAssemblies = EnumerateTypes(interfaceType)
            .Where(type => !type.IsVisible)
            .Select(type => type.Assembly.GetName().Name)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.Ordinal)
            .Cast<string>()
            .ToArray();
        if (targetAssemblies.Length == 0)
            return;

        var attribute = module.DefineType(
            "System.Runtime.CompilerServices.IgnoresAccessChecksToAttribute",
            TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.Class,
            typeof(Attribute));
        var field = attribute.DefineField("_assemblyName", typeof(string), FieldAttributes.Private | FieldAttributes.InitOnly);
        var constructor = attribute.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard, new[] { typeof(string) });
        var constructorIl = constructor.GetILGenerator();
        constructorIl.Emit(OpCodes.Ldarg_0);
        constructorIl.Emit(OpCodes.Call, typeof(Attribute).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null)!);
        constructorIl.Emit(OpCodes.Ldarg_0);
        constructorIl.Emit(OpCodes.Ldarg_1);
        constructorIl.Emit(OpCodes.Stfld, field);
        constructorIl.Emit(OpCodes.Ret);

        var getter = attribute.DefineMethod("get_AssemblyName", MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.HideBySig, typeof(string), Type.EmptyTypes);
        var getterIl = getter.GetILGenerator();
        getterIl.Emit(OpCodes.Ldarg_0);
        getterIl.Emit(OpCodes.Ldfld, field);
        getterIl.Emit(OpCodes.Ret);
        var property = attribute.DefineProperty("AssemblyName", PropertyAttributes.None, typeof(string), Type.EmptyTypes);
        property.SetGetMethod(getter);

        var attributeType = attribute.CreateType()!;
        var attributeConstructor = attributeType.GetConstructor(new[] { typeof(string) })!;
        foreach (var target in targetAssemblies)
            assembly.SetCustomAttribute(new CustomAttributeBuilder(attributeConstructor, new object[] { target }));
    }

    private static IEnumerable<Type> EnumerateTypes(Type type)
    {
        yield return type;
        if (type.HasElementType)
        {
            foreach (var element in EnumerateTypes(type.GetElementType()!))
                yield return element;
        }
        foreach (var argument in type.GetGenericArguments())
        {
            foreach (var nested in EnumerateTypes(argument))
                yield return nested;
        }
    }

    private static IEnumerable<MethodInfo> GetInterfaceMethods(Type interfaceType) =>
        interfaceType
            .GetInterfaces()
            .Append(interfaceType)
            .SelectMany(type => type.GetMethods())
            .GroupBy(method => (method.Module, method.MetadataToken))
            .Select(group => group.First());

    private static void ImplementMethod(TypeBuilder tb, FieldBuilder registryField, FieldBuilder instanceTagField, MethodInfo interfaceMethod)
    {
        var attributes = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.Final |
                         MethodAttributes.HideBySig | MethodAttributes.NewSlot;
        if (interfaceMethod.IsSpecialName)
            attributes |= MethodAttributes.SpecialName;

        var mb = tb.DefineMethod(interfaceMethod.Name, attributes, interfaceMethod.CallingConvention);
        var typeMap = new Dictionary<Type, Type>();
        GenericTypeParameterBuilder[] genericBuilders = Array.Empty<GenericTypeParameterBuilder>();

        if (interfaceMethod.IsGenericMethodDefinition)
        {
            var originalGeneric = interfaceMethod.GetGenericArguments();
            genericBuilders = mb.DefineGenericParameters(originalGeneric.Select(x => x.Name).ToArray());
            for (var i = 0; i < originalGeneric.Length; i++)
                typeMap[originalGeneric[i]] = genericBuilders[i];

            for (var i = 0; i < originalGeneric.Length; i++)
            {
                var source = originalGeneric[i];
                var target = genericBuilders[i];
                target.SetGenericParameterAttributes(source.GenericParameterAttributes);
                var constraints = source.GetGenericParameterConstraints().Select(t => Substitute(t, typeMap)).ToArray();
                var baseConstraint = constraints.FirstOrDefault(t => !t.IsInterface);
                if (baseConstraint is not null)
                    target.SetBaseTypeConstraint(baseConstraint);
                var interfaces = constraints.Where(t => t.IsInterface).ToArray();
                if (interfaces.Length > 0)
                    target.SetInterfaceConstraints(interfaces);
            }
        }

        var returnType = Substitute(interfaceMethod.ReturnType, typeMap);
        var parameterTypes = interfaceMethod.GetParameters().Select(p => Substitute(p.ParameterType, typeMap)).ToArray();
        mb.SetReturnType(returnType);
        mb.SetParameters(parameterTypes);

        var sourceParams = interfaceMethod.GetParameters();
        for (var i = 0; i < sourceParams.Length; i++)
            mb.DefineParameter(i + 1, sourceParams[i].Attributes, sourceParams[i].Name);

        var methodId = Interlocked.Increment(ref nextMethodId);
        Methods[methodId] = interfaceMethod;

        var il = mb.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldfld, registryField);
        il.Emit(OpCodes.Ldc_I4, methodId);
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Ldfld, instanceTagField);

        EmitGenericTypeArray(il, genericBuilders);
        EmitArgumentArray(il, parameterTypes);

        il.Emit(OpCodes.Call, typeof(ConstraintPreservingProxyFactory).GetMethod(nameof(Invoke))!);
        EmitReturn(il, returnType);

        tb.DefineMethodOverride(mb, interfaceMethod);
    }

    private static void EmitGenericTypeArray(ILGenerator il, GenericTypeParameterBuilder[] genericBuilders)
    {
        il.Emit(OpCodes.Ldc_I4, genericBuilders.Length);
        il.Emit(OpCodes.Newarr, typeof(Type));
        for (var i = 0; i < genericBuilders.Length; i++)
        {
            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldc_I4, i);
            il.Emit(OpCodes.Ldtoken, genericBuilders[i]);
            il.Emit(OpCodes.Call, typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle))!);
            il.Emit(OpCodes.Stelem_Ref);
        }
    }

    private static void EmitArgumentArray(ILGenerator il, Type[] parameterTypes)
    {
        il.Emit(OpCodes.Ldc_I4, parameterTypes.Length);
        il.Emit(OpCodes.Newarr, typeof(object));
        for (var i = 0; i < parameterTypes.Length; i++)
        {
            if (parameterTypes[i].IsByRef)
                throw new NotSupportedException("Constraint-preserving Rift proxy does not support by-ref parameters yet.");

            il.Emit(OpCodes.Dup);
            il.Emit(OpCodes.Ldc_I4, i);
            il.Emit(OpCodes.Ldarg, i + 1);
            if (parameterTypes[i].IsPointer)
            {
                il.Emit(OpCodes.Conv_I);
                il.Emit(OpCodes.Box, typeof(IntPtr));
            }
            else if (parameterTypes[i].IsValueType || parameterTypes[i].IsGenericParameter)
            {
                il.Emit(OpCodes.Box, parameterTypes[i]);
            }
            il.Emit(OpCodes.Stelem_Ref);
        }
    }

    private static void EmitReturn(ILGenerator il, Type returnType)
    {
        if (returnType == typeof(void))
        {
            il.Emit(OpCodes.Pop);
            il.Emit(OpCodes.Ret);
            return;
        }

        if (returnType.IsValueType || returnType.IsGenericParameter)
            il.Emit(OpCodes.Unbox_Any, returnType);
        else
            il.Emit(OpCodes.Castclass, returnType);
        il.Emit(OpCodes.Ret);
    }

    private static Type Substitute(Type type, IReadOnlyDictionary<Type, Type> map)
    {
        if (type.IsGenericParameter && map.TryGetValue(type, out var replacement))
            return replacement;
        if (type.IsByRef)
            return Substitute(type.GetElementType()!, map).MakeByRefType();
        if (type.IsPointer)
            return Substitute(type.GetElementType()!, map).MakePointerType();
        if (type.IsArray)
        {
            var element = Substitute(type.GetElementType()!, map);
            return type.GetArrayRank() == 1 ? element.MakeArrayType() : element.MakeArrayType(type.GetArrayRank());
        }
        if (type.IsGenericType)
            return type.GetGenericTypeDefinition().MakeGenericType(type.GetGenericArguments().Select(t => Substitute(t, map)).ToArray());
        return type;
    }

    private static string Sanitize(string value) => new(value.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_').ToArray());
}
