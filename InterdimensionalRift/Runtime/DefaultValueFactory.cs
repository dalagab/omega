using System.Collections;
using System.Reflection;

namespace InterdimensionalRift.Runtime;

internal static class DefaultValueFactory
{
    public static object? Create(Type type, RuntimeServiceRegistry registry)
    {
        if (type == typeof(void)) return null;
        if (type == typeof(string)) return string.Empty;
        if (type == typeof(Task)) return Task.CompletedTask;
        if (type == typeof(ValueTask)) return ValueTask.CompletedTask;
        if (type == typeof(DirectoryInfo)) return new DirectoryInfo(Path.GetTempPath());
        if (type == typeof(FileInfo)) return new FileInfo(Path.Combine(Path.GetTempPath(), "rift-empty"));

        if (type.IsInterface)
        {
            if (TryCreateEmptyCollection(type, out var empty)) return empty;
            return registry.GetService(type);
        }

        if (type.IsArray)
            return Array.CreateInstance(type.GetElementType()!, 0);

        if (type.IsGenericType)
        {
            var def = type.GetGenericTypeDefinition();
            var args = type.GetGenericArguments();
            if (def == typeof(Task<>))
            {
                var value = Create(args[0], registry);
                return typeof(Task).GetMethod(nameof(Task.FromResult))!
                    .MakeGenericMethod(args[0])
                    .Invoke(null, new[] { value });
            }
            if (def == typeof(ValueTask<>))
            {
                var value = Create(args[0], registry);
                return Activator.CreateInstance(type, value);
            }
            if (def == typeof(Nullable<>)) return null;
        }

        if (type.IsValueType)
            return Activator.CreateInstance(type);

        // Concrete Dalamud classes often represent handles whose absence is a
        // valid sandbox result. Returning null is preferable to running their
        // implementation code outside the fake service layer.
        return null;
    }

    private static bool TryCreateEmptyCollection(Type type, out object? value)
    {
        value = null;
        if (!type.IsGenericType) return false;
        var def = type.GetGenericTypeDefinition();
        var args = type.GetGenericArguments();

        if (def == typeof(IEnumerable<>) ||
            def == typeof(IReadOnlyCollection<>) ||
            def == typeof(IReadOnlyList<>) ||
            def == typeof(ICollection<>) ||
            def == typeof(IList<>))
        {
            value = Array.CreateInstance(args[0], 0);
            return true;
        }

        if (def == typeof(IReadOnlyDictionary<,>) || def == typeof(IDictionary<,>))
        {
            value = Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(args));
            return true;
        }

        return false;
    }
}
