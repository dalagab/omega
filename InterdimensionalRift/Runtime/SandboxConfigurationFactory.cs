using System.Collections;
using System.Diagnostics;
using System.Reflection;
using InterdimensionalRift.Host;

namespace InterdimensionalRift.Runtime;

internal static class SandboxConfigurationFactory
{
    public static object? CreateForCallingPlugin()
    {
        var assemblies = new StackTrace(skipFrames: 1, fNeedFileInfo: false)
            .GetFrames()?
            .Select(frame => frame.GetMethod()?.DeclaringType?.Assembly)
            .Where(assembly => assembly is not null && assembly != typeof(SandboxConfigurationFactory).Assembly)
            .Distinct()
            .Cast<Assembly>()
            ?? [];
        foreach (var assembly in assemblies)
        {
            var configurationType = assembly.GetTypes().FirstOrDefault(type =>
                type.Name == "Configuration" &&
                type.GetInterfaces().Any(@interface => @interface.FullName == "Dalamud.Configuration.IPluginConfiguration") &&
                type.GetConstructor(Type.EmptyTypes) is not null);
            if (configurationType is null)
                continue;

            var configuration = Activator.CreateInstance(configurationType);
            if (configuration is not null)
            {
                SeedRequiredCollections(configuration);
                BootstrapTrace.Record($"configuration.seeded type={configurationType.FullName}");
            }
            return configuration;
        }

        BootstrapTrace.Record("configuration.unavailable");
        return null;
    }

    private static void SeedRequiredCollections(object configuration)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.Public;
        foreach (var member in configuration.GetType().GetMembers(flags))
        {
            var value = member switch
            {
                FieldInfo field => field.GetValue(configuration),
                PropertyInfo property when property.CanRead && property.CanWrite => property.GetValue(configuration),
                _ => null,
            };
            if (value is not IList list || list.Count != 0)
                continue;

            var itemType = value.GetType().IsGenericType ? value.GetType().GetGenericArguments()[0] : null;
            if (itemType is null || itemType.IsAbstract)
                continue;
            try
            {
                var item = Activator.CreateInstance(itemType, nonPublic: true);
                if (item is not null)
                    list.Add(item);
            }
            catch (Exception)
            {
            }
        }
    }
}
