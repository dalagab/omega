// SPDX-License-Identifier: MIT-0
// Inspector.cs — uses MetadataLoadContext to enumerate every public type
// in the real Dalamud.dll and convert it to a TypeShape manifest. We never
// execute any code from the real DLL; MetadataLoadContext only reads the
// assembly's metadata tables.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace DalaInspect;

public static class Inspector
{
    public static Manifest Inspect(string dalamudPath)
    {
        if (!File.Exists(dalamudPath))
        {
            throw new FileNotFoundException($"real Dalamud.dll not found at {dalamudPath}");
        }

        // Confirm the assembly version we're targeting matches what the
        // shim's AssemblyVersion will be. The version is the anchor of
        // .NET's loose-binding reference resolution.
        var assemblyVersion = ReadAssemblyVersion(dalamudPath);
        Console.WriteLine($"source assembly version: {assemblyVersion}");

        // Build a resolver that knows about every DLL sitting next to
        // the real Dalamud.dll (its dependencies) plus the runtime
        // ref assemblies for everything else.
        var dir = Path.GetDirectoryName(dalamudPath)!;
        var directoryDlls = Directory.GetFiles(dir, "*.dll");
        var refs = new List<string>(directoryDlls);
        refs.Add(typeof(object).Assembly.Location);
        foreach (var extra in EnumerateRefAssemblies())
        {
            refs.Add(extra);
        }

        var resolver = new PathAssemblyResolver(refs);
        using var mlc = new MetadataLoadContext(resolver, coreAssemblyName: "System.Runtime");
        var asm = mlc.LoadFromAssemblyPath(dalamudPath);

        var manifest = new Manifest
        {
            SourceAssembly = Path.GetFileName(dalamudPath),
            AssemblyVersion = assemblyVersion,
        };

        foreach (var t in asm.GetTypes())
        {
            try
            {
                if (!IsInteresting(t)) continue;
                var shape = ShapeOf(t);
                if (shape is not null) manifest.Types.Add(shape);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[warn] failed to shape {t.FullName}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // Deterministic order: namespace, then declaring chain, then name.
        manifest.Types.Sort((a, b) =>
        {
            var c = string.CompareOrdinal(a.Namespace, b.Namespace);
            if (c != 0) return c;
            c = string.CompareOrdinal(a.DeclaringType ?? string.Empty, b.DeclaringType ?? string.Empty);
            if (c != 0) return c;
            return string.CompareOrdinal(a.Name, b.Name);
        });

        return manifest;
    }

    private static IEnumerable<string> EnumerateRefAssemblies()
    {
        // Find the dotnet install root by walking up from
        // typeof(object).Assembly.Location. On a typical install:
        //   typeof(object).Assembly.Location = C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.0\System.Private.CoreLib.dll
        // and the ref assemblies live at
        //   C:\Program Files\dotnet\packs\Microsoft.NETCore.App.Ref\<ver>\ref\netX.Y\*.dll
        var coreLib = typeof(object).Assembly.Location;
        var dir = new DirectoryInfo(Path.GetDirectoryName(coreLib)!);
        DirectoryInfo? dotnetRoot = null;
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "dotnet.exe")))
            {
                dotnetRoot = dir;
                break;
            }
            dir = dir.Parent;
        }
        if (dotnetRoot is null) yield break;
        var refDir = Path.Combine(dotnetRoot.FullName, "packs", "Microsoft.NETCore.App.Ref");
        if (!Directory.Exists(refDir)) yield break;
        foreach (var v in Directory.GetDirectories(refDir).OrderByDescending(d => d))
        {
            var refTfm = Path.Combine(v, "ref");
            if (!Directory.Exists(refTfm)) continue;
            foreach (var tfm in Directory.GetDirectories(refTfm))
            {
                foreach (var f in Directory.GetFiles(tfm, "*.dll"))
                {
                    yield return f;
                }
                yield break;
            }
        }
    }

    private static string ReadAssemblyVersion(string path)
    {
        using var fs = File.OpenRead(path);
        using var pe = new PEReader(fs);
        var md = pe.GetMetadataReader();
        var ver = md.GetAssemblyDefinition().Version;
        return $"{ver.Major}.{ver.Minor}.{ver.Build}.{ver.Revision}";
    }

    private static bool IsInteresting(Type t)
    {
        if (t.FullName == "<Module>") return false;
        if (IsCompilerGenerated(t)) return false;
        // Compiler-generated fixed-buffer types use angle brackets in
        // the name (e.g. `<Signature>e__FixedBuffer`); the shim doesn't
        // need them.
        if (t.Name.Contains('<') || t.Name.Contains('>')) return false;
        // We want every public type that's reachable from outside the
        // assembly, including nested types. Skip compiler-generated
        // helpers and the usual noise.
        if (!IsPubliclyVisible(t)) return false;
        return true;
    }

    private static bool IsPubliclyVisible(Type t)
    {
        if (t.IsPublic) return true;
        if (t.IsNestedPublic) return true;
        if (t.IsNestedFamily) return true;       // protected -> visible to derived
        if (t.IsNestedFamORAssem) return true;
        if (t.IsNestedAssembly) return false;     // internal nested -> not visible
        return false;
    }

    private static bool IsCompilerGenerated(MemberInfo mi)
    {
        return mi.CustomAttributes.Any(a => a.AttributeType.FullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute");
    }

    private static TypeShape? ShapeOf(Type t)
    {
        var shape = new TypeShape
        {
            Namespace = t.Namespace ?? string.Empty,
            Name = t.Name,
            DeclaringType = t.DeclaringType is null ? null : TypeFormatter.Format(t.DeclaringType),
            FullName = t.FullName ?? t.Name,
            Kind = KindOf(t),
            IsPublic = t.IsPublic || t.IsNestedPublic || t.IsNestedFamily,
            IsAbstract = t.IsAbstract,
            IsSealed = t.IsSealed,
            IsNested = t.IsNested,
        };

        if (shape.Kind == "enum")
        {
            shape.EnumUnderlyingType = TypeFormatter.Format(Enum.GetUnderlyingType(t));
            foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                if (f.IsLiteral && !f.IsPrivate)
                {
                    var v = f.GetRawConstantValue();
                    shape.EnumValues.Add(new EnumValue
                    {
                        Name = f.Name,
                        Value = v is null ? 0 : Convert.ToInt64(v),
                    });
                }
            }
            return shape;
        }

        if (t.IsGenericTypeDefinition)
        {
            foreach (var gp in t.GetGenericArguments())
            {
                shape.GenericParams.Add(gp.Name);
                shape.GenericConstraints.Add(BuildConstraint(gp));
            }
        }

        if (t.BaseType is not null && t.BaseType != typeof(object))
        {
            shape.BaseType = TypeFormatter.Format(t.BaseType);
        }

        foreach (var iface in t.GetInterfaces())
        {
            if (iface.FullName is null) continue;
            shape.Interfaces.Add(TypeFormatter.Format(iface));
        }

        var members = EnumerateMembers(t);
        shape.Members.AddRange(members);

        return shape;
    }

    private static GenericConstraint BuildConstraint(Type gp)
    {
        var c = new GenericConstraint { Name = gp.Name };
        var attrs = gp.GenericParameterAttributes;
        if ((attrs & GenericParameterAttributes.ReferenceTypeConstraint) != 0) c.Attributes.Add("class");
        if ((attrs & GenericParameterAttributes.NotNullableValueTypeConstraint) != 0) c.Attributes.Add("notnull");
        if ((attrs & GenericParameterAttributes.DefaultConstructorConstraint) != 0) c.Attributes.Add("new()");
        if ((attrs & GenericParameterAttributes.Contravariant) != 0) c.Attributes.Add("in");
        if ((attrs & GenericParameterAttributes.Covariant) != 0) c.Attributes.Add("out");
        if ((attrs & GenericParameterAttributes.SpecialConstraintMask) == 0 && c.Attributes.Count == 0)
        {
            c.Attributes.Add("none");
        }
        if (c.Attributes.Contains("none"))
        {
            // already marked; constraint types will be empty
        }
        foreach (var t in gp.GetGenericParameterConstraints())
        {
            if (t == typeof(object) || t == typeof(ValueType)) continue;
            c.ConstraintTypes.Add(TypeFormatter.Format(t));
        }
        return c;
    }

    private static IEnumerable<MemberShape> EnumerateMembers(Type t)
    {
        var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        if (t.IsClass || (t.IsValueType && !t.IsEnum))
        {
            foreach (var ctor in t.GetConstructors(flags))
            {
                if (ctor.IsPrivate || ctor.IsAssembly || ctor.IsFamilyAndAssembly) continue;
                if (IsCompilerGenerated(ctor)) continue;
                var m = new MemberShape
                {
                    Kind = "ctor",
                    Name = ".ctor",
                    IsPublic = ctor.IsPublic,
                    IsStatic = ctor.IsStatic,
                    IsAbstract = ctor.IsAbstract,
                    IsVirtual = ctor.IsVirtual,
                    IsFinal = ctor.IsFinal,
                };
                foreach (var p in ctor.GetParameters())
                {
                    m.Parameters.Add(BuildParam(p));
                }
                yield return m;
            }
        }

        foreach (var mi in t.GetMethods(flags))
        {
            if (mi.IsSpecialName) continue;
            if (mi.IsPrivate || mi.IsAssembly || mi.IsFamilyAndAssembly) continue;
            if (IsCompilerGenerated(mi)) continue;

            var m = new MemberShape
            {
                Kind = "method",
                Name = mi.Name,
                ReturnType = TypeFormatter.Format(mi.ReturnType),
                IsPublic = mi.IsPublic,
                IsStatic = mi.IsStatic,
                IsAbstract = mi.IsAbstract,
                IsVirtual = mi.IsVirtual,
                IsFinal = mi.IsFinal,
                IsNewSlot = (mi.Attributes & MethodAttributes.NewSlot) != 0,
            };
            if (mi.IsGenericMethodDefinition)
            {
                foreach (var gp in mi.GetGenericArguments())
                {
                    m.GenericParams.Add(gp.Name);
                    m.GenericConstraints.Add(BuildConstraint(gp));
                }
            }
            foreach (var p in mi.GetParameters())
            {
                m.Parameters.Add(BuildParam(p));
            }
            yield return m;
        }

        foreach (var pi in t.GetProperties(flags))
        {
            if (IsCompilerGenerated(pi)) continue;
            var getter = pi.GetMethod;
            var setter = pi.SetMethod;
            if (getter is null && setter is null) continue;
            if ((getter is null || !IsPubliclyVisible(getter)) && (setter is null || !IsPubliclyVisible(setter)))
            {
                continue;
            }
            var m = new MemberShape
            {
                Kind = "property",
                Name = pi.Name,
                PropertyType = TypeFormatter.Format(pi.PropertyType),
                IsPublic = (getter?.IsPublic ?? false) || (setter?.IsPublic ?? false),
                IsStatic = (getter?.IsStatic ?? false) || (setter?.IsStatic ?? false),
                IsAbstract = (getter?.IsAbstract ?? false) || (setter?.IsAbstract ?? false),
                IsVirtual = (getter?.IsVirtual ?? false) || (setter?.IsVirtual ?? false),
                IsFinal = (getter?.IsFinal ?? false) || (setter?.IsFinal ?? false),
                // Preserve the externally visible accessor contract, not merely
                // whether metadata contains an accessor. A private setter must
                // not turn into a public setter in the shim.
                PropertyCanRead = getter is not null && IsPubliclyVisible(getter),
                PropertyCanWrite = setter is not null && IsPubliclyVisible(setter),
            };
            foreach (var p in pi.GetIndexParameters())
            {
                m.Parameters.Add(BuildParam(p));
            }
            yield return m;
        }

        foreach (var fi in t.GetFields(flags))
        {
            if (fi.IsPrivate || fi.IsAssembly || fi.IsFamilyAndAssembly) continue;
            if (IsCompilerGenerated(fi)) continue;
            yield return new MemberShape
            {
                Kind = "field",
                Name = fi.Name,
                FieldType = TypeFormatter.Format(fi.FieldType),
                IsPublic = fi.IsPublic,
                IsStatic = fi.IsStatic,
            };
        }

        foreach (var ei in t.GetEvents(flags))
        {
            var add = ei.GetAddMethod(true);
            var remove = ei.GetRemoveMethod(true);
            if (add is null && remove is null) continue;
            if ((add is null || !IsPubliclyVisible(add)) && (remove is null || !IsPubliclyVisible(remove)))
            {
                continue;
            }
            yield return new MemberShape
            {
                Kind = "event",
                Name = ei.Name,
                EventType = TypeFormatter.Format(ei.EventHandlerType!),
                IsPublic = (add?.IsPublic ?? false) || (remove?.IsPublic ?? false),
                IsStatic = (add?.IsStatic ?? false) || (remove?.IsStatic ?? false),
                IsAbstract = (add?.IsAbstract ?? false) || (remove?.IsAbstract ?? false),
                IsVirtual = (add?.IsVirtual ?? false) || (remove?.IsVirtual ?? false),
            };
        }
    }

    private static bool IsPubliclyVisible(MethodBase mi)
    {
        if (mi.IsPublic) return true;
        if (mi.IsFamily) return true;
        if (mi.IsFamilyOrAssembly) return true;
        return false;
    }

    private static ParamShape BuildParam(ParameterInfo p)
    {
        var t = p.ParameterType;
        var isByRef = t.IsByRef;
        if (isByRef) t = t.GetElementType()!;
        var ps = new ParamShape
        {
            Name = string.IsNullOrEmpty(p.Name) ? "arg" : p.Name,
            Type = TypeFormatter.Format(t),
            IsByRef = isByRef,
            IsParams = p.GetCustomAttributesData().Any(a => a.AttributeType.FullName == "System.ParamArrayAttribute"),
            HasDefault = p.HasDefaultValue,
        };
        if (p.HasDefaultValue)
        {
            var raw = p.RawDefaultValue;
            // Use invariant culture so float defaults like 0.05 don't
            // get turned into 0,05 by a German locale.
            ps.DefaultValue = raw switch
            {
                null => null,
                IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
                _ => raw.ToString(),
            };
        }
        if (p.GetCustomAttributesData().Any(a => a.AttributeType.FullName == "System.Runtime.CompilerServices.IsReadOnlyAttribute"))
        {
            ps.IsIn = true;
        }
        return ps;
    }

    private static string KindOf(Type t)
    {
        if (t.IsEnum) return "enum";
        if (t.IsInterface) return "interface";
        if (IsDelegate(t)) return "delegate";
        if (t.IsValueType) return "struct";
        return "class";
    }

    private static bool IsDelegate(Type t)
    {
        return t.BaseType is not null && t.BaseType.FullName == "System.MulticastDelegate";
    }
}
