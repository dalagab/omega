// SPDX-License-Identifier: MIT-0
// TypeFormatter.cs — converts System.Type from MetadataLoadContext into a
// C#-emittable name. We don't use FullName because it returns the assembly
// qualified name for generic instantiations, which is not what we want.
// This format is the one the generator re-emits verbatim.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace DalaInspect;

public static class TypeFormatter
{
    public static string Format(Type t)
    {
        if (t is null) return "object";
        if (t.HasElementType)
        {
            var elem = t.GetElementType()!;
            if (t.IsArray)
            {
                var rank = t.GetArrayRank();
                var commas = rank == 1 ? string.Empty : new string(',', rank - 1);
                return $"{Format(elem)}[{commas}]";
            }
            if (t.IsByRef) return $"ref {Format(elem)}";
            if (t.IsPointer) return $"{Format(elem)}*";
        }
        if (t.IsGenericParameter)
        {
            return t.Name;
        }
        if (t.IsGenericType && !t.IsGenericTypeDefinition)
        {
            var def = t.GetGenericTypeDefinition();
            var args = t.GetGenericArguments();
            return $"{Format(def)}<{string.Join(", ", args.Select(Format))}>";
        }
        // For generic type definitions (e.g. `List<T>`), FullName is
        // `System.Collections.Generic.List\`1`. We just strip the
        // arity marker — the caller appends the generic argument list
        // separately when needed.
        var full = t.FullName ?? t.Name;
        var tick = full.IndexOf('`');
        if (tick > 0)
        {
            int i = tick + 1;
            while (i < full.Length && char.IsDigit(full[i])) i++;
            return full.Substring(0, tick) + full.Substring(i);
        }
        // For nested types, FullName uses '+'. We keep that — the generator
        // converts it to '.' for C#.
        return full;
    }
}
