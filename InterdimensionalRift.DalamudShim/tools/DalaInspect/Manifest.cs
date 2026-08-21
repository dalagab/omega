// SPDX-License-Identifier: MIT-0
// Manifest.cs — JSON-serialisable description of the real Dalamud.dll's
// public surface. The generator consumes this file and emits C# stub code.
// Fields are intentionally small and JSON-friendly; nothing here depends on
// System.Reflection types at runtime so the file is safe to commit.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DalaInspect;

public sealed class Manifest
{
    [JsonPropertyName("sourceAssembly")]
    public string SourceAssembly { get; set; } = string.Empty;

    [JsonPropertyName("assemblyVersion")]
    public string AssemblyVersion { get; set; } = string.Empty;

    [JsonPropertyName("targetShimName")]
    public string TargetShimName { get; set; } = "Dalamud";

    [JsonPropertyName("targetShimVersion")]
    public string TargetShimVersion { get; set; } = "15.0.3.2";

    [JsonPropertyName("types")]
    public List<TypeShape> Types { get; set; } = new();
}

public sealed class TypeShape
{
    [JsonPropertyName("namespace")]
    public string Namespace { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("declaringType")]
    public string? DeclaringType { get; set; }

    [JsonPropertyName("fullName")]
    public string FullName { get; set; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "class"; // class|interface|struct|enum|delegate

    [JsonPropertyName("isPublic")]
    public bool IsPublic { get; set; }

    [JsonPropertyName("isAbstract")]
    public bool IsAbstract { get; set; }

    [JsonPropertyName("isSealed")]
    public bool IsSealed { get; set; }

    [JsonPropertyName("isNested")]
    public bool IsNested { get; set; }

    [JsonPropertyName("baseType")]
    public string? BaseType { get; set; }

    [JsonPropertyName("interfaces")]
    public List<string> Interfaces { get; set; } = new();

    [JsonPropertyName("genericParams")]
    public List<string> GenericParams { get; set; } = new();

    [JsonPropertyName("genericConstraints")]
    public List<GenericConstraint> GenericConstraints { get; set; } = new();

    [JsonPropertyName("enumUnderlyingType")]
    public string? EnumUnderlyingType { get; set; }

    [JsonPropertyName("enumValues")]
    public List<EnumValue> EnumValues { get; set; } = new();

    [JsonPropertyName("members")]
    public List<MemberShape> Members { get; set; } = new();
}

public sealed class GenericConstraint
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("attributes")]
    public List<string> Attributes { get; set; } = new();

    [JsonPropertyName("constraintTypes")]
    public List<string> ConstraintTypes { get; set; } = new();
}

public sealed class EnumValue
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public long Value { get; set; }
}

public sealed class MemberShape
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "method"; // method|property|field|event|ctor

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("returnType")]
    public string? ReturnType { get; set; }

    [JsonPropertyName("parameters")]
    public List<ParamShape> Parameters { get; set; } = new();

    [JsonPropertyName("genericParams")]
    public List<string> GenericParams { get; set; } = new();

    [JsonPropertyName("genericConstraints")]
    public List<GenericConstraint> GenericConstraints { get; set; } = new();

    [JsonPropertyName("isStatic")]
    public bool IsStatic { get; set; }

    [JsonPropertyName("isAbstract")]
    public bool IsAbstract { get; set; }

    [JsonPropertyName("isVirtual")]
    public bool IsVirtual { get; set; }

    [JsonPropertyName("isFinal")]
    public bool IsFinal { get; set; }

    [JsonPropertyName("isNewSlot")]
    public bool IsNewSlot { get; set; }

    [JsonPropertyName("isPublic")]
    public bool IsPublic { get; set; }

    [JsonPropertyName("propertyType")]
    public string? PropertyType { get; set; }

    [JsonPropertyName("propertyCanRead")]
    public bool PropertyCanRead { get; set; }

    [JsonPropertyName("propertyCanWrite")]
    public bool PropertyCanWrite { get; set; }

    [JsonPropertyName("fieldType")]
    public string? FieldType { get; set; }

    [JsonPropertyName("eventType")]
    public string? EventType { get; set; }

    [JsonPropertyName("eventHandlerType")]
    public string? EventHandlerType { get; set; }
}

public sealed class ParamShape
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("isByRef")]
    public bool IsByRef { get; set; }

    [JsonPropertyName("isParams")]
    public bool IsParams { get; set; }

    [JsonPropertyName("hasDefault")]
    public bool HasDefault { get; set; }

    [JsonPropertyName("defaultValue")]
    public string? DefaultValue { get; set; }

    [JsonPropertyName("isIn")]
    public bool IsIn { get; set; }

    [JsonPropertyName("isOut")]
    public bool IsOut { get; set; }
}

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    IncludeFields = false)]
[JsonSerializable(typeof(Manifest))]
public partial class SourceGenerationContext : JsonSerializerContext { }
