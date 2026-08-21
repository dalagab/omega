// SPDX-License-Identifier: MIT-0
// DalaInspect — one-off tool that walks the public surface of the real
// Dalamud.dll via MetadataLoadContext and writes a JSON manifest. The
// companion DalaGen program consumes the manifest and emits C# stub code
// for InterdimensionalRift.DalamudShim. Run with:
//
//   dotnet run --project tools/DalaInspect -- <path-to-Dalamud.dll> <output-json> [--inspect-only] [--generate-only]
//
// The tool never loads the real DLL into a runtime ALC, so no code from
// the real assembly is executed.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DalaInspect;

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: DalaInspect <path-to-Dalamud.dll> <output-json> [--inspect-only|--generate-only]");
    return 2;
}

var dalamudPath = Path.GetFullPath(args[0]);
var manifestPath = Path.GetFullPath(args[1]);
var inspectOnly = args.Contains("--inspect-only");
var generateOnly = args.Contains("--generate-only");

var shimProjectRoot = LocateShimProjectRoot();
if (shimProjectRoot is null)
{
    Console.Error.WriteLine("could not locate InterdimensionalRift.DalamudShim project root");
    return 2;
}

if (!generateOnly)
{
    var manifest = Inspector.Inspect(dalamudPath);
    Directory.CreateDirectory(Path.GetDirectoryName(manifestPath)!);
    File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, SourceGenerationContext.Default.Manifest));
    Console.WriteLine($"manifest written: {manifestPath}");
    Console.WriteLine($"  types       : {manifest.Types.Count}");
    Console.WriteLine($"  by kind     : {string.Join(", ", manifest.Types.GroupBy(t => t.Kind).OrderBy(g => g.Key).Select(g => $"{g.Key}={g.Count()}"))}");
    var memCount = manifest.Types.Sum(t => t.Members.Count);
    Console.WriteLine($"  members     : {memCount}");
    Console.WriteLine($"  nested      : {manifest.Types.Count(t => t.IsNested)}");
}

if (inspectOnly) return 0;

var manifest2 = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(manifestPath), SourceGenerationContext.Default.Manifest)!;
var generator = new Generator(shimProjectRoot, dalamudPath);
generator.Emit(manifest2);
Console.WriteLine($"generated code at: {shimProjectRoot}");
return 0;

static string? LocateShimProjectRoot()
{
    // We're in tools/DalaInspect/. The shim project is two levels up.
    var here = AppContext.BaseDirectory;
    var probe = new DirectoryInfo(here);
    for (int i = 0; i < 6 && probe is not null; i++)
    {
        if (File.Exists(Path.Combine(probe.FullName, "InterdimensionalRift.DalamudShim.csproj")))
        {
            return probe.FullName;
        }
        probe = probe.Parent;
    }
    return null;
}
