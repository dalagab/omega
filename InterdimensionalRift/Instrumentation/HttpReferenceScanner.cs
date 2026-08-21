using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;
using InterdimensionalRift.Reporting;

namespace InterdimensionalRift.Instrumentation;

/// <summary>
/// Statically inspects a plugin DLL's metadata tables to surface
/// outbound-network capability indicators. Runs before the plugin is
/// loaded so even hard-failing plugins can still be analysed.
/// </summary>
public static class HttpReferenceScanner
{
    private static readonly string[] NetworkAssemblyNames =
    {
        "System.Net.Http",
        "System.Net.WebClient",
        "System.Net.Requests",
        "System.Net.Sockets",
    };

    private static readonly string[] NetworkNamespaces =
    {
        "System.Net.Http",
        "System.Net.Web",
        "System.Net.Sockets",
        "System.Net.Mail",
    };

    // A loose URL pattern: scheme:// followed by any non-whitespace. We
    // also catch a host literal of the form "evil.example.com" so the
    // scanner reports even when the URL is built from string parts.
    private static readonly Regex UrlRegex = new(
        @"\b(?:https?|ftp|ws|wss|tcp)://[^\s""'<>]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex HostLiteralRegex = new(
        @"\b(?:[a-z0-9-]+\.){1,}[a-z]{2,}\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // File extensions to exclude from the host literal scan. The
    // scanner sees every UTF-16 string in the DLL, and "SamplePlugin.dll"
    // is a common one that we don't want flagged as a network host.
    private static readonly HashSet<string> NoiseSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "dll", "exe", "pdb", "cs", "json", "xml", "txt", "config",
    };

    public static IReadOnlyList<Finding> Scan(string pluginPath, AccessTracker tracker)
    {
        var findings = new List<Finding>();
        if (!File.Exists(pluginPath))
        {
            return findings;
        }

        try
        {
            using var stream = File.OpenRead(pluginPath);
            using var peReader = new PEReader(stream);
            var md = peReader.GetMetadataReader();

            foreach (var handle in md.AssemblyReferences)
            {
                var reference = md.GetAssemblyReference(handle);
                var name = md.GetString(reference.Name) ?? string.Empty;
                if (NetworkAssemblyNames.Any(n => name.Equals(n, StringComparison.OrdinalIgnoreCase)))
                {
                    findings.Add(new Finding
                    {
                        Kind = FindingKind.AssemblyReference,
                        Severity = FindingSeverity.Medium,
                        Service = null,
                        Method = "AssemblyRef",
                        Message = name,
                        Context = "static metadata scan",
                    });
                }
            }

            foreach (var handle in md.TypeReferences)
            {
                var reference = md.GetTypeReference(handle);
                var ns = md.GetString(reference.Namespace) ?? string.Empty;
                if (NetworkNamespaces.Any(n => ns.StartsWith(n, StringComparison.Ordinal)))
                {
                    var typeName = md.GetString(reference.Name) ?? string.Empty;
                    findings.Add(new Finding
                    {
                        Kind = FindingKind.Capability,
                        Severity = FindingSeverity.Low,
                        Service = null,
                        Method = "TypeRef",
                        Message = $"{ns}.{typeName}",
                        Context = "static metadata scan",
                    });
                }
            }

            // .NET 10's SDK aggressively type-forwards HttpClient into
            // System.Runtime, so the AssemblyRef and TypeRef walks often
            // come up empty. Walk the user-string heap for URL literals
            // and notable host names — this catches the common case
            // where the plugin bakes an address into a log message or
            // a string constant.
            var usStrings = ExtractUserStrings(peReader);
            foreach (Match m in UrlRegex.Matches(usStrings))
            {
                findings.Add(new Finding
                {
                    Kind = FindingKind.Capability,
                    Severity = FindingSeverity.Medium,
                    Service = null,
                    Method = "UrlLiteral",
                    Message = m.Value,
                    Context = "static user-string scan",
                });
            }
            foreach (Match m in HostLiteralRegex.Matches(usStrings))
            {
                var last = m.Value.Split('.').LastOrDefault() ?? string.Empty;
                if (last.Length < 2) continue;
                if (NoiseSuffixes.Contains(last)) continue;
                findings.Add(new Finding
                {
                    Kind = FindingKind.Capability,
                    Severity = FindingSeverity.Low,
                    Service = null,
                    Method = "HostLiteral",
                    Message = m.Value,
                    Context = "static user-string scan",
                });
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Kind = FindingKind.Capability,
                Severity = FindingSeverity.Info,
                Method = "scan_failed",
                Message = ex.GetType().Name,
                ExceptionType = ex.GetType().FullName,
                ExceptionMessage = ex.Message,
                Context = "static metadata scan",
            });
        }

        foreach (var f in findings)
        {
            // stamp a timestamp relative to the tracker clock so they line up
            f.TimestampOffsetMs = tracker.ElapsedMs;
        }
        return findings;
    }

    /// <summary>
    /// Decodes every UTF-16 string in the file's #US heap so we can
    /// regex over it. We don't try to walk the compressed length
    /// prefixes (the public <c>System.Reflection.Metadata</c> surface
    /// in .NET 10 doesn't expose <c>GetHeapMetadataOffset</c>), so
    /// instead we extract every run of UTF-16LE printable characters
    /// and join them with spaces. False positives are tolerable — the
    /// host literal regex is already conservative.
    /// </summary>
    private static string ExtractUserStrings(PEReader peReader)
    {
        // Read the whole image into memory. Plugin DLLs are small and
        // the sandbox has no other use for the bytes; this is the
        // simplest cross-platform path.
        var image = peReader.GetEntireImage().GetContent();
        var imageBytes = image.ToArray();
        var sb = new StringBuilder(imageBytes.Length / 2);

        // Look for runs of 4+ printable UTF-16LE characters. That
        // excludes most of the metadata noise (which is ASCII / UTF-8
        // strings interleaved with binary) and keeps the work bounded.
        int i = 0;
        while (i < imageBytes.Length - 3)
        {
            // UTF-16LE pattern for printable ASCII: low byte is the
            // ASCII char, high byte is 0x00. So we look for two
            // consecutive 0x00, printable, 0x00, printable runs.
            if (IsUtf16Unit(imageBytes[i]) && imageBytes[i + 1] == 0 &&
                IsUtf16Unit(imageBytes[i + 2]) && imageBytes[i + 3] == 0)
            {
                int start = i;
                while (i < imageBytes.Length - 1 &&
                       IsUtf16Unit(imageBytes[i]) &&
                       imageBytes[i + 1] == 0)
                {
                    i += 2;
                }
                int runBytes = i - start;
                if (runBytes >= 8)
                {
                    sb.Append(Encoding.Unicode.GetString(imageBytes, start, runBytes));
                    sb.Append(' ');
                }
            }
            else
            {
                i++;
            }
        }

        return sb.ToString();
    }

    private static bool IsUtf16Unit(byte b)
    {
        // ASCII printable + a few extras seen in URLs / host names.
        return b >= 0x20 && b < 0x7F;
    }
}
