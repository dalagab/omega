using System.Diagnostics;
using System.Numerics;
using Dalamud.Bindings.ImGui;

namespace Dalagab.Omega;

/// <summary>
/// Renders bounded, classified project actions discovered by Omega's public metadata scraper.
/// Arbitrary/raw URLs are intentionally not exposed as client buttons.
/// </summary>
internal sealed partial class MarketplaceWindow
{
    private IReadOnlyList<MarketplaceProjectLink> BuildProductProjectLinks(MarketplacePlugin plugin)
    {
        var links = new List<MarketplaceProjectLink>();
        foreach (var link in plugin.OmegaProjectLinks.OrderBy(link => ProjectLinkPriority(link.Kind)))
        {
            if (!IsSafeProjectActionUrl(link.Url) || links.Any(x => x.Kind.Equals(link.Kind, StringComparison.OrdinalIgnoreCase)))
                continue;
            links.Add(link);
        }

        // Older Definitions do not carry classified links yet. Keep the existing project action as a
        // compatibility fallback until the next Definitions refresh populates the structured roles.
        var project = ResolveProjectUrl(plugin);
        if (IsSafeProjectActionUrl(project) && !links.Any(x => x.Kind.Equals("source", StringComparison.OrdinalIgnoreCase)))
            links.Add(new MarketplaceProjectLink("source", "Source", project));
        return links.OrderBy(link => ProjectLinkPriority(link.Kind)).Take(6).ToArray();
    }

    private void DrawProductProjectLinks(MarketplacePlugin plugin)
    {
        var links = BuildProductProjectLinks(plugin);
        if (links.Count == 0)
            return;

        ImGui.Dummy(new Vector2(1f, 8f));
        ImGui.TextDisabled("Project links");
        var first = true;
        foreach (var link in links)
        {
            var label = string.IsNullOrWhiteSpace(link.Label) ? ProjectLinkLabel(link.Kind) : link.Label.Trim();
            var width = Math.Clamp(ImGui.CalcTextSize(label).X + 28f, 86f, 170f);
            if (!first && ImGui.GetContentRegionAvail().X < width + 8f)
                ImGui.NewLine();
            else
                ImGui.SameLine(0f, 7f);

            if (DrawPillButton(
                    label,
                    $"project-link-{StableId(plugin.InternalName + "-" + link.Kind)}",
                    new Vector2(width, 28f),
                    link.Kind.Equals("discord", StringComparison.OrdinalIgnoreCase)))
            {
                OpenProductWebsite(plugin, link.Url);
            }
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip(link.Url);
            first = false;
        }
        ImGui.NewLine();
    }

    private void OpenProductWebsite(MarketplacePlugin plugin, string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Plugin.Log.Debug(ex, "Omega could not open project URL for {Plugin}", plugin.InternalName);
            operationMessage = $"Could not open the project page for {plugin.Name}.";
        }
    }

    private static bool IsSafeProjectActionUrl(string? candidate)
        => Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
           uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static int ProjectLinkPriority(string kind) => kind.Trim().ToLowerInvariant() switch
    {
        "discord" => 0,
        "website" => 1,
        "source" => 2,
        "docs" => 3,
        "issues" => 4,
        "releases" => 5,
        _ => 10,
    };

    private static string ProjectLinkLabel(string kind) => kind.Trim().ToLowerInvariant() switch
    {
        "discord" => "Join Discord",
        "website" => "Website",
        "source" => "Source",
        "docs" => "Documentation",
        "issues" => "Issues",
        "releases" => "Releases",
        _ => "Project link",
    };
}
