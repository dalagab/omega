using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Dalagab.Omega;

internal enum MarketplaceReadmeBlockKind
{
    Paragraph,
    Heading,
    Bullet,
    Numbered,
    Quote,
    Code,
    Rule,
}

internal sealed record MarketplaceReadmeBlock(MarketplaceReadmeBlockKind Kind, string Text, int Level = 0);

/// <summary>
/// Converts the bounded public README copy into safe presentation blocks.
/// Markdown and common embedded HTML are interpreted for readability; executable HTML,
/// scripts, forms, images and arbitrary raw links are never executed by the client.
/// </summary>
internal static partial class MarketplaceReadmeMarkup
{
    [GeneratedRegex(@"<!--.*?-->", RegexOptions.Singleline)]
    private static partial Regex HtmlCommentRegex();

    [GeneratedRegex(@"<(script|style|iframe|object|embed|form)\b[^>]*>.*?</\1\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex DangerousHtmlBlockRegex();

    [GeneratedRegex(@"<a\b[^>]*>(.*?)</a\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex HtmlAnchorRegex();

    [GeneratedRegex(@"<pre\b[^>]*>(.*?)</pre\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex HtmlPreRegex();

    [GeneratedRegex(@"<blockquote\b[^>]*>(.*?)</blockquote\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex HtmlBlockquoteRegex();

    [GeneratedRegex(@"<img\b[^>]*(?:alt=[""']([^""']*)[""'])?[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex HtmlImageRegex();

    [GeneratedRegex(@"<br\s*/?>", RegexOptions.IgnoreCase)]
    private static partial Regex HtmlBreakRegex();

    [GeneratedRegex(@"<(p|div|section|article|header|footer|table|tr|ul|ol)\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex HtmlBlockStartRegex();

    [GeneratedRegex(@"</(p|div|section|article|header|footer|table|tr|ul|ol)\s*>", RegexOptions.IgnoreCase)]
    private static partial Regex HtmlBlockEndRegex();

    [GeneratedRegex(@"<h([1-6])\b[^>]*>(.*?)</h\1\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex HtmlHeadingRegex();

    [GeneratedRegex(@"<li\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex HtmlListItemStartRegex();

    [GeneratedRegex(@"</li\s*>", RegexOptions.IgnoreCase)]
    private static partial Regex HtmlListItemEndRegex();

    [GeneratedRegex(@"</?(td|th)\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex HtmlTableCellRegex();

    [GeneratedRegex(@"<[^>]+>", RegexOptions.Singleline)]
    private static partial Regex RemainingHtmlRegex();

    [GeneratedRegex(@"!\[([^\]]*)\]\([^)]*\)")]
    private static partial Regex MarkdownImageRegex();

    [GeneratedRegex(@"\[([^\]]+)\]\([^)]*\)")]
    private static partial Regex MarkdownLinkRegex();

    [GeneratedRegex(@"^#{1,6}\s+")]
    private static partial Regex MarkdownHeadingPrefixRegex();

    [GeneratedRegex(@"^\s*[-*+]\s+")]
    private static partial Regex MarkdownBulletRegex();

    [GeneratedRegex(@"^\s*\d+[.)]\s+")]
    private static partial Regex MarkdownNumberedRegex();

    [GeneratedRegex(@"^\s*([-*_])(?:\s*\1){2,}\s*$")]
    private static partial Regex MarkdownRuleRegex();

    [GeneratedRegex(@"\n{3,}")]
    private static partial Regex ExcessBlankLinesRegex();

    public static IReadOnlyList<MarketplaceReadmeBlock> Parse(string? input)
    {
        var text = NormalizeHtml(input ?? string.Empty);
        if (string.IsNullOrWhiteSpace(text))
            return [];

        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');
        var blocks = new List<MarketplaceReadmeBlock>();
        var paragraph = new StringBuilder();
        var code = new StringBuilder();
        var inCode = false;

        void FlushParagraph()
        {
            if (paragraph.Length == 0)
                return;
            var value = CleanInline(paragraph.ToString());
            if (!string.IsNullOrWhiteSpace(value))
                blocks.Add(new MarketplaceReadmeBlock(MarketplaceReadmeBlockKind.Paragraph, value));
            paragraph.Clear();
        }

        void FlushCode()
        {
            if (code.Length == 0)
                return;
            blocks.Add(new MarketplaceReadmeBlock(MarketplaceReadmeBlockKind.Code, code.ToString().TrimEnd()));
            code.Clear();
        }

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd();
            var trimmed = line.Trim();
            if (trimmed.StartsWith("```", StringComparison.Ordinal) || trimmed.StartsWith("~~~", StringComparison.Ordinal))
            {
                FlushParagraph();
                if (inCode)
                    FlushCode();
                inCode = !inCode;
                continue;
            }
            if (inCode)
            {
                code.AppendLine(line);
                continue;
            }
            if (trimmed.Length == 0)
            {
                FlushParagraph();
                continue;
            }
            if (MarkdownRuleRegex().IsMatch(trimmed))
            {
                FlushParagraph();
                blocks.Add(new MarketplaceReadmeBlock(MarketplaceReadmeBlockKind.Rule, string.Empty));
                continue;
            }
            if (trimmed.StartsWith('#'))
            {
                var level = Math.Clamp(trimmed.TakeWhile(ch => ch == '#').Count(), 1, 6);
                if (trimmed.Length > level && char.IsWhiteSpace(trimmed[level]))
                {
                    FlushParagraph();
                    blocks.Add(new MarketplaceReadmeBlock(MarketplaceReadmeBlockKind.Heading, CleanInline(MarkdownHeadingPrefixRegex().Replace(trimmed, string.Empty)), level));
                    continue;
                }
            }
            if (trimmed.StartsWith('>'))
            {
                FlushParagraph();
                blocks.Add(new MarketplaceReadmeBlock(MarketplaceReadmeBlockKind.Quote, CleanInline(trimmed.TrimStart('>', ' '))));
                continue;
            }
            if (MarkdownBulletRegex().IsMatch(line))
            {
                FlushParagraph();
                blocks.Add(new MarketplaceReadmeBlock(MarketplaceReadmeBlockKind.Bullet, CleanInline(MarkdownBulletRegex().Replace(line, string.Empty))));
                continue;
            }
            if (MarkdownNumberedRegex().IsMatch(line))
            {
                FlushParagraph();
                var marker = line.TrimStart().TakeWhile(ch => char.IsDigit(ch)).Aggregate(new StringBuilder(), (builder, ch) => builder.Append(ch)).ToString();
                blocks.Add(new MarketplaceReadmeBlock(MarketplaceReadmeBlockKind.Numbered, CleanInline(MarkdownNumberedRegex().Replace(line, string.Empty)), int.TryParse(marker, out var number) ? number : 0));
                continue;
            }

            if (paragraph.Length > 0)
                paragraph.Append(' ');
            paragraph.Append(trimmed);
        }

        FlushParagraph();
        FlushCode();
        return blocks.Take(320).ToArray();
    }

    internal static string NormalizeHtml(string input)
    {
        var text = HtmlCommentRegex().Replace(input, string.Empty);
        text = DangerousHtmlBlockRegex().Replace(text, string.Empty);
        text = HtmlPreRegex().Replace(text, match => $"\n```\n{RemainingHtmlRegex().Replace(match.Groups[1].Value, string.Empty)}\n```\n");
        text = HtmlBlockquoteRegex().Replace(text, match => $"\n> {RemainingHtmlRegex().Replace(match.Groups[1].Value, string.Empty)}\n");
        text = HtmlHeadingRegex().Replace(text, match => $"\n{new string('#', int.Parse(match.Groups[1].Value))} {match.Groups[2].Value}\n");
        text = HtmlAnchorRegex().Replace(text, "$1");
        text = HtmlImageRegex().Replace(text, match => string.IsNullOrWhiteSpace(match.Groups[1].Value) ? string.Empty : match.Groups[1].Value);
        text = HtmlBreakRegex().Replace(text, "\n");
        text = HtmlListItemStartRegex().Replace(text, "\n- ");
        text = HtmlListItemEndRegex().Replace(text, "\n");
        text = HtmlTableCellRegex().Replace(text, " | ");
        text = HtmlBlockStartRegex().Replace(text, "\n");
        text = HtmlBlockEndRegex().Replace(text, "\n");
        text = RemainingHtmlRegex().Replace(text, string.Empty);
        text = WebUtility.HtmlDecode(text);
        return ExcessBlankLinesRegex().Replace(text, "\n\n").Trim();
    }

    private static string CleanInline(string input)
    {
        var text = MarkdownImageRegex().Replace(input, "$1");
        text = MarkdownLinkRegex().Replace(text, "$1");
        text = text.Replace("**", string.Empty, StringComparison.Ordinal)
            .Replace("__", string.Empty, StringComparison.Ordinal)
            .Replace("`", string.Empty, StringComparison.Ordinal)
            .Replace("~~", string.Empty, StringComparison.Ordinal);
        return string.Join(' ', text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).Trim();
    }
}
