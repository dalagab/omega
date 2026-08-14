namespace Dalagab.Omega.RegressionTests;

internal static partial class RegressionCases
{
    internal static void TestPluginSecurityIntelligenceContract()
    {
        var scanner = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "security_scan.py"));
        Contains(scanner, "SCANNER_VERSION = \"1.0.0\"", "scanner version is explicit so stale scans can be refreshed");
        Contains(scanner, "Only HTTPS downloads are scanned", "scanner refuses insecure artifact transports");
        Contains(scanner, "MAX_ARTIFACT_BYTES", "artifact downloads are bounded");
        Contains(scanner, "MAX_ARCHIVE_ENTRIES", "archive entry count is bounded");
        Contains(scanner, "safe_member_name", "archive paths are validated before content inspection");
        Contains(scanner, "never", "scanner documents its no-execution trust boundary");
        Contains(scanner, "compound.network-execute", "compound network/process risk is surfaced");
        Contains(scanner, "sourceToBinaryVerified", "source inspection does not imply source-to-binary verification");
        Contains(scanner, "plugin_security_current", "scanner persists the current result per exact catalog variant");
        Contains(scanner, "Preserve last-known-good intelligence", "transient revalidation failures do not erase the last completed scan");

        var workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "security-scanner.yml"));
        var normalizedWorkflow = workflow.ReplaceLineEndings("\n");
        Contains(normalizedWorkflow, "cron: \"17 6 * * *\"", "security scanner runs daily");
        Contains(normalizedWorkflow, "permissions:\n      contents: read", "hostile artifact scan job has read-only repository permission");
        Contains(workflow, "name: Publish security-enriched catalog", "publishing is isolated into a second job");
        Contains(workflow, "contents: write", "only publishing receives repository write permission");
        Contains(workflow, "--max-scans", "daily scan work is bounded");
        Contains(workflow, "--rescan-after-hours", "unchanged artifacts are periodically revalidated");
        Contains(workflow, "security-report.json", "each batch publishes an auditable scan summary");

        var builder = File.ReadAllText(Path.Combine(Root, "tools", "catalog", "build_sqlite_catalog.py"));
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugin_security_scans", "catalog schema preserves security scan history");
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugin_security_findings", "catalog schema stores individual findings");
        Contains(builder, "CREATE TABLE IF NOT EXISTS plugin_security_current", "catalog schema stores current per-variant security state");
        Contains(builder, "security_status", "runtime catalog view exposes security state to Omega");

        var store = File.ReadAllText(Path.Combine(Root, "Omega", "Services", "SqliteCatalogStore.cs"));
        Contains(store, "SecurityArtifactSha256", "runtime reads exact scanned artifact hashes");
        Contains(store, "ReadSecurityFindings", "runtime reads structured security findings from SQLite");

        var product = File.ReadAllText(Path.Combine(Root, "Omega", "UI", "MarketplaceWindow.PluginSecurity.cs"));
        Contains(product, "Observed capabilities", "product page explains observed permissions/capabilities");
        Contains(product, "View findings", "product page exposes detailed findings");
        Contains(product, "No findings is not proof", "product page avoids claiming that static analysis proves safety");
        Contains(product, "Source-to-binary correspondence has not been verified", "product page preserves source provenance uncertainty");
    }
}
