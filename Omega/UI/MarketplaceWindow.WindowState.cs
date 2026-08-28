// Retired 0.7.4.0 overlay tombstone.
//
// ZipRunner overlays packages without deleting files omitted by newer ZIPs. The
// 0.7.4.0 transition package introduced this partial class, but the window state is
// now integrated into MarketplaceWindow.cs and MarketplaceWindow.Chrome.cs.
// Keep this file intentionally member-free so upgraded worktrees cannot compile a
// second isMinimized field or obsolete minimize implementation.
