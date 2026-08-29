package window

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLaunchRequiresURL(t *testing.T) {
	if _, err := Launch(context.Background(), Options{}); err == nil {
		t.Fatal("expected URL validation error")
	}
}

func TestResolveIconPrefersExplicitThenDesktopAssets(t *testing.T) {
	root := t.TempDir()
	assetDir := filepath.Join(root, "desktop", "assets")
	if err := os.MkdirAll(assetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	defaultIcon := filepath.Join(assetDir, "deltascope.png")
	if err := os.WriteFile(defaultIcon, []byte("icon"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveIcon(root, ""); got != defaultIcon {
		t.Fatalf("ResolveIcon default = %q, want %q", got, defaultIcon)
	}
	explicit := filepath.Join(root, "custom.ico")
	if err := os.WriteFile(explicit, []byte("ico"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveIcon(root, explicit); got != explicit {
		t.Fatalf("ResolveIcon explicit = %q, want %q", got, explicit)
	}
}
