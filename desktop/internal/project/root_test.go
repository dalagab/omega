package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindRootWalksUp(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(root, "deltascope", "runtime-contract.json"))
	mustWrite(filepath.Join(root, "tools", "security", "deltascope.py"))
	nested := filepath.Join(root, "desktop", "cmd", "app")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := FindRoot(nested)
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Fatalf("got %q want %q", got, root)
	}
}
