package download

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchVerifiesDigestAndReusesDestination(t *testing.T) {
	payload := []byte("DeltaScope desktop downloader")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	sum := sha256.Sum256(payload)
	expected := hex.EncodeToString(sum[:])
	destination := filepath.Join(t.TempDir(), "payload.bin")
	manager := Manager{Client: server.Client()}
	first, err := manager.Fetch(context.Background(), Request{URL: server.URL, Destination: destination, SHA256: expected})
	if err != nil {
		t.Fatal(err)
	}
	if first.FromCache || first.SHA256 != expected {
		t.Fatalf("unexpected first result: %+v", first)
	}
	server.Close()
	second, err := manager.Fetch(context.Background(), Request{URL: server.URL, Destination: destination, SHA256: expected})
	if err != nil {
		t.Fatal(err)
	}
	if !second.FromCache {
		t.Fatalf("expected verified local reuse: %+v", second)
	}
}

func TestFetchRejectsOversize(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1234567890"))
	}))
	defer server.Close()
	_, err := (Manager{Client: server.Client()}).Fetch(context.Background(), Request{
		URL: server.URL, Destination: filepath.Join(t.TempDir(), "x"), MaxBytes: 4,
	})
	if err == nil {
		t.Fatal("expected size failure")
	}
}

func TestExtractZipRejectsTraversal(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	entry, err := zw.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(entry, "no")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := ExtractZip(archive, filepath.Join(t.TempDir(), "out"), ExtractOptions{}); err == nil {
		t.Fatal("expected traversal rejection")
	}
}
