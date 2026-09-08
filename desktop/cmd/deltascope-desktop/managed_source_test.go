package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dalagab/omega/deltascope-desktop/internal/download"
)

const (
	commitA = "1111111111111111111111111111111111111111"
	commitB = "2222222222222222222222222222222222222222"
)

type branchFixture struct {
	mu     sync.Mutex
	commit string
	etag   string
	status int
	calls  int
}

func (b *branchFixture) handler(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.status != 0 && b.status != http.StatusOK {
		http.Error(w, "offline", b.status)
		return
	}
	if b.etag != "" && r.Header.Get("If-None-Match") == b.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if b.etag != "" {
		w.Header().Set("ETag", b.etag)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]any{"sha": b.commit}})
}

func (b *branchFixture) set(commit, etag string, status int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.commit = commit
	b.etag = etag
	b.status = status
}

func newTestManager(t *testing.T, branch *branchFixture) (*managedSourceManager, *int) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(branch.handler))
	t.Cleanup(server.Close)
	fetches := 0
	manager := &managedSourceManager{
		root:         filepath.Join(t.TempDir(), "managed"),
		client:       server.Client(),
		now:          func() time.Time { return time.Date(2026, 9, 8, 10, 35, 0, 0, time.UTC) },
		branchURL:    server.URL,
		pollInterval: time.Millisecond,
	}
	manager.fetchArchive = func(_ context.Context, commit, destination string) (download.Result, error) {
		fetches++
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return download.Result{}, err
		}
		if err := os.WriteFile(destination, []byte("archive-"+commit), 0o644); err != nil {
			return download.Result{}, err
		}
		return download.Result{Path: destination, SHA256: strings.Repeat(commit[:1], 64), Bytes: int64(len(commit) + 8)}, nil
	}
	manager.extractArchive = func(_ string, destination string) error {
		root := filepath.Join(destination, "dalagab-omega-test")
		return writeValidSource(root)
	}
	return manager, &fetches
}

func writeValidSource(root string) error {
	files := map[string]string{
		filepath.Join("deltascope", "runtime-contract.json"): `{"schema":"omega.deltascope.runtime-contract.v1","runtime":{"language":"python"}}`,
		filepath.Join("deltascope", "requirements.txt"):      "PyYAML==6.0.3\n",
		filepath.Join("tools", "security", "deltascope.py"):  "print('DeltaScope')\n",
		filepath.Join("desktop", "assets", "deltascope.ico"): "ico",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func TestManagedSourceFirstInstallAndUnchangedCommit(t *testing.T) {
	branch := &branchFixture{commit: commitA, etag: `"a"`}
	manager, fetches := newTestManager(t, branch)
	first, err := manager.prepareForLaunch(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Managed || !first.Updated || first.Commit != commitA {
		t.Fatalf("unexpected first launch: %+v", first)
	}
	if *fetches != 1 {
		t.Fatalf("first install fetches=%d want 1", *fetches)
	}
	if first.EnvironmentDir != filepath.Join(manager.root, "python-env") {
		t.Fatalf("environment=%q", first.EnvironmentDir)
	}
	second, err := manager.prepareForLaunch(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if second.Commit != commitA || second.Updated {
		t.Fatalf("unexpected unchanged launch: %+v", second)
	}
	if *fetches != 1 {
		t.Fatalf("unchanged commit downloaded again: %d", *fetches)
	}
	stateBytes, err := os.ReadFile(manager.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(stateBytes)), "token") || strings.Contains(string(stateBytes), "Authorization") {
		t.Fatal("managed state must not contain credentials")
	}
}

func TestManagedSourceStagesWhileRunningAndActivatesOnNextStart(t *testing.T) {
	branch := &branchFixture{commit: commitA, etag: `"a"`}
	manager, fetches := newTestManager(t, branch)
	if _, err := manager.prepareForLaunch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	branch.set(commitB, `"b"`, http.StatusOK)
	staged, err := manager.stageIfNew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if staged != commitB || *fetches != 2 {
		t.Fatalf("staged=%q fetches=%d", staged, *fetches)
	}
	state, _ := manager.loadState()
	if state.ActiveCommit != commitA || state.StagedCommit != commitB {
		t.Fatalf("live state changed underneath running source: %+v", state)
	}
	next, err := manager.prepareForLaunch(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if next.Commit != commitB || !next.Updated {
		t.Fatalf("staged source not activated on restart: %+v", next)
	}
	state, _ = manager.loadState()
	if state.PreviousCommit != commitA || state.StagedCommit != "" {
		t.Fatalf("previous/staged state incorrect: %+v", state)
	}
}

func TestManagedSourceOfflineUsesInstalledRevision(t *testing.T) {
	branch := &branchFixture{commit: commitA, etag: `"a"`}
	manager, _ := newTestManager(t, branch)
	if _, err := manager.prepareForLaunch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	branch.set(commitA, `"a"`, http.StatusServiceUnavailable)
	result, err := manager.prepareForLaunch(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Commit != commitA || result.Warning == "" {
		t.Fatalf("offline fallback=%+v", result)
	}
}

func TestManagedSourceRollbackQuarantinesFailedCommit(t *testing.T) {
	branch := &branchFixture{commit: commitA, etag: `"a"`}
	manager, fetches := newTestManager(t, branch)
	if _, err := manager.prepareForLaunch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	branch.set(commitB, `"b"`, http.StatusOK)
	if _, err := manager.stageIfNew(context.Background()); err != nil {
		t.Fatal(err)
	}
	newSource, err := manager.prepareForLaunch(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := rollbackLaunchSource(newSource, errors.New("backend failed"))
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Commit != commitA {
		t.Fatalf("rollback commit=%s", rolled.Commit)
	}
	state, _ := manager.loadState()
	if state.BadCommit != commitB || state.ActiveCommit != commitA {
		t.Fatalf("rollback state=%+v", state)
	}
	before := *fetches
	result, err := manager.prepareForLaunch(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Commit != commitA || *fetches != before {
		t.Fatalf("quarantined commit reacquired: result=%+v fetches=%d/%d", result, *fetches, before)
	}
}

func TestValidateSourceRootRejectsWrongContract(t *testing.T) {
	root := t.TempDir()
	if err := writeValidSource(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deltascope", "runtime-contract.json"), []byte(`{"schema":"wrong","runtime":{"language":"python"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateSourceRoot(root); err == nil {
		t.Fatal("expected invalid runtime contract")
	}
}
