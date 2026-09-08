package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dalagab/omega/deltascope-desktop/internal/download"
	"github.com/dalagab/omega/deltascope-desktop/internal/project"
)

const (
	managedStateSchema  = "omega.deltascope.desktop-managed-source.v1"
	managedPollInterval = 30 * time.Minute
	managedBranchURL    = "https://api.github.com/repos/dalagab/omega/branches/deltascope"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type launchSource struct {
	Root           string
	EnvironmentDir string
	Commit         string
	ManagerRoot    string
	Managed        bool
	Updated        bool
	Warning        string
}

type managedSourceState struct {
	Schema                string `json:"schema"`
	ActiveCommit          string `json:"activeCommit,omitempty"`
	ActiveArchiveSHA256   string `json:"activeArchiveSha256,omitempty"`
	PreviousCommit        string `json:"previousCommit,omitempty"`
	PreviousArchiveSHA256 string `json:"previousArchiveSha256,omitempty"`
	StagedCommit          string `json:"stagedCommit,omitempty"`
	StagedArchiveSHA256   string `json:"stagedArchiveSha256,omitempty"`
	BadCommit             string `json:"badCommit,omitempty"`
	LatestCommit          string `json:"latestCommit,omitempty"`
	BranchETag            string `json:"branchEtag,omitempty"`
	LastCheckAtUTC        string `json:"lastCheckAtUtc,omitempty"`
	LastSuccessAtUTC      string `json:"lastSuccessAtUtc,omitempty"`
	LastError             string `json:"lastError,omitempty"`
}

type managedSourceManager struct {
	root           string
	client         *http.Client
	now            func() time.Time
	branchURL      string
	pollInterval   time.Duration
	fetchArchive   func(context.Context, string, string) (download.Result, error)
	extractArchive func(string, string) error
}

func newManagedSourceManager() (*managedSourceManager, error) {
	cache, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(cache) == "" {
		return nil, errors.New("cannot resolve the per-user DeltaScope managed-source directory")
	}
	root := filepath.Join(cache, "Omega", "DeltaScope", "managed")
	manager := &managedSourceManager{
		root:         root,
		client:       &http.Client{Timeout: 20 * time.Second},
		now:          time.Now,
		branchURL:    managedBranchURL,
		pollInterval: managedPollInterval,
	}
	manager.fetchArchive = func(ctx context.Context, commit, destination string) (download.Result, error) {
		return (download.Manager{UserAgent: "DeltaScope-Desktop/" + launcherVersion}).Fetch(ctx, download.Request{
			URL:          "https://codeload.github.com/dalagab/omega/zip/" + commit,
			Destination:  destination,
			MaxBytes:     256 << 20,
			AllowedHosts: []string{"codeload.github.com"},
		})
	}
	manager.extractArchive = func(archive, destination string) error {
		return download.ExtractZip(archive, destination, download.ExtractOptions{MaxFiles: 20_000, MaxBytes: 2 << 30})
	}
	return manager, nil
}

func resolveLaunchSource(ctx context.Context, explicit string, noUpdate bool) (launchSource, error) {
	if strings.TrimSpace(explicit) != "" {
		root, err := project.FindRoot(explicit)
		return launchSource{Root: root}, err
	}
	if executable, err := os.Executable(); err == nil {
		if root, findErr := project.FindRoot(filepath.Dir(executable)); findErr == nil {
			return launchSource{Root: root}, nil
		}
	}
	if root, err := project.FindRoot(""); err == nil {
		return launchSource{Root: root}, nil
	}
	manager, err := newManagedSourceManager()
	if err != nil {
		return launchSource{}, err
	}
	return manager.prepareForLaunch(ctx, noUpdate)
}

func (m *managedSourceManager) prepareForLaunch(ctx context.Context, noUpdate bool) (launchSource, error) {
	state, err := m.loadState()
	if err != nil {
		return launchSource{}, err
	}
	updated := false
	warning := ""

	if validCommit(state.StagedCommit) && state.StagedCommit != state.BadCommit && m.sourceValid(state.StagedCommit) {
		m.activate(&state, state.StagedCommit, state.StagedArchiveSHA256)
		updated = true
		if err := m.saveState(state); err != nil {
			return launchSource{}, err
		}
	}

	if !noUpdate {
		latest, checkErr := m.latestCommit(ctx, &state)
		state.LastCheckAtUTC = m.timestamp()
		if checkErr != nil {
			state.LastError = boundedError(checkErr)
			_ = m.saveState(state)
			if m.sourceValid(state.ActiveCommit) {
				warning = "GitHub update check failed; using installed DeltaScope source " + state.ActiveCommit + ": " + state.LastError
			} else {
				return launchSource{}, fmt.Errorf("DeltaScope source is not installed and the GitHub update check failed: %w", checkErr)
			}
		} else {
			state.LastError = ""
			state.LastSuccessAtUTC = m.timestamp()
			if latest != state.ActiveCommit && latest != state.BadCommit {
				archiveSHA, acquireErr := m.ensureSource(ctx, latest)
				if acquireErr != nil {
					state.LastError = boundedError(acquireErr)
					_ = m.saveState(state)
					if m.sourceValid(state.ActiveCommit) {
						warning = "DeltaScope update " + latest + " could not be staged; using installed source " + state.ActiveCommit + ": " + state.LastError
					} else {
						return launchSource{}, acquireErr
					}
				} else {
					m.activate(&state, latest, archiveSHA)
					updated = true
				}
			}
			if err := m.saveState(state); err != nil {
				return launchSource{}, err
			}
		}
	}

	if !m.sourceValid(state.ActiveCommit) {
		if m.sourceValid(state.PreviousCommit) {
			state.ActiveCommit = state.PreviousCommit
			state.ActiveArchiveSHA256 = state.PreviousArchiveSHA256
			state.PreviousCommit = ""
			state.PreviousArchiveSHA256 = ""
			if err := m.saveState(state); err != nil {
				return launchSource{}, err
			}
		} else {
			return launchSource{}, errors.New("no valid managed DeltaScope source is installed")
		}
	}
	m.prune(state)
	return m.launchInfo(state.ActiveCommit, updated, warning), nil
}

func (m *managedSourceManager) stageIfNew(ctx context.Context) (string, error) {
	state, err := m.loadState()
	if err != nil {
		return "", err
	}
	latest, err := m.latestCommit(ctx, &state)
	state.LastCheckAtUTC = m.timestamp()
	if err != nil {
		state.LastError = boundedError(err)
		_ = m.saveState(state)
		return "", err
	}
	state.LastError = ""
	state.LastSuccessAtUTC = m.timestamp()
	if latest == state.ActiveCommit || latest == state.StagedCommit || latest == state.BadCommit {
		return "", m.saveState(state)
	}
	archiveSHA, err := m.ensureSource(ctx, latest)
	if err != nil {
		state.LastError = boundedError(err)
		_ = m.saveState(state)
		return "", err
	}
	state.StagedCommit = latest
	state.StagedArchiveSHA256 = archiveSHA
	if err := m.saveState(state); err != nil {
		return "", err
	}
	m.prune(state)
	return latest, nil
}

func (m *managedSourceManager) latestCommit(ctx context.Context, state *managedSourceState) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.branchURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "DeltaScope-Desktop/"+launcherVersion)
	if state.BranchETag != "" && validCommit(state.LatestCommit) {
		req.Header.Set("If-None-Match", state.BranchETag)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && validCommit(state.LatestCommit) {
		return state.LatestCommit, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("GitHub branch lookup returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode GitHub branch response: %w", err)
	}
	commit := strings.ToLower(strings.TrimSpace(payload.Commit.SHA))
	if !validCommit(commit) {
		return "", fmt.Errorf("GitHub returned invalid deltascope commit %q", payload.Commit.SHA)
	}
	state.LatestCommit = commit
	state.BranchETag = strings.TrimSpace(resp.Header.Get("ETag"))
	return commit, nil
}

func (m *managedSourceManager) ensureSource(ctx context.Context, commit string) (string, error) {
	if !validCommit(commit) {
		return "", fmt.Errorf("invalid DeltaScope source commit %q", commit)
	}
	if m.sourceValid(commit) {
		return "", nil
	}
	if err := os.MkdirAll(filepath.Join(m.root, "downloads"), 0o755); err != nil {
		return "", err
	}
	archive := filepath.Join(m.root, "downloads", commit+".zip")
	result, err := m.fetchArchive(ctx, commit, archive)
	if err != nil {
		return "", fmt.Errorf("download DeltaScope source %s: %w", commit, err)
	}
	defer os.Remove(archive)
	staging, err := os.MkdirTemp(m.root, ".source-stage-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	if err := m.extractArchive(archive, staging); err != nil {
		return "", fmt.Errorf("extract DeltaScope source %s: %w", commit, err)
	}
	extracted, err := findExtractedRoot(staging)
	if err != nil {
		return "", err
	}
	if err := validateSourceRoot(extracted); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(m.root, "sources"), 0o755); err != nil {
		return "", err
	}
	destination := m.sourceDir(commit)
	if err := os.RemoveAll(destination); err != nil {
		return "", err
	}
	if err := os.Rename(extracted, destination); err != nil {
		if m.sourceValid(commit) {
			return result.SHA256, nil
		}
		return "", fmt.Errorf("activate staged source directory: %w", err)
	}
	if err := validateSourceRoot(destination); err != nil {
		_ = os.RemoveAll(destination)
		return "", err
	}
	return result.SHA256, nil
}

func (m *managedSourceManager) activate(state *managedSourceState, commit, archiveSHA string) {
	if commit == state.ActiveCommit {
		state.StagedCommit = ""
		state.StagedArchiveSHA256 = ""
		return
	}
	if validCommit(state.ActiveCommit) && m.sourceValid(state.ActiveCommit) {
		state.PreviousCommit = state.ActiveCommit
		state.PreviousArchiveSHA256 = state.ActiveArchiveSHA256
	}
	state.ActiveCommit = commit
	state.ActiveArchiveSHA256 = archiveSHA
	state.StagedCommit = ""
	state.StagedArchiveSHA256 = ""
	if state.BadCommit != commit {
		state.BadCommit = ""
	}
}

func rollbackLaunchSource(info launchSource, startupErr error) (launchSource, error) {
	if !info.Managed || strings.TrimSpace(info.ManagerRoot) == "" {
		return launchSource{}, errors.New("source is not managed")
	}
	manager, err := newManagedSourceManager()
	if err != nil {
		return launchSource{}, err
	}
	manager.root = info.ManagerRoot
	state, err := manager.loadState()
	if err != nil {
		return launchSource{}, err
	}
	if state.ActiveCommit != info.Commit {
		return launchSource{}, errors.New("managed source state changed before rollback")
	}
	failed := state.ActiveCommit
	failedDir := manager.sourceDir(failed)
	state.BadCommit = failed
	state.LastError = "startup failed for " + failed + ": " + boundedError(startupErr)
	if manager.sourceValid(state.PreviousCommit) {
		state.ActiveCommit = state.PreviousCommit
		state.ActiveArchiveSHA256 = state.PreviousArchiveSHA256
		state.PreviousCommit = ""
		state.PreviousArchiveSHA256 = ""
		if err := manager.saveState(state); err != nil {
			return launchSource{}, err
		}
		_ = os.RemoveAll(failedDir)
		manager.prune(state)
		return manager.launchInfo(state.ActiveCommit, false, ""), nil
	}
	state.ActiveCommit = ""
	state.ActiveArchiveSHA256 = ""
	if err := manager.saveState(state); err != nil {
		return launchSource{}, err
	}
	_ = os.RemoveAll(failedDir)
	return launchSource{}, errors.New("new managed source failed startup and no previous known-good revision is available")
}

func pollManagedSource(ctx context.Context, info launchSource, stderr io.Writer) {
	manager, err := newManagedSourceManager()
	if err != nil {
		return
	}
	manager.root = info.ManagerRoot
	ticker := time.NewTicker(manager.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			commit, err := manager.stageIfNew(ctx)
			if err != nil {
				if stderr != nil {
					fmt.Fprintln(stderr, "DeltaScope Desktop update check:", err)
				}
				continue
			}
			if commit != "" && stderr != nil {
				fmt.Fprintf(stderr, "DeltaScope Desktop update staged: %s; restart DeltaScope to activate it.\n", commit)
			}
		}
	}
}

func (m *managedSourceManager) loadState() (managedSourceState, error) {
	state := managedSourceState{Schema: managedStateSchema}
	data, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return managedSourceState{}, fmt.Errorf("read managed DeltaScope state: %w", err)
	}
	if state.Schema != managedStateSchema {
		return managedSourceState{}, fmt.Errorf("unsupported managed DeltaScope state schema %q", state.Schema)
	}
	return state, nil
}

func (m *managedSourceManager) saveState(state managedSourceState) error {
	state.Schema = managedStateSchema
	if err := os.MkdirAll(m.root, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(m.root, ".state-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := download.ReplaceFile(tmpPath, m.statePath()); err != nil {
		return err
	}
	committed = true
	return nil
}

func (m *managedSourceManager) launchInfo(commit string, updated bool, warning string) launchSource {
	return launchSource{
		Root:           m.sourceDir(commit),
		EnvironmentDir: filepath.Join(m.root, "python-env"),
		Commit:         commit,
		ManagerRoot:    m.root,
		Managed:        true,
		Updated:        updated,
		Warning:        warning,
	}
}

func (m *managedSourceManager) sourceDir(commit string) string {
	return filepath.Join(m.root, "sources", commit)
}

func (m *managedSourceManager) sourceValid(commit string) bool {
	if !validCommit(commit) {
		return false
	}
	return validateSourceRoot(m.sourceDir(commit)) == nil
}

func (m *managedSourceManager) statePath() string { return filepath.Join(m.root, "state.json") }

func (m *managedSourceManager) timestamp() string {
	return m.now().UTC().Format(time.RFC3339)
}

func (m *managedSourceManager) prune(state managedSourceState) {
	keep := map[string]bool{}
	for _, commit := range []string{state.ActiveCommit, state.PreviousCommit, state.StagedCommit} {
		if validCommit(commit) {
			keep[commit] = true
		}
	}
	entries, err := os.ReadDir(filepath.Join(m.root, "sources"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && !keep[entry.Name()] {
			_ = os.RemoveAll(filepath.Join(m.root, "sources", entry.Name()))
		}
	}
}

func findExtractedRoot(staging string) (string, error) {
	entries, err := os.ReadDir(staging)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(staging, entry.Name())
		if root, err := project.FindRoot(candidate); err == nil {
			return root, nil
		}
	}
	return "", errors.New("downloaded DeltaScope archive does not contain a standalone source root")
}

func validateSourceRoot(root string) error {
	resolved, err := project.FindRoot(root)
	if err != nil {
		return err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	resolvedAbs, err := filepath.Abs(resolved)
	if err != nil {
		return err
	}
	if resolvedAbs != rootAbs {
		return errors.New("managed DeltaScope archive resolved an unexpected source root")
	}
	contractPath := filepath.Join(rootAbs, "deltascope", "runtime-contract.json")
	data, err := os.ReadFile(contractPath)
	if err != nil {
		return err
	}
	var contract struct {
		Schema  string `json:"schema"`
		Runtime struct {
			Language string `json:"language"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal(data, &contract); err != nil {
		return fmt.Errorf("parse DeltaScope runtime contract: %w", err)
	}
	if contract.Schema != "omega.deltascope.runtime-contract.v1" || contract.Runtime.Language != "python" {
		return errors.New("downloaded source has an unsupported DeltaScope runtime contract")
	}
	for _, required := range []string{
		filepath.Join(rootAbs, "deltascope", "requirements.txt"),
		filepath.Join(rootAbs, "tools", "security", "deltascope.py"),
		filepath.Join(rootAbs, "desktop", "assets", "deltascope.ico"),
	} {
		if info, err := os.Stat(required); err != nil || info.IsDir() {
			return fmt.Errorf("downloaded DeltaScope source is missing %s", required)
		}
	}
	return nil
}

func validCommit(value string) bool {
	return commitPattern.MatchString(strings.ToLower(strings.TrimSpace(value)))
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 500 {
		value = value[:500]
	}
	return value
}
