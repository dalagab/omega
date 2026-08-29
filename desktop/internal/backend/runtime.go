package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/dalagab/omega/deltascope-desktop/internal/processutil"
)

type PythonCommand struct {
	Path   string
	Prefix []string
}

type Runtime struct {
	Root       string
	PythonHint string
	Stdout     io.Writer
	Stderr     io.Writer
	Logf       func(string, ...any)
}

func (r Runtime) Ensure(ctx context.Context) (string, error) {
	requirements := filepath.Join(r.Root, "deltascope", "requirements.txt")
	entrypoint := filepath.Join(r.Root, "tools", "security", "deltascope.py")
	if !isFile(requirements) || !isFile(entrypoint) {
		return "", errors.New("DeltaScope runtime files are incomplete")
	}
	venvDir := filepath.Join(r.Root, ".deltascope-venv")
	venvPython := venvPythonPath(venvDir)
	marker := filepath.Join(venvDir, ".deltascope-requirements.sha256")
	digest, err := fileDigest(requirements)
	if err != nil {
		return "", err
	}
	if isFile(venvPython) && markerMatches(marker, digest) {
		return venvPython, nil
	}

	base, err := r.discoverPython(ctx)
	if err != nil {
		return "", err
	}
	if !isFile(venvPython) {
		r.log("creating private Python environment at %s", venvDir)
		if err := r.runPython(ctx, r.Root, base, "-m", "venv", venvDir); err != nil {
			return "", fmt.Errorf("create DeltaScope Python environment: %w", err)
		}
	}
	r.log("installing pinned DeltaScope Python requirements")
	cmd := exec.CommandContext(ctx, venvPython, "-m", "pip", "install", "--disable-pip-version-check", "-r", requirements)
	cmd.Dir = r.Root
	cmd.Stdout = r.stdout()
	cmd.Stderr = r.stderr()
	processutil.HideWindow(cmd)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("install DeltaScope requirements: %w", err)
	}
	if err := os.WriteFile(marker, []byte(digest+"\n"), 0o644); err != nil {
		return "", err
	}
	return venvPython, nil
}

func (r Runtime) EnsureDesktop(ctx context.Context) (string, error) {
	python, err := r.Ensure(ctx)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		return python, nil
	}
	requirements := filepath.Join(r.Root, "desktop", "requirements.txt")
	if !isFile(requirements) {
		return python, nil
	}
	marker := filepath.Join(r.Root, ".deltascope-venv", ".deltascope-desktop-requirements.sha256")
	digest, err := fileDigest(requirements)
	if err != nil {
		return "", err
	}
	if markerMatches(marker, digest) {
		return python, nil
	}
	r.log("installing pinned DeltaScope desktop Python requirements")
	cmd := exec.CommandContext(ctx, python, "-m", "pip", "install", "--disable-pip-version-check", "-r", requirements)
	cmd.Dir = r.Root
	cmd.Stdout = r.stdout()
	cmd.Stderr = r.stderr()
	processutil.HideWindow(cmd)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("install DeltaScope desktop requirements: %w", err)
	}
	if err := os.WriteFile(marker, []byte(digest+"\n"), 0o644); err != nil {
		return "", err
	}
	return python, nil
}

func (r Runtime) Discover(ctx context.Context) (PythonCommand, error) {
	return r.discoverPython(ctx)
}

func (r Runtime) discoverPython(ctx context.Context) (PythonCommand, error) {
	candidates := []PythonCommand{}
	if hint := strings.TrimSpace(r.PythonHint); hint != "" {
		candidates = append(candidates, PythonCommand{Path: hint})
	}
	if hint := strings.TrimSpace(os.Getenv("DELTASCOPE_PYTHON")); hint != "" {
		candidates = append(candidates, PythonCommand{Path: hint})
	}
	candidates = append(candidates, bundledPythonCandidates(r.Root)...)
	if runtime.GOOS == "windows" {
		candidates = append(candidates, PythonCommand{Path: "py", Prefix: []string{"-3"}}, PythonCommand{Path: "python"})
	} else {
		candidates = append(candidates, PythonCommand{Path: "python3"}, PythonCommand{Path: "python"})
	}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		key := candidate.Path + "\x00" + strings.Join(candidate.Prefix, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		resolved := candidate.Path
		if !filepath.IsAbs(resolved) {
			found, err := exec.LookPath(resolved)
			if err != nil {
				continue
			}
			resolved = found
		} else if !isFile(resolved) {
			continue
		}
		candidate.Path = resolved
		if pythonSupported(ctx, candidate) {
			return candidate, nil
		}
	}
	return PythonCommand{}, errors.New("DeltaScope requires Python 3.10+ or a bundled desktop runtime")
}

func bundledPythonCandidates(root string) []PythonCommand {
	if runtime.GOOS == "windows" {
		return []PythonCommand{
			{Path: filepath.Join(root, "runtime", "python", "python.exe")},
			{Path: filepath.Join(root, "desktop", "runtime", "python", "python.exe")},
		}
	}
	return []PythonCommand{
		{Path: filepath.Join(root, "runtime", "python", "bin", "python3")},
		{Path: filepath.Join(root, "desktop", "runtime", "python", "bin", "python3")},
	}
}

func pythonSupported(ctx context.Context, command PythonCommand) bool {
	args := append(append([]string{}, command.Prefix...), "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)")
	cmd := exec.CommandContext(ctx, command.Path, args...)
	processutil.HideWindow(cmd)
	return cmd.Run() == nil
}

func (r Runtime) runPython(ctx context.Context, dir string, command PythonCommand, args ...string) error {
	full := append(append([]string{}, command.Prefix...), args...)
	cmd := exec.CommandContext(ctx, command.Path, full...)
	cmd.Dir = dir
	cmd.Stdout = r.stdout()
	cmd.Stderr = r.stderr()
	processutil.HideWindow(cmd)
	return cmd.Run()
}

func (r Runtime) stdout() io.Writer {
	if r.Stdout != nil {
		return r.Stdout
	}
	return os.Stdout
}

func (r Runtime) stderr() io.Writer {
	if r.Stderr != nil {
		return r.Stderr
	}
	return os.Stderr
}

func venvPythonPath(venv string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(venv, "Scripts", "python.exe")
	}
	return filepath.Join(venv, "bin", "python")
}

func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func markerMatches(path, expected string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(data)) == expected
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (r Runtime) log(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}
