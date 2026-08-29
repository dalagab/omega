package window

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/dalagab/omega/deltascope-desktop/internal/processutil"
)

type Options struct {
	URL           string
	Title         string
	ProfileDir    string
	Width         int
	Height        int
	SystemBrowser bool
	Python        string
	Root          string
	Icon          string
	Stdout        io.Writer
	Stderr        io.Writer
}

type Process struct {
	cmd       *exec.Cmd
	Dedicated bool
	Engine    string
}

func DetectEngine() (string, bool) {
	path, ok := findChromiumEngine()
	return path, ok
}

func NativeAvailable(ctx context.Context, python, root string) bool {
	if runtime.GOOS != "windows" || python == "" || root == "" {
		return false
	}
	helper := filepath.Join(root, "desktop", "window_host.py")
	if _, err := os.Stat(helper); err != nil {
		return false
	}
	cmd := exec.CommandContext(ctx, python, helper, "--probe")
	cmd.Dir = root
	processutil.HideWindow(cmd)
	return cmd.Run() == nil
}

func ResolveIcon(root, explicit string) string {
	if explicit != "" {
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit
		}
	}
	for _, candidate := range []string{
		filepath.Join(root, "desktop", "assets", "deltascope.ico"),
		filepath.Join(root, "desktop", "assets", "deltascope.png"),
		filepath.Join(root, "images", "title-icon.png"),
		filepath.Join(root, "images", "icon.png"),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func Launch(ctx context.Context, opts Options) (*Process, error) {
	if opts.URL == "" {
		return nil, errors.New("window URL is required")
	}
	if opts.Width <= 0 {
		opts.Width = 1600
	}
	if opts.Height <= 0 {
		opts.Height = 1000
	}
	if opts.ProfileDir == "" {
		cache, _ := os.UserCacheDir()
		opts.ProfileDir = filepath.Join(cache, "Omega", "DeltaScope", "desktop-browser")
	}
	if err := os.MkdirAll(opts.ProfileDir, 0o755); err != nil {
		return nil, err
	}

	if !opts.SystemBrowser && NativeAvailable(ctx, opts.Python, opts.Root) {
		helper := filepath.Join(opts.Root, "desktop", "window_host.py")
		args := []string{
			helper,
			"--url", opts.URL,
			"--title", opts.Title,
			"--storage-path", opts.ProfileDir,
			"--width", strconv.Itoa(opts.Width),
			"--height", strconv.Itoa(opts.Height),
		}
		if icon := ResolveIcon(opts.Root, opts.Icon); icon != "" {
			args = append(args, "--icon", icon)
		}
		cmd := exec.CommandContext(ctx, opts.Python, args...)
		cmd.Dir = opts.Root
		cmd.Stdout = opts.Stdout
		cmd.Stderr = opts.Stderr
		processutil.HideWindow(cmd)
		if err := cmd.Start(); err == nil {
			return &Process{cmd: cmd, Dedicated: true, Engine: "pywebview/edgechromium"}, nil
		}
	}

	if !opts.SystemBrowser {
		if engine, ok := findChromiumEngine(); ok {
			args := []string{
				"--app=" + opts.URL,
				"--user-data-dir=" + opts.ProfileDir,
				"--no-first-run",
				"--no-default-browser-check",
				"--disable-sync",
				"--disable-extensions",
				"--disable-background-mode",
				"--window-size=" + strconv.Itoa(opts.Width) + "," + strconv.Itoa(opts.Height),
			}
			cmd := exec.CommandContext(ctx, engine, args...)
			processutil.HideWindow(cmd)
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			return &Process{cmd: cmd, Dedicated: true, Engine: engine + " (app-mode fallback)"}, nil
		}
	}
	cmd, err := defaultBrowserCommand(ctx, opts.URL)
	if err != nil {
		return nil, err
	}
	processutil.HideWindow(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Process{cmd: cmd, Dedicated: false, Engine: "system-browser"}, nil
}

func (p *Process) Wait() error {
	if p == nil || p.cmd == nil {
		return nil
	}
	return p.cmd.Wait()
}

func findChromiumEngine() (string, bool) {
	candidates := []string{}
	switch runtime.GOOS {
	case "windows":
		for _, name := range []string{"msedge.exe", "chrome.exe"} {
			if path, err := exec.LookPath(name); err == nil {
				return path, true
			}
		}
		for _, base := range []string{os.Getenv("PROGRAMFILES(X86)"), os.Getenv("PROGRAMFILES"), os.Getenv("LOCALAPPDATA")} {
			if base == "" {
				continue
			}
			candidates = append(candidates,
				filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"),
			)
		}
	case "darwin":
		candidates = append(candidates,
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		)
	default:
		for _, name := range []string{"microsoft-edge", "microsoft-edge-stable", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
			if path, err := exec.LookPath(name); err == nil {
				return path, true
			}
		}
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

func defaultBrowserCommand(ctx context.Context, target string) (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "windows":
		return exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", target), nil
	case "darwin":
		return exec.CommandContext(ctx, "open", target), nil
	default:
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return nil, fmt.Errorf("no Chromium app-window engine and no xdg-open fallback: %w", err)
		}
		return exec.CommandContext(ctx, "xdg-open", target), nil
	}
}
