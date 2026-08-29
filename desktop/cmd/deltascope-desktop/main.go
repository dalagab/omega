package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dalagab/omega/deltascope-desktop/internal/backend"
	"github.com/dalagab/omega/deltascope-desktop/internal/download"
	"github.com/dalagab/omega/deltascope-desktop/internal/host"
	"github.com/dalagab/omega/deltascope-desktop/internal/project"
	"github.com/dalagab/omega/deltascope-desktop/internal/window"
)

var version = "4.21.12-dev"
var buildFlavor = "console"

type stringList []string

func (s *stringList) String() string         { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error { *s = append(*s, value); return nil }

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	command := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	switch command {
	case "run":
		return runDesktop(args)
	case "fetch":
		return runFetch(args)
	case "doctor":
		return runDoctor(args)
	case "version", "--version", "-version":
		fmt.Println(version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q. Use run, fetch, doctor, or version.\n", command)
		return 2
	}
}

func runDesktop(args []string) int {
	passthroughAt := len(args)
	for i, arg := range args {
		if arg == "--" {
			passthroughAt = i
			break
		}
	}
	shellArgs := args[:passthroughAt]
	backendArgs := []string{}
	if passthroughAt < len(args) {
		backendArgs = append(backendArgs, args[passthroughAt+1:]...)
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	rootFlag := fs.String("root", "", "DeltaScope source root; auto-detected by default")
	pythonFlag := fs.String("python", "", "Python 3.10+ executable override")
	portFlag := fs.Int("port", 8765, "Go loopback front-door port; default 8765 preserves DeltaScope browser/localStorage origin; 0 chooses an available port")
	noWindow := fs.Bool("no-window", false, "Host DeltaScope without opening an app window")
	systemBrowser := fs.Bool("system-browser", false, "Use the normal system browser instead of the native DeltaScope window")
	iconFlag := fs.String("icon", "", "Desktop icon override (.ico or <=256px .png on Windows)")
	width := fs.Int("width", 1600, "App window width")
	height := fs.Int("height", 1000, "App window height")
	if err := fs.Parse(shellArgs); err != nil {
		return 2
	}
	logFile, logPath := openDesktopLog()
	if logFile != nil {
		defer logFile.Close()
	}
	stdout, stderr := desktopWriters(logFile)
	if logPath != "" {
		fmt.Fprintln(stderr, "DeltaScope Desktop log:", logPath)
	}
	root, err := resolveRoot(*rootFlag)
	if err != nil {
		fmt.Fprintln(stderr, "DeltaScope Desktop:", err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	front, err := host.Start(*portFlag)
	if err != nil && *portFlag == 8765 && !flagWasSet(fs, "port") {
		fmt.Fprintln(stderr, "DeltaScope Desktop: port 8765 is busy; using an ephemeral front-door port for this session:", err)
		front, err = host.Start(0)
	}
	if err != nil {
		fmt.Fprintln(stderr, "DeltaScope Desktop: start loopback host:", err)
		return 2
	}
	defer front.Close()
	fmt.Fprintln(stderr, "DeltaScope Desktop front door:", front.URL())

	var appWindow *window.Process
	preparedPython := ""
	if !*noWindow && !*systemBrowser {
		runtimeManager := backend.Runtime{Root: root, PythonHint: *pythonFlag, Stdout: stdout, Stderr: stderr, Logf: func(format string, args ...any) {
			fmt.Fprintf(stderr, "DeltaScope Desktop: "+format+"\n", args...)
		}}
		preparedPython, err = runtimeManager.EnsureDesktop(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "DeltaScope Desktop: native window runtime unavailable; browser fallback will be used:", err)
		}
	}
	if !*noWindow {
		cache, _ := os.UserCacheDir()
		profile := filepath.Join(cache, "Omega", "DeltaScope", "desktop-browser")
		appWindow, err = window.Launch(ctx, window.Options{URL: front.URL(), Title: "DeltaScope", ProfileDir: profile, Width: *width, Height: *height, SystemBrowser: *systemBrowser, Python: preparedPython, Root: root, Icon: *iconFlag, Stdout: stdout, Stderr: stderr})
		if err != nil {
			fmt.Fprintln(stderr, "DeltaScope Desktop: window launch failed; continuing headless:", err)
		} else {
			fmt.Fprintf(stderr, "DeltaScope Desktop window: %s\n", appWindow.Engine)
		}
	}

	supervisor := backend.Supervisor{Root: root, PythonHint: *pythonFlag, StartupTimeout: 90 * time.Second, Stdout: stdout, Stderr: stderr, BackendArgs: backendArgs}
	pythonProcess, err := supervisor.Start(ctx)
	if err != nil {
		front.SetError(err.Error())
		fmt.Fprintln(stderr, "DeltaScope Desktop:", err)
		if appWindow != nil && appWindow.Dedicated {
			_ = appWindow.Wait()
		}
		return 2
	}
	defer pythonProcess.Stop(context.Background())
	front.SetBackend(pythonProcess.URL)
	fmt.Fprintln(stderr, "DeltaScope Python backend:", pythonProcess.URL.String())

	windowDone := make(chan error, 1)
	if appWindow != nil && appWindow.Dedicated {
		go func() { windowDone <- appWindow.Wait() }()
	}
	select {
	case <-ctx.Done():
		return 0
	case err := <-pythonProcess.Done():
		if err != nil {
			front.SetError("Python backend exited: " + err.Error())
			fmt.Fprintln(stderr, "DeltaScope Desktop: Python backend exited:", err)
			if appWindow != nil && appWindow.Dedicated {
				select {
				case <-windowDone:
				case <-time.After(3 * time.Second):
				}
			}
			return 1
		}
		return 0
	case <-windowDone:
		return 0
	}
}

func runFetch(args []string) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	source := fs.String("url", "", "HTTPS URL")
	destination := fs.String("out", "", "Destination path")
	expected := fs.String("sha256", "", "Expected SHA-256")
	maxMB := fs.Int64("max-mb", 512, "Maximum download size in MiB")
	allowHTTP := fs.Bool("allow-http", false, "Allow plain HTTP (disabled by default)")
	extractTo := fs.String("extract-to", "", "Safely extract .zip or .tar.gz after download")
	var hosts stringList
	fs.Var(&hosts, "allow-host", "Restrict source/redirect hosts; repeat as needed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*source) == "" || strings.TrimSpace(*destination) == "" {
		fmt.Fprintln(os.Stderr, "fetch requires --url and --out")
		return 2
	}
	manager := download.Manager{UserAgent: "DeltaScope-Desktop/" + version}
	result, err := manager.Fetch(context.Background(), download.Request{URL: *source, Destination: *destination, SHA256: *expected, MaxBytes: *maxMB << 20, AllowHTTP: *allowHTTP, AllowedHosts: hosts})
	if err != nil {
		fmt.Fprintln(os.Stderr, "DeltaScope fetch:", err)
		return 1
	}
	fmt.Printf("%s\t%d\t%s\n", result.SHA256, result.Bytes, result.Path)
	if *extractTo != "" {
		lower := strings.ToLower(result.Path)
		switch {
		case strings.HasSuffix(lower, ".zip"):
			err = download.ExtractZip(result.Path, *extractTo, download.ExtractOptions{})
		case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
			err = download.ExtractTarGz(result.Path, *extractTo, download.ExtractOptions{})
		default:
			err = errors.New("--extract-to supports .zip, .tar.gz, and .tgz")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "DeltaScope extract:", err)
			return 1
		}
	}
	return 0
}

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	rootFlag := fs.String("root", "", "DeltaScope source root")
	pythonFlag := fs.String("python", "", "Python executable override")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	root, err := resolveRoot(*rootFlag)
	if err != nil {
		fmt.Println("root: ERROR -", err)
		return 1
	}
	fmt.Println("version:", version)
	fmt.Println("root:", root)
	runtimeManager := backend.Runtime{Root: root, PythonHint: *pythonFlag}
	py, pyErr := runtimeManager.Discover(context.Background())
	if pyErr != nil {
		fmt.Println("python: ERROR -", pyErr)
	} else {
		fmt.Println("python:", py.Path, strings.Join(py.Prefix, " "))
	}
	if pyErr == nil && window.NativeAvailable(context.Background(), py.Path, root) {
		fmt.Println("native window: pywebview available")
	} else {
		fmt.Println("native window: not currently available")
	}
	if engine, ok := window.DetectEngine(); ok {
		fmt.Println("Chromium fallback:", engine)
	} else {
		fmt.Println("Chromium fallback: unavailable; system-browser fallback remains")
	}
	fmt.Println("app requirements:", filepath.Join(root, "deltascope", "requirements.txt"))
	fmt.Println("desktop requirements:", filepath.Join(root, "desktop", "requirements.txt"))
	if icon := window.ResolveIcon(root, ""); icon != "" {
		fmt.Println("desktop icon:", icon)
	} else {
		fmt.Println("desktop icon: none found; use --icon or add desktop/assets/deltascope.ico")
	}
	if pyErr != nil {
		return 1
	}
	return 0
}

func openDesktopLog() (*os.File, string) {
	cache, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(cache) == "" {
		return nil, ""
	}
	dir := filepath.Join(cache, "Omega", "DeltaScope", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, ""
	}
	path := filepath.Join(dir, "desktop.log")
	if info, err := os.Stat(path); err == nil && info.Size() > 5*1024*1024 {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, ""
	}
	_, _ = fmt.Fprintf(file, "\n[%s] DeltaScope Desktop %s starting (%s build)\n", time.Now().Format(time.RFC3339), version, buildFlavor)
	return file, path
}

func desktopWriters(logFile *os.File) (io.Writer, io.Writer) {
	if buildFlavor == "gui" {
		if logFile != nil {
			return logFile, logFile
		}
		return io.Discard, io.Discard
	}
	if logFile == nil {
		return os.Stdout, os.Stderr
	}
	return io.MultiWriter(os.Stdout, logFile), io.MultiWriter(os.Stderr, logFile)
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(item *flag.Flag) {
		if item.Name == name {
			found = true
		}
	})
	return found
}

func resolveRoot(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return project.FindRoot(explicit)
	}
	if executable, err := os.Executable(); err == nil {
		if root, findErr := project.FindRoot(filepath.Dir(executable)); findErr == nil {
			return root, nil
		}
	}
	return project.FindRoot("")
}
