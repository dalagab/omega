package backend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dalagab/omega/deltascope-desktop/internal/processutil"
)

var readyURLPattern = regexp.MustCompile(`Omega security research workbench:\s*(http://[^\s]+)`) // loopback URL printed by Python server

type Supervisor struct {
	Root           string
	PythonHint     string
	StartupTimeout time.Duration
	Stdout         io.Writer
	Stderr         io.Writer
	BackendArgs    []string
}

type Process struct {
	cmd  *exec.Cmd
	URL  *url.URL
	done chan error
	once sync.Once
}

func (s Supervisor) Start(ctx context.Context) (*Process, error) {
	timeout := s.StartupTimeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	runtimeManager := Runtime{Root: s.Root, PythonHint: s.PythonHint, Stdout: s.Stdout, Stderr: s.Stderr, Logf: func(format string, args ...any) {
		if s.Stderr != nil {
			_, _ = fmt.Fprintf(s.Stderr, "DeltaScope Desktop: "+format+"\n", args...)
		}
	}}
	python, err := runtimeManager.Ensure(ctx)
	if err != nil {
		return nil, err
	}

	args := []string{s.Root + string(os.PathSeparator) + "tools" + string(os.PathSeparator) + "security" + string(os.PathSeparator) + "deltascope.py", "serve-online", "--host", "127.0.0.1", "--port", "0", "--no-browser"}
	args = append(args, s.BackendArgs...)
	cmd := exec.Command(python, args...)
	cmd.Dir = s.Root
	cmd.Env = append(os.Environ(), "OMEGA_DELTASCOPE_DESKTOP=1")
	processutil.HideWindow(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	process := &Process{cmd: cmd, done: make(chan error, 1)}
	go func() { process.done <- cmd.Wait() }()
	if s.Stdout == nil {
		s.Stdout = os.Stdout
	}
	if s.Stderr == nil {
		s.Stderr = os.Stderr
	}
	go func() { _, _ = io.Copy(s.Stdout, stdout) }()

	ready := make(chan *url.URL, 1)
	go scanBackendStderr(stderr, s.Stderr, ready)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case backendURL := <-ready:
		process.URL = backendURL
		return process, nil
	case err := <-process.done:
		if err == nil {
			err = errors.New("backend exited before reporting its URL")
		}
		return nil, fmt.Errorf("DeltaScope backend startup failed: %w", err)
	case <-timer.C:
		_ = process.Stop(context.Background())
		return nil, fmt.Errorf("DeltaScope backend did not become ready within %s", timeout)
	case <-ctx.Done():
		_ = process.Stop(context.Background())
		return nil, ctx.Err()
	}
}

func scanBackendStderr(reader io.Reader, destination io.Writer, ready chan<- *url.URL) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	sent := false
	for scanner.Scan() {
		line := scanner.Text()
		if destination != nil {
			_, _ = fmt.Fprintln(destination, line)
		}
		if sent {
			continue
		}
		match := readyURLPattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(match[1]))
		if err == nil && parsed.Hostname() == "127.0.0.1" {
			ready <- parsed
			sent = true
		}
	}
}

func ParseReadyURL(line string) (*url.URL, bool) {
	match := readyURLPattern.FindStringSubmatch(line)
	if len(match) != 2 {
		return nil, false
	}
	parsed, err := url.Parse(match[1])
	return parsed, err == nil
}

func (p *Process) Done() <-chan error { return p.done }

func (p *Process) Stop(ctx context.Context) error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	var stopErr error
	p.once.Do(func() {
		if runtime.GOOS != "windows" {
			_ = p.cmd.Process.Signal(os.Interrupt)
			select {
			case <-p.done:
				return
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
			}
		}
		stopErr = p.cmd.Process.Kill()
	})
	return stopErr
}
