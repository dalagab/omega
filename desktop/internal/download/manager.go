package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultMaxBytes int64 = 512 << 20

// Manager is DeltaScope Desktop's reusable download primitive. It is intentionally
// not exposed as a browser HTTP endpoint: callers are trusted local shell code or
// explicit CLI commands.
type Manager struct {
	Client    *http.Client
	CacheDir  string
	UserAgent string
}

type Request struct {
	URL          string
	Destination  string
	SHA256       string
	MaxBytes     int64
	AllowHTTP    bool
	AllowedHosts []string
}

type Result struct {
	Path      string
	SHA256    string
	Bytes     int64
	FromCache bool
}

func (m Manager) Fetch(ctx context.Context, req Request) (Result, error) {
	parsed, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil {
		return Result{}, fmt.Errorf("parse download URL: %w", err)
	}
	if parsed.Scheme != "https" && !(req.AllowHTTP && parsed.Scheme == "http") {
		return Result{}, fmt.Errorf("download URL must use HTTPS: %s", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return Result{}, errors.New("download URL has no host")
	}
	allowed := normalizeHosts(req.AllowedHosts)
	if len(allowed) > 0 && !hostAllowed(parsed.Hostname(), allowed) {
		return Result{}, fmt.Errorf("download host %q is not allowed", parsed.Hostname())
	}

	expected := strings.ToLower(strings.TrimSpace(req.SHA256))
	if expected != "" {
		if len(expected) != 64 {
			return Result{}, errors.New("expected SHA-256 must be 64 hexadecimal characters")
		}
		if _, err := hex.DecodeString(expected); err != nil {
			return Result{}, errors.New("expected SHA-256 is not hexadecimal")
		}
	}

	destination := strings.TrimSpace(req.Destination)
	if destination == "" {
		if m.CacheDir == "" {
			return Result{}, errors.New("destination or cache directory is required")
		}
		key := sha256.Sum256([]byte(parsed.String()))
		destination = filepath.Join(m.CacheDir, hex.EncodeToString(key[:])+".bin")
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return Result{}, err
	}
	if expected != "" {
		if got, size, ok := verifiedExisting(destination, expected); ok {
			return Result{Path: destination, SHA256: got, Bytes: size, FromCache: true}, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return Result{}, err
	}

	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	client := m.Client
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		client = &http.Client{Transport: transport, Timeout: 10 * time.Minute}
	}
	originalCheck := client.CheckRedirect
	clone := *client
	clone.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if next.URL.Scheme != "https" && !(req.AllowHTTP && next.URL.Scheme == "http") {
			return errors.New("redirect downgraded transport")
		}
		if len(allowed) > 0 && !hostAllowed(next.URL.Hostname(), allowed) {
			return fmt.Errorf("redirect host %q is not allowed", next.URL.Hostname())
		}
		if originalCheck != nil {
			return originalCheck(next, via)
		}
		return nil
	}
	client = &clone

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Result{}, err
	}
	agent := strings.TrimSpace(m.UserAgent)
	if agent == "" {
		agent = "DeltaScope-Desktop/4.21.12"
	}
	httpReq.Header.Set("User-Agent", agent)
	resp, err := client.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("download %s: %w", parsed.Hostname(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{}, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes && resp.ContentLength >= 0 {
		return Result{}, fmt.Errorf("download is %d bytes; limit is %d", resp.ContentLength, maxBytes)
	}

	tmp, err := os.CreateTemp(filepath.Dir(destination), ".deltascope-download-*.part")
	if err != nil {
		return Result{}, err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	digest := sha256.New()
	written, err := copyBounded(tmp, resp.Body, digest, maxBytes)
	if err != nil {
		return Result{}, err
	}
	got := hex.EncodeToString(digest.Sum(nil))
	if expected != "" && got != expected {
		return Result{}, fmt.Errorf("SHA-256 mismatch: expected %s, got %s", expected, got)
	}
	if err := tmp.Sync(); err != nil {
		return Result{}, err
	}
	if err := tmp.Close(); err != nil {
		return Result{}, err
	}
	if err := replaceFile(tmpName, destination); err != nil {
		return Result{}, err
	}
	committed = true
	return Result{Path: destination, SHA256: got, Bytes: written}, nil
}

func copyBounded(dst io.Writer, src io.Reader, digest hash.Hash, maxBytes int64) (int64, error) {
	limited := &io.LimitedReader{R: src, N: maxBytes + 1}
	n, err := io.Copy(io.MultiWriter(dst, digest), limited)
	if err != nil {
		return n, err
	}
	if n > maxBytes {
		return n, fmt.Errorf("download exceeded %d-byte limit", maxBytes)
	}
	return n, nil
}

func verifiedExisting(path, expected string) (string, int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false
	}
	defer f.Close()
	digest := sha256.New()
	n, err := io.Copy(digest, f)
	if err != nil {
		return "", 0, false
	}
	got := hex.EncodeToString(digest.Sum(nil))
	return got, n, got == expected
}

func normalizeHosts(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func hostAllowed(host string, allowed map[string]struct{}) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	_, ok := allowed[host]
	return ok
}
