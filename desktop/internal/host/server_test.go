package host

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestShellTransitionsToReverseProxy(t *testing.T) {
	shell, err := Start(0)
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Close()
	response, err := http.Get(shell.URL())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "Starting DeltaScope") {
		t.Fatalf("unexpected startup page: %s", body)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-DeltaScope-Desktop") != "1" {
			t.Error("desktop header missing")
		}
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	shell.SetBackend(target)
	response, err = http.Get(shell.URL() + "some/path")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "backend-ok" {
		t.Fatalf("proxy returned %q", body)
	}
}
