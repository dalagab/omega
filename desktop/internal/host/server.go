package host

import (
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

type State struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
	Backend string `json:"backend,omitempty"`
}

type Server struct {
	mu       sync.RWMutex
	state    State
	proxy    *httputil.ReverseProxy
	server   *http.Server
	listener net.Listener
}

func Start(port int) (*Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	shell := &Server{listener: listener, state: State{Phase: "starting", Message: "Starting DeltaScope Python backend…"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/__deltascope/shell/status", shell.statusHandler)
	mux.HandleFunc("/__deltascope/shell/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", shell.proxyHandler)
	shell.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = shell.server.Serve(listener) }()
	return shell, nil
}

func (s *Server) URL() string { return "http://" + s.listener.Addr().String() + "/" }

func (s *Server) SetBackend(target *url.URL) {
	proxy := httputil.NewSingleHostReverseProxy(target)
	original := proxy.Director
	proxy.Director = func(req *http.Request) {
		original(req)
		req.Header.Set("X-DeltaScope-Desktop", "1")
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s.SetError("Python backend became unavailable: " + err.Error())
		s.renderShell(w)
	}
	s.mu.Lock()
	s.proxy = proxy
	s.state = State{Phase: "ready", Message: "DeltaScope is ready", Backend: target.String()}
	s.mu.Unlock()
}

func (s *Server) SetError(message string) {
	s.mu.Lock()
	s.state = State{Phase: "error", Message: message}
	s.proxy = nil
	s.mu.Unlock()
}

func (s *Server) Close() error {
	return s.server.Close()
}

func (s *Server) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(s.State())
}

func (s *Server) proxyHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	proxy := s.proxy
	s.mu.RUnlock()
	if proxy == nil {
		s.renderShell(w)
		return
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) renderShell(w http.ResponseWriter) {
	state := s.State()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	status := "Starting DeltaScope"
	if state.Phase == "error" {
		status = "DeltaScope could not start"
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DeltaScope</title><style>
html,body{height:100%%;margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;background:#f4f4f4;color:#161616}.shell{height:100%%;display:grid;place-items:center}.card{width:min(640px,calc(100vw - 48px));background:white;border:1px solid #e0e0e0;padding:32px;box-shadow:0 8px 28px #0001}.eyebrow{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#6f6f6f}.bar{height:3px;background:#e0e0e0;margin-top:22px;overflow:hidden}.bar:after{content:"";display:block;width:35%%;height:100%%;background:#0f62fe;animation:move 1.1s infinite ease-in-out}@keyframes move{from{transform:translateX(-100%%)}to{transform:translateX(390%%)}}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#525252;word-break:break-word}</style></head><body><main class="shell"><section class="card"><div class="eyebrow">DeltaScope Desktop</div><h1>%s</h1><p><code>%s</code></p>%s</section></main><script>
%s
</script></body></html>`, html.EscapeString(status), html.EscapeString(state.Message), shellProgress(state.Phase), shellScript(state.Phase))
}

func shellProgress(phase string) string {
	if phase == "starting" {
		return `<div class="bar" aria-label="Starting"></div>`
	}
	return ""
}

func shellScript(phase string) string {
	if phase != "starting" {
		return ""
	}
	return `setInterval(async()=>{try{const r=await fetch('/__deltascope/shell/status',{cache:'no-store'});const s=await r.json();if(s.phase==='ready')location.reload();if(s.phase==='error')location.reload();}catch(e){}},500);`
}
