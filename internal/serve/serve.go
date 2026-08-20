package serve

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/soffchen/oixproxy/internal/dialer"
	"github.com/soffchen/oixproxy/internal/inbound"
)

type Mapping struct {
	Node dialer.Node
	Port int
	ln   net.Listener
}

type DialFunc func(ctx context.Context, n dialer.Node, network, host string, port uint16) (net.Conn, error)

type Extra struct {
	Node dialer.Node
	Addr string
}

type Server struct {
	Listen        string
	Bind          string
	BasePort      int
	User          string
	Pass          string
	Nodes         []dialer.Node
	Extras        []Extra
	Template      []byte
	Dial          DialFunc
	OpenSurgePath string
	ProcessName   string
	ProcessPath   string

	mu      sync.Mutex
	maps    []Mapping
	httpLn  net.Listener
	httpSrv *http.Server
}

func (s *Server) Mappings() []Mapping {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Mapping, len(s.maps))
	copy(out, s.maps)
	return out
}

func (s *Server) Start() error {
	if s.Bind == "" {
		s.Bind = "127.0.0.1"
	}
	if s.BasePort == 0 {
		s.BasePort = 7200
	}
	dial := s.Dial
	if dial == nil {
		dial = dialer.Dial
	}
	s.maps = make([]Mapping, 0, len(s.Nodes))
	for i, n := range s.Nodes {
		port := s.BasePort + i
		node := n
		h := func(network, host string, portu uint16) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			return dial(ctx, node, network, host, portu)
		}
		addr := net.JoinHostPort(s.Bind, strconv.Itoa(port))
		ln, err := inbound.ListenMixed(addr, s.User, s.Pass, h)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		s.maps = append(s.maps, Mapping{Node: n, Port: port, ln: ln})
		log.Printf("mapped %s -> %s", n.Name, addr)
	}
	for _, extra := range s.Extras {
		node := extra.Node
		h := func(network, host string, portu uint16) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			return dial(ctx, node, network, host, portu)
		}
		ln, err := inbound.ListenMixed(extra.Addr, s.User, s.Pass, h)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen %s: %w", extra.Addr, err)
		}
		_, ps, _ := net.SplitHostPort(extra.Addr)
		port, _ := strconv.Atoi(ps)
		s.maps = append(s.maps, Mapping{Node: extra.Node, Port: port, ln: ln})
		log.Printf("mapped %s -> %s", extra.Node.Name, extra.Addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/clash", s.auth(s.handleClash))
	mux.HandleFunc("/list", s.auth(s.handleList))
	mux.HandleFunc("/opensurge", s.auth(s.handleOpenSurge))
	mux.HandleFunc("/map", s.auth(s.handleSurge))
	mux.HandleFunc("/", s.auth(s.handleSurge))

	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		s.Close()
		return err
	}
	s.httpLn = ln
	s.Listen = ln.Addr().String()
	s.httpSrv = &http.Server{Handler: mux}
	log.Printf("config server http://%s  (/ /clash /list /opensurge /health)", s.Listen)
	body := s.openSurgeBody()
	if s.OpenSurgePath != "" {
		if err := writeOpenSurgeFile(s.OpenSurgePath, body); err != nil {
			log.Printf("OpenSurge.yaml: %v", err)
		} else {
			log.Printf("OpenSurge profile → %s", s.OpenSurgePath)
		}
	}
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("config server: %v", err)
		}
	}()
	return nil
}

func (s *Server) processName() string {
	if s.ProcessName != "" {
		return s.ProcessName
	}
	return filepath.Base(os.Args[0])
}

func (s *Server) processPath() string {
	if s.ProcessPath != "" {
		return s.ProcessPath
	}
	if p, err := os.Executable(); err == nil && p != "" {
		return p
	}
	return officialProcessPath
}

func (s *Server) openSurgeBody() string {
	return OpenSurgeConfig(clashInspectURL(s.Listen, s.User, s.Pass), s.processName(), s.processPath())
}

func (s *Server) handleOpenSurge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, s.openSurgeBody())
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.httpSrv.Shutdown(ctx)
		cancel()
	}
	if s.httpLn != nil {
		_ = s.httpLn.Close()
	}
	for _, m := range s.maps {
		if m.ln != nil {
			_ = m.ln.Close()
		}
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.User != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != s.User || p != s.Pass {
				w.Header().Set("WWW-Authenticate", `Basic realm="oixCloud"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) advertiseHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || host == "localhost" {
		return "127.0.0.1"
	}
	return host
}

func (s *Server) handleClash(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, ClashConfig(s.Mappings(), s.advertiseHost(r)))
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, ProxyList(s.Mappings(), s.advertiseHost(r)))
}

func (s *Server) handleSurge(w http.ResponseWriter, r *http.Request) {
	host := s.advertiseHost(r)
	path := "/"
	if r.URL.Path == "/map" {
		path = "/map"
	}
	listenURL := managedURL(host, portOf(s.Listen), path, s.User, s.Pass)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, SurgeConfig(s.Mappings(), listenURL, host, s.Template))
}

func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "6172"
	}
	return p
}
