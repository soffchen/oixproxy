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
	Host string
	// UDP is ASSOCIATE + profile advertise for this listener.
	UDP  bool
	User string
	Pass string
	ln   net.Listener
}

type DialFunc func(ctx context.Context, n dialer.Node, network, host string, port uint16) (net.Conn, error)

type Extra struct {
	Name string
	Node dialer.Node
	Addr string
}

type Server struct {
	Listen        string
	Bind          string
	BasePort      int
	User          string
	Pass          string
	Auth          func(addr string) (user, pass string)
	NoHTTP        bool
	Nodes         []dialer.Node
	Extras        []Extra
	Template      []byte
	Dial          DialFunc
	OpenSurgePath string
	ProcessName   string
	ProcessPath   string

	mu         sync.Mutex
	maps       []Mapping
	pools      []*dialer.Pool
	poolByName map[string]*dialer.Pool
	httpLn     net.Listener
	httpSrv    *http.Server
	closed     bool
}

func (s *Server) Mappings() []Mapping {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Mapping, len(s.maps))
	copy(out, s.maps)
	return out
}

func (s *Server) Start() error {
	s.closed = false
	if s.Bind == "" {
		s.Bind = "127.0.0.1"
	}
	if s.BasePort == 0 {
		s.BasePort = 7200
	}
	s.maps = make([]Mapping, 0, len(s.Nodes))
	go dialer.Prefetch(s.Nodes)
	for i, n := range s.Nodes {
		port := s.BasePort + i
		node := n
		dial := s.dialerFor(node)
		h := func(network, host string, portu uint16) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			return dial(ctx, node, network, host, portu)
		}
		addr := net.JoinHostPort(s.Bind, strconv.Itoa(port))
		udp := s.udpDialer(node)
		u, p := s.creds(addr)
		ln, err := inbound.ListenMixed(addr, u, p, h, udp)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		s.maps = append(s.maps, Mapping{Node: n, Port: port, UDP: udp != nil, User: u, Pass: p, ln: ln})
		log.Printf("mapped %s -> %s", n.Name, addr)
	}
	for _, extra := range s.Extras {
		node := extra.Node
		dial := s.dialerFor(node)
		h := func(network, host string, portu uint16) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			return dial(ctx, node, network, host, portu)
		}
		udp := s.udpDialer(node)
		u, p := s.creds(extra.Addr)
		ln, err := inbound.ListenMixed(extra.Addr, u, p, h, udp)
		if err != nil {
			s.Close()
			return fmt.Errorf("listen %s: %w", extra.Addr, err)
		}
		boundAddr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			_ = ln.Close()
			s.Close()
			return fmt.Errorf("监听 %s: 非预期地址类型 %T", extra.Addr, ln.Addr())
		}
		host := tcpAddrHost(boundAddr)
		mappedNode := extra.Node
		if extra.Name != "" {
			mappedNode.Name = extra.Name
		}
		s.maps = append(s.maps, Mapping{Node: mappedNode, Port: boundAddr.Port, Host: host, UDP: udp != nil, User: u, Pass: p, ln: ln})
		log.Printf("mapped %s -> %s", mappedNode.Name, extra.Addr)
	}

	if s.NoHTTP {
		return nil
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
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("config server http://%s  (/ /clash /list /opensurge /health)", s.Listen)
	body := s.openSurgeBody()
	if s.OpenSurgePath != "" {
		if err := writeOpenSurgeFile(s.OpenSurgePath, body); err != nil {
			log.Printf("OpenSurge.yaml: %v", err)
		} else {
			log.Printf("OpenSurge profile → %s", s.OpenSurgePath)
		}
	}
	httpSrv := s.httpSrv
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("config server: %v", err)
		}
	}()
	return nil
}

func (s *Server) dialerFor(n dialer.Node) DialFunc {
	if s.Dial != nil {
		return s.Dial
	}
	if !n.Reuse && n.Preconnect <= 0 {
		return dialer.Dial
	}
	if s.poolByName == nil {
		s.poolByName = map[string]*dialer.Pool{}
	}
	key := poolKey(n)
	if p := s.poolByName[key]; p != nil {
		return p.Dial
	}
	p := dialer.NewPool(n)
	s.poolByName[key] = p
	s.pools = append(s.pools, p)
	p.Warm(n.Preconnect)
	return p.Dial
}

func (s *Server) creds(addr string) (string, string) {
	if s.Auth != nil {
		return s.Auth(addr)
	}
	return s.User, s.Pass
}

func poolKey(n dialer.Node) string {
	return n.Name + "\x00" + n.Server + "\x00" + strconv.Itoa(n.Port)
}

func (s *Server) udpDialer(n dialer.Node) inbound.UDPDialer {
	if s.Dial != nil || !n.UDP {
		return nil
	}
	node := n
	return func() (net.PacketConn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return dialer.ListenPacket(ctx, node)
	}
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
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	httpSrv := s.httpSrv
	s.httpSrv = nil
	httpLn := s.httpLn
	s.httpLn = nil
	maps := append([]Mapping(nil), s.maps...)
	pools := append([]*dialer.Pool(nil), s.pools...)
	s.pools = nil
	s.poolByName = nil
	s.mu.Unlock()

	for _, m := range maps {
		if m.ln != nil {
			_ = m.ln.Close()
		}
	}
	if httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("config server shutdown: %v", err)
			_ = httpSrv.Close()
		}
		cancel()
	}
	if httpLn != nil {
		_ = httpLn.Close()
	}
	for _, p := range pools {
		p.Close()
	}
	s.mu.Lock()
	s.maps = nil
	s.mu.Unlock()
}

func tcpAddrHost(addr *net.TCPAddr) string {
	if addr.IP.IsUnspecified() {
		return ""
	}
	host := addr.IP.String()
	if addr.Zone != "" {
		host += "%" + addr.Zone
	}
	return host
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
