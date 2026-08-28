package serve

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soffchen/oixproxy/internal/dialer"
)

func TestMappedPortSOCKSCONNECT(t *testing.T) {
	var mu sync.Mutex
	var gotHost string
	var gotPort uint16
	var gotNode string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapPort := pln.Addr().(*net.TCPAddr).Port
	_ = pln.Close()

	s := &Server{
		Listen:   net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		Bind:     "127.0.0.1",
		BasePort: mapPort,
		Nodes:    []dialer.Node{{Name: "🇭🇰 香港 Fusion 01", Server: "remote.example", Port: 443, PSK: "x", ECHConfig: "AAAA"}},
		Dial: func(ctx context.Context, n dialer.Node, network, host string, port uint16) (net.Conn, error) {
			mu.Lock()
			gotHost, gotPort, gotNode = host, port, n.Name
			mu.Unlock()
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				buf := make([]byte, 16)
				n, _ := b.Read(buf)
				b.Write([]byte("OK" + string(buf[:n])))
			}()
			return a, nil
		},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mapPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	host := "www.gstatic.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], 443)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks reply %v", rep)
	}
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	n, _ := c.Read(out)
	if string(out[:n]) != "OKhi" {
		t.Fatalf("relay %q", out[:n])
	}
	mu.Lock()
	defer mu.Unlock()
	if gotHost != host || gotPort != 443 || gotNode != "🇭🇰 香港 Fusion 01" {
		t.Fatalf("dial %s %s:%d", gotNode, gotHost, gotPort)
	}
}

func TestDialerForIgnoresPreconnectWithoutReuse(t *testing.T) {
	s := &Server{}
	_ = s.dialerFor(dialer.Node{Name: "hk", Preconnect: 2})
	if len(s.pools) != 0 {
		t.Fatalf("关闭复用后仍创建了 %d 个连接池", len(s.pools))
	}
}

func TestConfigHTTPAuthRejects(t *testing.T) {
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	_ = httpLn.Close()
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapPort := pln.Addr().(*net.TCPAddr).Port
	_ = pln.Close()

	s := &Server{
		Listen:   net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		Bind:     "127.0.0.1",
		BasePort: mapPort,
		User:     "alice",
		Pass:     "secret",
		Nodes:    []dialer.Node{{Name: "hk", Server: "remote.example", Port: 443, PSK: "x", ECHConfig: "AAAA"}},
		Dial: func(ctx context.Context, n dialer.Node, network, host string, port uint16) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { _ = b.Close() }()
			return a, nil
		},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	base := "http://" + s.Listen
	resp, err := http.Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health %d", resp.StatusCode)
	}
	resp, err = http.Get(base + "/clash")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/clash %d", resp.StatusCode)
	}
}

func TestNoHTTPSkipsConfigServer(t *testing.T) {
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpAddr := httpLn.Addr().String()
	_ = httpLn.Close()
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapPort := pln.Addr().(*net.TCPAddr).Port
	_ = pln.Close()

	s := &Server{
		Listen:   httpAddr,
		Bind:     "127.0.0.1",
		BasePort: mapPort,
		NoHTTP:   true,
		Nodes:    []dialer.Node{{Name: "hk", Server: "remote.example", Port: 443, PSK: "x", ECHConfig: "AAAA"}},
		Dial: func(ctx context.Context, n dialer.Node, network, host string, port uint16) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { _ = b.Close() }()
			return a, nil
		},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = net.DialTimeout("tcp", httpAddr, 200*time.Millisecond)
	if err == nil {
		t.Fatal("HTTP still bound")
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mapPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestMappingsRecordListenerAuth(t *testing.T) {
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	_ = httpLn.Close()
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapPort := pln.Addr().(*net.TCPAddr).Port
	_ = pln.Close()
	eln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	extraAddr := eln.Addr().String()
	_ = eln.Close()

	s := &Server{
		Listen:   net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		Bind:     "127.0.0.1",
		BasePort: mapPort,
		Auth: func(addr string) (string, string) {
			if addr == extraAddr {
				return "alice", "secret"
			}
			return "", ""
		},
		Nodes: []dialer.Node{{Name: "loop", Server: "remote.example", Port: 443, PSK: "x", ECHConfig: "AAAA"}},
		Extras: []Extra{{
			Name: "lan",
			Node: dialer.Node{Name: "upstream", Server: "remote.example", Port: 443, PSK: "x", ECHConfig: "AAAA"},
			Addr: extraAddr,
		}},
		Dial: func(ctx context.Context, n dialer.Node, network, host string, port uint16) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { _ = b.Close() }()
			return a, nil
		},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	maps := s.Mappings()
	if len(maps) != 2 {
		t.Fatalf("maps %d", len(maps))
	}
	if maps[0].User != "" || maps[0].Pass != "" {
		t.Fatalf("loopback mapping should skip auth: %+v", maps[0])
	}
	if maps[1].User != "alice" || maps[1].Pass != "secret" {
		t.Fatalf("extra mapping missing creds: %+v", maps[1])
	}

	resp, err := http.Get("http://" + s.Listen + "/list")
	if err != nil {
		t.Fatal(err)
	}
	list, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(list), "lan = socks5, 127.0.0.1, "+strconv.Itoa(maps[1].Port)+", alice, secret") {
		t.Fatalf("list: %s", list)
	}
	if strings.Contains(string(list), "loop = socks5, 127.0.0.1, "+strconv.Itoa(mapPort)+", alice") {
		t.Fatalf("loopback leaked auth: %s", list)
	}
	resp, err = http.Get("http://" + s.Listen + "/clash")
	if err != nil {
		t.Fatal(err)
	}
	clash, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(clash), `username: "alice"`) || strings.Count(string(clash), `username:`) != 1 {
		t.Fatalf("clash: %s", clash)
	}
}

func TestExtraMappingPublishesResolvedListenerAddress(t *testing.T) {
	s := &Server{
		NoHTTP: true,
		Extras: []Extra{{
			Node: dialer.Node{Name: "local", Server: "remote.example", Port: 443, PSK: "x", ECHConfig: "AAAA"},
			Addr: "localhost:0",
		}},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	maps := s.Mappings()
	if len(maps) != 1 {
		t.Fatalf("maps %d", len(maps))
	}
	m := maps[0]
	if net.ParseIP(m.Host) == nil || m.Port == 0 {
		t.Fatalf("未记录实际监听地址: %+v", m)
	}
	list := ProxyList(maps, "198.51.100.10")
	clash := ClashConfig(maps, "198.51.100.10")
	if strings.Contains(list, "localhost") || strings.Contains(clash, "localhost") {
		t.Fatalf("发布了原始绑定名:\nlist=%s\nclash=%s", list, clash)
	}
	if !strings.Contains(list, ", "+m.Host+", "+strconv.Itoa(m.Port)) || !strings.Contains(clash, "server: "+m.Host) {
		t.Fatalf("未发布实际监听地址:\nlist=%s\nclash=%s", list, clash)
	}
}

func TestTCPAddrHostPreservesIPv6Zone(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 7801, Zone: "en0"}
	host := tcpAddrHost(addr)
	if host != "fe80::1%en0" {
		t.Fatalf("IPv6 作用域丢失: %q", host)
	}
	maps := []Mapping{{Node: dialer.Node{Name: "固定 IPv6"}, Host: host, Port: addr.Port}}
	if list := ProxyList(maps, "198.51.100.10"); !strings.Contains(list, ", fe80::1%en0, 7801") {
		t.Fatalf("列表未发布 IPv6 作用域: %s", list)
	}
	if clash := ClashConfig(maps, "198.51.100.10"); !strings.Contains(clash, "server: fe80::1%en0") {
		t.Fatalf("Clash 未发布 IPv6 作用域: %s", clash)
	}
}

func TestConfigServerHasResourceTimeouts(t *testing.T) {
	s := &Server{Listen: "127.0.0.1:0"}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.httpSrv == nil {
		t.Fatal("HTTP server 未启动")
	}
	if s.httpSrv.ReadHeaderTimeout <= 0 || s.httpSrv.WriteTimeout <= 0 || s.httpSrv.IdleTimeout <= 0 {
		t.Fatalf("HTTP 资源超时未完整配置: %+v", s.httpSrv)
	}
}

func TestCloseDoesNotHoldMappingLockDuringShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := &Server{maps: []Mapping{{Node: dialer.Node{Name: "node"}, Port: 7200}}}
	entered := make(chan struct{})
	proceed := make(chan struct{})
	handlerErr := make(chan error, 1)
	s.httpLn = ln
	s.httpSrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-proceed
		if len(s.Mappings()) != 1 {
			handlerErr <- io.ErrUnexpectedEOF
			return
		}
		_, err := io.WriteString(w, "ok")
		handlerErr <- err
	})}
	srv := s.httpSrv
	go func() { _ = srv.Serve(ln) }()
	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://" + ln.Addr().String())
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler 未启动")
	}
	closeDone := make(chan struct{})
	go func() {
		s.Close()
		close(closeDone)
	}()
	time.Sleep(20 * time.Millisecond)
	close(proceed)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close 与 Mappings 发生锁等待")
	}
	select {
	case err := <-handlerErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler 未完成")
	}
	select {
	case err := <-requestDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP 请求未完成")
	}
}
