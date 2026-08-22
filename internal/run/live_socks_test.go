package run

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/soffchen/oixproxy/internal/dialer"
	"github.com/soffchen/oixproxy/internal/profile"
	"github.com/soffchen/oixproxy/internal/serve"
)

func liveNodes(t *testing.T) []dialer.Node {
	t.Helper()
	if os.Getenv("OIX_LIVE_SOCKS") != "1" {
		t.Skip("OIX_LIVE_SOCKS=1 and OIX_PROFILE=<dedicated.yaml>")
	}
	p := os.Getenv("OIX_PROFILE")
	if p == "" {
		t.Skip("OIX_PROFILE is required for live tests")
	}
	nodes, err := profile.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 {
		t.Fatal("no snell nodes")
	}
	return nodes
}

func TestLiveHandshakeVariants(t *testing.T) {
	n := liveNodes(t)[0]
	t.Logf("node=%s host=%s port=%d alpn=%s path=%t", n.Name, n.Server, n.Port, n.ALPN, n.Path != "")

	type trial struct {
		name   string
		fp     string
		protos []string
		ws     bool
	}
	trials := []trial{
		{name: "chrome-snell-ech", fp: "chrome", protos: []string{"snell-ech/1"}, ws: false},
		{name: "chrome120-snell-ech", fp: "chrome120", protos: []string{"snell-ech/1"}, ws: false},
		{name: "chrome-http11-ws", fp: "chrome", protos: []string{"http/1.1"}, ws: true},
	}
	ok := 0
	for _, tr := range trials {
		nn := n
		nn.Fingerprint = tr.fp
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, st, err := dialer.HandshakeForTest(ctx, nn, tr.protos, tr.ws)
		if err != nil {
			t.Logf("%s handshake: %v", tr.name, err)
			cancel()
			continue
		}
		t.Logf("%s handshake ok alpn=%q ech=%v ver=0x%x", tr.name, st.ALPN, st.ECH, st.Version)
		if tr.ws {
			wsc, err := dialer.UpgradeWebsocketForTest(ctx, c, nn)
			if err != nil {
				t.Logf("%s websocket: %v", tr.name, err)
				_ = c.Close()
				cancel()
				continue
			}
			c = wsc
			t.Logf("%s websocket ok", tr.name)
		}
		_ = c.Close()
		cancel()
		ok++
	}
	if ok == 0 {
		t.Fatal("all handshake variants failed")
	}
}

func TestLiveDestinationSelection(t *testing.T) {
	n := liveNodes(t)[0]
	if n.DialIP != "" {
		t.Fatal("fixture must not pin DialIP")
	}
	t.Setenv("OIX_DIAL_IP", "198.51.100.1")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dest, err := dialer.SelectDestination(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		t.Fatal(err)
	}
	if net.ParseIP(host) == nil {
		t.Fatalf("expected resolved IP, got %s", dest)
	}
	if host == "198.51.100.1" {
		t.Fatal("SelectDestination honored OIX_DIAL_IP")
	}
	if host == "119.40.182.189" {
		t.Fatal("SelectDestination used decoy A from unsigned QNAME")
	}
	if port != strconv.Itoa(n.Port) {
		t.Fatalf("port %s", port)
	}
	t.Logf("selected an address for %s (env OIX_DIAL_IP ignored)", n.Server)
}

func TestLiveDirectSnellDial(t *testing.T) {
	n := liveNodes(t)[0]
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := dialer.Dial(ctx, n, "tcp", "www.google.com", 443)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	t.Log("dial ok")
}

func TestLiveMappedSOCKSReachesGoogle(t *testing.T) {
	nodes := liveNodes(t)
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	_ = httpLn.Close()
	mapLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapPort := mapLn.Addr().(*net.TCPAddr).Port
	_ = mapLn.Close()

	s := &serve.Server{
		Listen:   net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		Bind:     "127.0.0.1",
		BasePort: mapPort,
		Nodes:    nodes[:1],
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mapPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	host := "www.google.com"
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
	tc := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls over socks/snell: %v", err)
	}
	if _, err := io.WriteString(tc, "GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 80)
	n, err := tc.Read(buf)
	if n == 0 {
		t.Fatalf("empty google response: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "HTTP/") {
		t.Fatalf("not http: %q", got)
	}
	line := strings.Split(got, "\r\n")[0]
	t.Logf("google via local socks5 -> snell-ech: %q", line)
	if !strings.Contains(line, "204") && !strings.HasPrefix(line, "HTTP/") {
		t.Fatalf("unexpected google line %q", line)
	}
}

func TestLiveTFODialReachesGoogle(t *testing.T) {
	n := liveNodes(t)[0]
	n.TFO = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := dialer.Dial(ctx, n, "tcp", "www.google.com", 443)
	if err != nil {
		t.Fatalf("tfo dial: %v", err)
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "www.google.com", MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls over tfo snell: %v", err)
	}
	if _, err := io.WriteString(tc, "GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 80)
	nread, err := tc.Read(buf)
	if nread == 0 {
		t.Fatalf("empty google response: %v", err)
	}
	line := strings.Split(string(buf[:nread]), "\r\n")[0]
	t.Logf("google via tfo snell: %q", line)
	if !strings.HasPrefix(line, "HTTP/") {
		t.Fatalf("not http: %q", line)
	}
}

func TestLiveUDPPacketDNS(t *testing.T) {
	n := liveNodes(t)[0]
	n.UDP = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pc, err := dialer.ListenPacket(ctx, n)
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(12 * time.Second))
	q := dnsQueryA("www.google.com")
	if _, err := pc.WriteTo(q, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 1500)
	nread, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if nread < 12 {
		t.Fatalf("short dns %d from %v", nread, addr)
	}
	t.Logf("dns via snell udp: %d bytes from %v", nread, addr)
}

func TestLiveMappedSOCKSUDPAssociate(t *testing.T) {
	nodes := liveNodes(t)
	n0 := nodes[0]
	n0.UDP = true
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	_ = httpLn.Close()
	mapLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mapPort := mapLn.Addr().(*net.TCPAddr).Port
	_ = mapLn.Close()

	s := &serve.Server{
		Listen:   net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		Bind:     "127.0.0.1",
		BasePort: mapPort,
		Nodes:    []dialer.Node{n0},
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mapPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("associate reply %v", rep)
	}
	port := int(binary.BigEndian.Uint16(rep[8:10]))
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(12 * time.Second))
	q := dnsQueryA("www.google.com")
	pkt := []byte{0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53}
	pkt = append(pkt, q...)
	if _, err := uc.Write(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	nread, err := uc.Read(buf)
	if err != nil {
		t.Fatalf("socks udp read: %v", err)
	}
	if nread < 10 {
		t.Fatalf("short socks udp %d", nread)
	}
	t.Logf("dns via socks5 udp associate: %d bytes", nread)
}

func dnsQueryA(name string) []byte {
	var q []byte
	q = append(q, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, lab := range strings.Split(name, ".") {
		q = append(q, byte(len(lab)))
		q = append(q, lab...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
	return q
}
