package inbound

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type memPC struct {
	mu   sync.Mutex
	got  []byte
	addr net.Addr
	ch   chan pkt
	loc  net.Addr
}

type pkt struct {
	p []byte
	a net.Addr
}

func (m *memPC) ReadFrom(p []byte) (int, net.Addr, error) {
	m.mu.Lock()
	ch := m.ch
	m.mu.Unlock()
	if ch == nil {
		return 0, nil, io.EOF
	}
	x, ok := <-ch
	if !ok {
		return 0, nil, io.EOF
	}
	n := copy(p, x.p)
	return n, x.a, nil
}

func (m *memPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.Lock()
	m.got = append([]byte(nil), p...)
	m.addr = addr
	m.mu.Unlock()
	return len(p), nil
}

func (m *memPC) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ch != nil {
		close(m.ch)
		m.ch = nil
	}
	return nil
}

func (m *memPC) LocalAddr() net.Addr              { return m.loc }
func (m *memPC) SetDeadline(time.Time) error      { return nil }
func (m *memPC) SetReadDeadline(time.Time) error  { return nil }
func (m *memPC) SetWriteDeadline(time.Time) error { return nil }

func TestSOCKS5UDPAssociate(t *testing.T) {
	pc := &memPC{ch: make(chan pkt), loc: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}}
	udp := func() (net.PacketConn, error) { return pc, nil }
	h := func(network, host string, port uint16) (net.Conn, error) {
		return nil, io.ErrClosedPipe
	}
	ln, err := ListenMixed("127.0.0.1:0", "", "", h, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tcpPort := ln.Addr().(*net.TCPAddr).Port

	c, err := net.Dial("tcp", ln.Addr().String())
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
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 5 || rep[1] != 0 || rep[3] != 1 {
		t.Fatalf("reply %v", rep)
	}
	port := int(binary.BigEndian.Uint16(rep[8:10]))
	if port != tcpPort {
		t.Fatalf("bnd port %d want tcp %d", port, tcpPort)
	}
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	pkt := []byte{0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53, 1, 2, 3}
	if _, err := uc.Write(pkt); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pc.mu.Lock()
		got := append([]byte(nil), pc.got...)
		addr := pc.addr
		pc.mu.Unlock()
		if len(got) > 0 {
			if string(got) != "\x01\x02\x03" {
				t.Fatalf("payload %q", got)
			}
			ua := addr.(*net.UDPAddr)
			if !ua.IP.Equal(net.IPv4(8, 8, 8, 8)) || ua.Port != 53 {
				t.Fatalf("dest %v", addr)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no udp datagram")
}

func TestSOCKS5UDPRejectedWithoutDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := func(network, host string, port uint16) (net.Conn, error) {
		return nil, io.ErrClosedPipe
	}
	go AcceptLoop(ln, "", "", h, nil)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var greet [2]byte
	_, _ = io.ReadFull(c, greet[:])
	_, _ = c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x07 {
		t.Fatalf("want command not supported, got %v", rep)
	}
}

func TestSOCKSBindAddrUnspecified(t *testing.T) {
	ip, port := socksBindAddr(&net.UDPAddr{IP: net.IPv4zero, Port: 7200}, nil)
	if !ip.Equal(net.IPv4zero) || port != 7200 {
		t.Fatalf("%v %d", ip, port)
	}
	ip, port = socksBindAddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7201}, nil)
	if !ip.Equal(net.IPv4(127, 0, 0, 1)) || port != 7201 {
		t.Fatalf("%v %d", ip, port)
	}
	v6any := &net.UDPAddr{IP: net.IPv6unspecified, Port: 7200}
	ip, port = socksBindAddr(v6any, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1})
	if !ip.Equal(net.IPv4zero) || port != 7200 {
		t.Fatalf("ipv4 peer on :: bind got %v %d", ip, port)
	}
}

func TestUDPNetworkDualStack(t *testing.T) {
	if g := udpNetwork("0.0.0.0"); g != "udp4" {
		t.Fatalf("v4 %s", g)
	}
	if g := udpNetwork("::"); g != "udp" {
		t.Fatalf("unspec v6 %s", g)
	}
	if g := udpNetwork("2001:db8::1"); g != "udp6" {
		t.Fatalf("v6 %s", g)
	}
}

func TestUDPHubRejectsSecondWildcardSameIP(t *testing.T) {
	h := &udpHub{byClient: map[string]*udpSess{}}
	peer := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 1}
	a, err := h.register(peer, nil)
	if err != nil || a == nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := h.register(peer, nil); err != errUDPWildcardBusy {
		t.Fatalf("second: %v", err)
	}
	other, err := h.register(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 8), Port: 1}, nil)
	if err != nil || other == nil {
		t.Fatalf("other ip: %v", err)
	}
}

func TestSOCKS5UDPSecondWildcardAssociateRejected(t *testing.T) {
	udp := func() (net.PacketConn, error) {
		return &memPC{ch: make(chan pkt), loc: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}}, nil
	}
	h := func(network, host string, port uint16) (net.Conn, error) {
		return nil, io.ErrClosedPipe
	}
	ln, err := ListenMixed("127.0.0.1:0", "", "", h, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dialAssoc := func() (net.Conn, []byte) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte{0x05, 0x01, 0x00})
		var greet [2]byte
		_, _ = io.ReadFull(c, greet[:])
		_, _ = c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		rep := make([]byte, 10)
		if _, err := io.ReadFull(c, rep); err != nil {
			t.Fatal(err)
		}
		return c, rep
	}
	c1, rep1 := dialAssoc()
	defer c1.Close()
	if rep1[1] != 0 {
		t.Fatalf("first associate %v", rep1)
	}
	c2, rep2 := dialAssoc()
	defer c2.Close()
	if rep2[1] != 0x01 {
		t.Fatalf("second associate %v, want general failure", rep2)
	}
}

func TestUDPHubAmbiguousPendingDoesNotSteal(t *testing.T) {
	h := &udpHub{byClient: map[string]*udpSess{}}
	a := &udpSess{peerIP: net.IPv4(127, 0, 0, 1), ch: make(chan udpDatagram, 1), done: make(chan struct{})}
	b := &udpSess{peerIP: net.IPv4(127, 0, 0, 1), ch: make(chan udpDatagram, 1), done: make(chan struct{})}
	h.pending = []*udpSess{a, b}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if s := h.dispatch(from); s != nil {
		t.Fatal("two wildcard pending must not pin")
	}
}

func TestUDPHubPinsByAssociateDST(t *testing.T) {
	h := &udpHub{byClient: map[string]*udpSess{}}
	a := &udpSess{
		peerIP: net.IPv4(127, 0, 0, 1),
		expect: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000},
		ch:     make(chan udpDatagram, 1),
		done:   make(chan struct{}),
	}
	b := &udpSess{
		peerIP: net.IPv4(127, 0, 0, 1),
		expect: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000},
		ch:     make(chan udpDatagram, 1),
		done:   make(chan struct{}),
	}
	h.pending = []*udpSess{a, b}
	got := h.dispatch(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000})
	if got != b {
		t.Fatalf("got %p want b", got)
	}
	got = h.dispatch(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000})
	if got != a {
		t.Fatalf("got %p want a", got)
	}
}

func TestSOCKS5UDPTwoAssociatesByDST(t *testing.T) {
	var mu sync.Mutex
	var pcs []*memPC
	udp := func() (net.PacketConn, error) {
		pc := &memPC{ch: make(chan pkt), loc: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}}
		mu.Lock()
		pcs = append(pcs, pc)
		mu.Unlock()
		return pc, nil
	}
	h := func(network, host string, port uint16) (net.Conn, error) {
		return nil, io.ErrClosedPipe
	}
	ln, err := ListenMixed("127.0.0.1:0", "", "", h, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bnd := ln.Addr().(*net.TCPAddr)

	type client struct {
		tcp net.Conn
		uc  *net.UDPConn
		pay byte
	}
	clients := make([]client, 2)
	for i := range clients {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		la := uc.LocalAddr().(*net.UDPAddr)
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte{0x05, 0x01, 0x00})
		var greet [2]byte
		_, _ = io.ReadFull(c, greet[:])
		req := []byte{0x05, 0x03, 0x00, 0x01}
		req = append(req, la.IP.To4()...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], uint16(la.Port))
		req = append(req, pb[:]...)
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
		rep := make([]byte, 10)
		if _, err := io.ReadFull(c, rep); err != nil {
			t.Fatal(err)
		}
		if rep[1] != 0 {
			t.Fatalf("associate %v", rep)
		}
		pay := byte('A' + i)
		pkt := []byte{0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53, pay}
		if _, err := uc.WriteTo(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bnd.Port}); err != nil {
			t.Fatal(err)
		}
		clients[i] = client{tcp: c, uc: uc, pay: pay}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(pcs)
		got := make([][]byte, n)
		for i, pc := range pcs {
			pc.mu.Lock()
			got[i] = append([]byte(nil), pc.got...)
			pc.mu.Unlock()
		}
		mu.Unlock()
		if n == 2 && len(got[0]) > 0 && len(got[1]) > 0 {
			if got[0][0] == got[1][0] {
				t.Fatalf("crossed payloads %q %q", got[0], got[1])
			}
			seen := map[byte]bool{got[0][0]: true, got[1][0]: true}
			if !seen['A'] || !seen['B'] {
				t.Fatalf("payloads %q %q", got[0], got[1])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("did not receive both datagrams")
}

func TestUDPHubSinglePendingPins(t *testing.T) {
	h := &udpHub{byClient: map[string]*udpSess{}}
	s := &udpSess{peerIP: net.IPv4(10, 0, 0, 1), ch: make(chan udpDatagram, 1), done: make(chan struct{})}
	h.pending = []*udpSess{s}
	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9}
	if h.dispatch(from) != s {
		t.Fatal("single pending")
	}
	if h.dispatch(from) != s {
		t.Fatal("pinned lookup")
	}
}

func TestUDPAllowedPinsTCPPeerThenFirstAddr(t *testing.T) {
	peer := net.IPv4(10, 0, 0, 1)
	first := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000}
	otherIP := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000}
	otherPort := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40001}
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:10.0.0.1"), Port: 40000}

	if _, ok := udpAllowed(peer, nil, otherIP); ok {
		t.Fatal("foreign IP must drop")
	}
	pinned, ok := udpAllowed(peer, nil, first)
	if !ok || !sameUDPAddr(pinned, first) {
		t.Fatalf("pin first %v ok=%v", pinned, ok)
	}
	if _, ok := udpAllowed(peer, pinned, otherPort); ok {
		t.Fatal("other port after pin must drop")
	}
	if _, ok := udpAllowed(peer, pinned, first); !ok {
		t.Fatal("pinned addr must pass")
	}
	if _, ok := udpAllowed(peer, nil, mapped); !ok {
		t.Fatal("ipv4-mapped peer IP must pass")
	}
}
