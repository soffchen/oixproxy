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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := func(network, host string, port uint16) (net.Conn, error) {
		return nil, io.ErrClosedPipe
	}
	go AcceptLoop(ln, "", "", h, udp)

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

func TestUDPLocalOKLoopbackOnly(t *testing.T) {
	if !udpLocalOK(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}) {
		t.Fatal("127.0.0.1")
	}
	if !udpLocalOK(&net.TCPAddr{IP: net.IPv6loopback, Port: 1}) {
		t.Fatal("::1")
	}
	if udpLocalOK(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}) {
		t.Fatal("lan must reject")
	}
	if udpLocalOK(&net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 1}) {
		t.Fatal("unspecified must reject")
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
