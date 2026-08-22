package inbound

import (
	"net"
	"sync"
)

type udpDatagram struct {
	dest    net.Addr
	payload []byte
}

type udpSess struct {
	peerIP net.IP
	expect net.Addr
	client net.Addr
	ch     chan udpDatagram
	once   sync.Once
	done   chan struct{}
}

func (s *udpSess) stop() {
	s.once.Do(func() { close(s.done) })
}

type udpHub struct {
	pc       net.PacketConn
	mu       sync.Mutex
	pending  []*udpSess
	byClient map[string]*udpSess
}

func newUDPHub(pc net.PacketConn) *udpHub {
	h := &udpHub{pc: pc, byClient: map[string]*udpSess{}}
	go h.readLoop()
	return h
}

func (h *udpHub) Close() error { return h.pc.Close() }

func (h *udpHub) LocalAddr() net.Addr { return h.pc.LocalAddr() }

func (h *udpHub) WriteTo(p []byte, addr net.Addr) (int, error) {
	return h.pc.WriteTo(p, addr)
}

func (h *udpHub) register(peer, expect net.Addr) *udpSess {
	s := &udpSess{
		peerIP: addrIP(peer),
		expect: expect,
		ch:     make(chan udpDatagram, 32),
		done:   make(chan struct{}),
	}
	h.mu.Lock()
	h.pending = append(h.pending, s)
	h.mu.Unlock()
	return s
}

func (h *udpHub) unregister(s *udpSess) {
	s.stop()
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, p := range h.pending {
		if p != s {
			h.pending[n] = p
			n++
		}
	}
	h.pending = h.pending[:n]
	if s.client != nil {
		delete(h.byClient, s.client.String())
	}
}

func (h *udpHub) clientOf(s *udpSess) net.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	return s.client
}

func (h *udpHub) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := h.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		host, port, payload, err := parseSOCKSUDP(buf[:n])
		if err != nil {
			continue
		}
		s := h.dispatch(from)
		if s == nil {
			continue
		}
		var dest net.Addr
		if ip := net.ParseIP(host); ip != nil {
			dest = &net.UDPAddr{IP: ip, Port: int(port)}
		} else {
			dest = socksHostAddr{host: host, port: int(port)}
		}
		d := udpDatagram{dest: dest, payload: append([]byte(nil), payload...)}
		select {
		case s.ch <- d:
		case <-s.done:
		}
	}
}

func (h *udpHub) dispatch(from net.Addr) *udpSess {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.lookupPinned(from); s != nil {
		return s
	}
	var exact *udpSess
	exactI, exactN := 0, 0
	var wild *udpSess
	wildI, wildN := 0, 0
	for i, s := range h.pending {
		if s.expect != nil {
			if sameUDPAddr(s.expect, from) {
				if s.peerIP != nil {
					if ip := addrIP(from); ip == nil || !s.peerIP.Equal(ip) {
						continue
					}
				}
				exact, exactI = s, i
				exactN++
			}
			continue
		}
		if _, ok := udpAllowed(s.peerIP, nil, from); ok {
			wild, wildI = s, i
			wildN++
		}
	}
	switch {
	case exactN == 1:
		return h.pinLocked(exact, exactI, from)
	case exactN > 1:
		return nil
	case wildN == 1:
		return h.pinLocked(wild, wildI, from)
	default:
		return nil
	}
}

func (h *udpHub) lookupPinned(from net.Addr) *udpSess {
	if s := h.byClient[from.String()]; s != nil {
		return s
	}
	for _, s := range h.byClient {
		if sameUDPAddr(s.client, from) {
			h.byClient[from.String()] = s
			return s
		}
	}
	return nil
}

func (h *udpHub) pinLocked(s *udpSess, i int, from net.Addr) *udpSess {
	s.client = from
	h.byClient[from.String()] = s
	h.pending = append(h.pending[:i], h.pending[i+1:]...)
	return s
}

func socksBindAddr(local, tcpPeer net.Addr) (net.IP, int) {
	ua, ok := local.(*net.UDPAddr)
	if !ok || ua == nil {
		return net.IPv4zero, 0
	}
	ip := ua.IP
	if ip != nil && !ip.IsUnspecified() {
		return ip, ua.Port
	}
	if peer := addrIP(tcpPeer); peer != nil && peer.To4() != nil {
		return net.IPv4zero, ua.Port
	}
	if ip != nil && ip.To4() == nil {
		return net.IPv6zero, ua.Port
	}
	return net.IPv4zero, ua.Port
}

func udpNetwork(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return "udp"
	}
	if ip.To4() != nil {
		return "udp4"
	}
	if ip.IsUnspecified() {
		return "udp"
	}
	return "udp6"
}

func listenPacketSame(addr string) (net.PacketConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	return net.ListenPacket(udpNetwork(host), addr)
}

func associateExpect(host string, port uint16) net.Addr {
	if port == 0 || host == "" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}
}
