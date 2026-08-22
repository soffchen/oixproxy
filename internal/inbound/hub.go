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

func (h *udpHub) register(peer net.Addr) *udpSess {
	s := &udpSess{
		peerIP: addrIP(peer),
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
		default:
		}
	}
}

func (h *udpHub) dispatch(from net.Addr) *udpSess {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.byClient[from.String()]; s != nil {
		return s
	}
	for i, s := range h.pending {
		pinned, ok := udpAllowed(s.peerIP, s.client, from)
		if !ok {
			continue
		}
		s.client = pinned
		h.byClient[pinned.String()] = s
		h.pending = append(h.pending[:i], h.pending[i+1:]...)
		return s
	}
	return nil
}

func socksBindAddr(a net.Addr) (net.IP, int) {
	ua, ok := a.(*net.UDPAddr)
	if !ok || ua == nil {
		return net.IPv4zero, 0
	}
	ip := ua.IP
	if ip == nil || ip.IsUnspecified() {
		if ip != nil && ip.To4() == nil {
			return net.IPv6zero, ua.Port
		}
		return net.IPv4zero, ua.Port
	}
	return ip, ua.Port
}

func listenPacketSame(addr string) (net.PacketConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	network := "udp"
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	return net.ListenPacket(network, addr)
}
