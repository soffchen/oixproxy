package inbound

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

func serveUDPAssociate(tcp net.Conn, br *bufio.Reader, udp UDPDialer) error {
	if udp == nil || !udpLocalOK(tcp.LocalAddr()) {
		_, _ = tcp.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("socks udp not enabled")
	}
	up, err := udp()
	if err != nil {
		_, _ = tcp.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer up.Close()

	localIP := net.IPv4(127, 0, 0, 1)
	if ta, ok := tcp.LocalAddr().(*net.TCPAddr); ok && ta.IP != nil {
		localIP = ta.IP
	}
	network := "udp"
	if localIP.To4() != nil {
		network = "udp4"
	} else if localIP.To16() != nil {
		network = "udp6"
	}
	pc, err := net.ListenPacket(network, net.JoinHostPort(localIP.String(), "0"))
	if err != nil {
		_, _ = tcp.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer pc.Close()

	ua, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_, _ = tcp.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("udp bind")
	}
	if err := writeSOCKSReply(tcp, 0x00, ua.IP, ua.Port); err != nil {
		return err
	}

	peerIP := addrIP(tcp.RemoteAddr())
	var clientAddr net.Addr
	var mu sync.Mutex
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	go func() {
		defer stop()
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			host, port, payload, err := parseSOCKSUDP(buf[:n])
			if err != nil {
				continue
			}
			mu.Lock()
			pinned, ok := udpAllowed(peerIP, clientAddr, addr)
			if !ok {
				mu.Unlock()
				continue
			}
			clientAddr = pinned
			mu.Unlock()
			var dest net.Addr
			if ip := net.ParseIP(host); ip != nil {
				dest = &net.UDPAddr{IP: ip, Port: int(port)}
			} else {
				dest = socksHostAddr{host: host, port: int(port)}
			}
			_, _ = up.WriteTo(payload, dest)
		}
	}()
	go func() {
		defer stop()
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			dst := clientAddr
			mu.Unlock()
			if dst == nil {
				continue
			}
			pkt := encodeSOCKSUDP(addr, buf[:n])
			_, _ = pc.WriteTo(pkt, dst)
		}
	}()
	go func() {
		_, _ = io.Copy(io.Discard, br)
		stop()
	}()
	<-done
	return nil
}

func udpLocalOK(local net.Addr) bool {
	ip := addrIP(local)
	return ip != nil && ip.IsLoopback()
}

func addrIP(a net.Addr) net.IP {
	if a == nil {
		return nil
	}
	switch t := a.(type) {
	case *net.UDPAddr:
		return t.IP
	case *net.TCPAddr:
		return t.IP
	case *net.IPAddr:
		return t.IP
	default:
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return net.ParseIP(a.String())
		}
		return net.ParseIP(host)
	}
}

func sameUDPAddr(a, b net.Addr) bool {
	if a == nil || b == nil {
		return false
	}
	ua, aok := a.(*net.UDPAddr)
	ub, bok := b.(*net.UDPAddr)
	if aok && bok {
		return ua.IP.Equal(ub.IP) && ua.Port == ub.Port
	}
	return a.String() == b.String()
}

// udpAllowed pins SOCKS UDP to the TCP peer IP, then the first matching UDP addr.
func udpAllowed(peerIP net.IP, pinned, from net.Addr) (net.Addr, bool) {
	if from == nil {
		return pinned, false
	}
	if peerIP != nil {
		if ip := addrIP(from); ip == nil || !peerIP.Equal(ip) {
			return pinned, false
		}
	}
	if pinned == nil {
		return from, true
	}
	if !sameUDPAddr(pinned, from) {
		return pinned, false
	}
	return pinned, true
}

type socksHostAddr struct {
	host string
	port int
}

func (a socksHostAddr) Network() string { return "udp" }
func (a socksHostAddr) String() string {
	return net.JoinHostPort(a.host, fmt.Sprintf("%d", a.port))
}

func writeSOCKSReply(c net.Conn, rep byte, ip net.IP, port int) error {
	buf := []byte{0x05, rep, 0x00}
	if v4 := ip.To4(); v4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, v4...)
	} else if len(ip) == net.IPv6len {
		buf = append(buf, 0x04)
		buf = append(buf, ip...)
	} else {
		buf = append(buf, 0x01, 0, 0, 0, 0)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	buf = append(buf, p[:]...)
	_, err := c.Write(buf)
	return err
}

func parseSOCKSUDP(b []byte) (host string, port uint16, payload []byte, err error) {
	if len(b) < 4 {
		return "", 0, nil, fmt.Errorf("short socks udp")
	}
	if b[2] != 0 {
		return "", 0, nil, fmt.Errorf("socks udp frag")
	}
	off := 3
	switch b[off] {
	case 0x01:
		if len(b) < off+1+net.IPv4len+2 {
			return "", 0, nil, fmt.Errorf("short socks udp ipv4")
		}
		host = net.IP(b[off+1 : off+1+net.IPv4len]).String()
		off += 1 + net.IPv4len
	case 0x04:
		if len(b) < off+1+net.IPv6len+2 {
			return "", 0, nil, fmt.Errorf("short socks udp ipv6")
		}
		host = net.IP(b[off+1 : off+1+net.IPv6len]).String()
		off += 1 + net.IPv6len
	case 0x03:
		if len(b) < off+2 {
			return "", 0, nil, fmt.Errorf("short socks udp domain")
		}
		n := int(b[off+1])
		if len(b) < off+2+n+2 {
			return "", 0, nil, fmt.Errorf("short socks udp domain")
		}
		host = string(b[off+2 : off+2+n])
		off += 2 + n
	default:
		return "", 0, nil, fmt.Errorf("socks udp atyp %d", b[off])
	}
	port = binary.BigEndian.Uint16(b[off : off+2])
	return host, port, b[off+2:], nil
}

func encodeSOCKSUDP(addr net.Addr, payload []byte) []byte {
	host := ""
	port := 0
	if ua, ok := addr.(*net.UDPAddr); ok {
		host = ua.IP.String()
		port = ua.Port
	} else if addr != nil {
		h, p, err := net.SplitHostPort(addr.String())
		if err == nil {
			host = h
			n, _ := strconv.Atoi(p)
			port = n
		}
	}
	buf := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	buf = append(buf, p[:]...)
	return append(buf, payload...)
}
