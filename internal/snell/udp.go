package snell

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

const cmdUDPForward byte = 1

func encodeUDPRequest(host string, port uint16, payload []byte) ([]byte, error) {
	if len(payload) > maxPayload-32 {
		return nil, errors.New("snell UDP payload too large")
	}
	buf := make([]byte, 0, 8+len(host)+len(payload))
	buf = append(buf, cmdUDPForward)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x00, 0x04)
			buf = append(buf, v4...)
		} else {
			v6 := ip.To16()
			if v6 == nil {
				return nil, errors.New("snell UDP address invalid")
			}
			buf = append(buf, 0x00, 0x06)
			buf = append(buf, v6...)
		}
	} else {
		if host == "" || len(host) > 255 {
			return nil, errors.New("snell UDP host invalid")
		}
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	buf = append(buf, p[:]...)
	buf = append(buf, payload...)
	return buf, nil
}

func parseUDPResponse(pkt []byte) (net.Addr, []byte, error) {
	if len(pkt) < 1 {
		return nil, nil, errors.New("snell UDP response empty")
	}
	switch pkt[0] {
	case 0x04:
		if len(pkt) < 1+net.IPv4len+2 {
			return nil, nil, errors.New("snell UDP IPv4 response short")
		}
		ip := net.IP(pkt[1 : 1+net.IPv4len])
		port := binary.BigEndian.Uint16(pkt[1+net.IPv4len : 1+net.IPv4len+2])
		return &net.UDPAddr{IP: ip, Port: int(port)}, pkt[1+net.IPv4len+2:], nil
	case 0x06:
		if len(pkt) < 1+net.IPv6len+2 {
			return nil, nil, errors.New("snell UDP IPv6 response short")
		}
		ip := net.IP(pkt[1 : 1+net.IPv6len])
		port := binary.BigEndian.Uint16(pkt[1+net.IPv6len : 1+net.IPv6len+2])
		return &net.UDPAddr{IP: ip, Port: int(port)}, pkt[1+net.IPv6len+2:], nil
	default:
		return nil, nil, errors.New("snell UDP response address invalid")
	}
}

func addrHostPort(addr net.Addr) (string, uint16, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String(), uint16(a.Port), nil
	case *net.TCPAddr:
		return a.IP.String(), uint16(a.Port), nil
	default:
		host, ps, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", 0, err
		}
		n, err := strconv.Atoi(ps)
		if err != nil || n < 0 || n > 65535 {
			return "", 0, errors.New("invalid port")
		}
		return host, uint16(n), nil
	}
}

// PacketConn is snell v4 UDP-over-TCP.
type PacketConn struct {
	conn *Conn
	rmu  sync.Mutex
	wmu  sync.Mutex
}

func NewPacketConn(c *Conn) *PacketConn {
	return &PacketConn{conn: c}
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host, port, err := addrHostPort(addr)
	if err != nil {
		return 0, err
	}
	pkt, err := encodeUDPRequest(host, port, p)
	if err != nil {
		return 0, err
	}
	pc.wmu.Lock()
	defer pc.wmu.Unlock()
	if _, err := pc.conn.WritePacket(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pc.rmu.Lock()
	defer pc.rmu.Unlock()
	pkt, err := pc.conn.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	addr, payload, err := parseUDPResponse(pkt)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, payload)
	return n, addr, nil
}

func (pc *PacketConn) Close() error { return pc.conn.Close() }

func (pc *PacketConn) LocalAddr() net.Addr { return pc.conn.LocalAddr() }

func (pc *PacketConn) SetDeadline(t time.Time) error { return pc.conn.SetDeadline(t) }

func (pc *PacketConn) SetReadDeadline(t time.Time) error { return pc.conn.SetReadDeadline(t) }

func (pc *PacketConn) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}
