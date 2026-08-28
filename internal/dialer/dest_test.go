package dialer

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func signedDNSHost(t *testing.T) string {
	t.Helper()
	dnsAuthInit()
	if dnsAuthSuffix == "" {
		t.Fatal("dns-auth suffix unavailable")
	}
	return "n1." + dnsAuthSuffix
}

func TestDestinationsUsesPrivateDNSNotEnv(t *testing.T) {
	const want = "203.0.113.9"
	host := signedDNSHost(t)
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveTestDNS(t, ln, host, net.ParseIP(want))

	t.Setenv("OIX_DIAL_IP", "198.51.100.1")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	n := Node{
		Server: host,
		Port:   14888,
		DNS:    []DNSServer{{Network: "udp", Addr: ln.LocalAddr().String()}},
	}
	dests, err := Destinations(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	wantAddr := net.JoinHostPort(want, "14888")
	if len(dests) != 1 || dests[0] != wantAddr {
		t.Fatalf("destinations %v", dests)
	}
	got, err := SelectDestination(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantAddr {
		t.Fatalf("select %s", got)
	}
	if got == net.JoinHostPort("198.51.100.1", "14888") {
		t.Fatal("used OIX_DIAL_IP")
	}
}

func TestHTTPSIPv4HintPreferred(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host := signedDNSHost(t)
	go serveTestDNSMixed(t, ln, host,
		net.ParseIP("203.0.113.9"), net.ParseIP("198.51.100.10"))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n := Node{
		Server: host,
		Port:   14888,
		DNS:    []DNSServer{{Network: "udp", Addr: ln.LocalAddr().String()}},
	}
	dests, err := Destinations(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if dests[0] != "198.51.100.10:14888" {
		t.Fatalf("want ipv4hint first, got %v", dests)
	}
	if len(dests) < 2 || dests[1] != "203.0.113.9:14888" {
		t.Fatalf("want A second, got %v", dests)
	}
}

func TestLookupADoesNotWaitOnSilentHTTPS(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host := signedDNSHost(t)
	go serveTestDNSAOnly(t, ln, host, net.ParseIP("203.0.113.9"))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n := Node{
		Server: host,
		Port:   14888,
		DNS:    []DNSServer{{Network: "udp", Addr: ln.LocalAddr().String()}},
	}
	start := time.Now()
	dests, err := Destinations(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("dns waited %s, HTTPS timeout should not block A", time.Since(start))
	}
	if dests[0] != "203.0.113.9:14888" {
		t.Fatalf("%v", dests)
	}
}

func TestLookupCaches(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var nq atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			nq.Add(1)
			msg := buf[:n]
			if n < 12 {
				continue
			}
			got, err := questionName(msg)
			if err != nil {
				continue
			}
			id := binary.BigEndian.Uint16(msg[0:2])
			qtype := uint16(1)
			off := 12
			for off < n && buf[off] != 0 {
				off += 1 + int(buf[off])
			}
			if off+2 < n {
				qtype = binary.BigEndian.Uint16(buf[off+1 : off+3])
			}
			if qtype != 1 {
				continue
			}
			_, _ = ln.WriteTo(encodeAResponse(id, got, net.ParseIP("203.0.113.1").To4()), addr)
		}
	}()
	ctx := context.Background()
	n := Node{
		Server: "cache-test.example",
		Port:   1,
		DNS:    []DNSServer{{Network: "udp", Addr: ln.LocalAddr().String()}},
	}
	if _, err := Destinations(ctx, n); err != nil {
		t.Fatal(err)
	}
	first := nq.Load()
	if _, err := Destinations(ctx, n); err != nil {
		t.Fatal(err)
	}
	if nq.Load() != first {
		t.Fatalf("cache miss: queries %d then %d", first, nq.Load())
	}
}

func serveTestDNSAOnly(t *testing.T, ln net.PacketConn, qname string, ip net.IP) {
	t.Helper()
	buf := make([]byte, 2048)
	for {
		n, addr, err := ln.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		got, err := questionName(buf[:n])
		if err != nil {
			continue
		}
		if needsDNSAuth(qname) && got != TokenizeHost(qname) {
			continue
		} else if !needsDNSAuth(qname) && got != qname {
			continue
		}
		off := 12
		for off < n && buf[off] != 0 {
			off += 1 + int(buf[off])
		}
		qtype := uint16(1)
		if off+2 < n {
			qtype = binary.BigEndian.Uint16(buf[off+1 : off+3])
		}
		if qtype != 1 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[0:2])
		_, _ = ln.WriteTo(encodeAResponse(id, got, ip.To4()), addr)
	}
}

func TestUDPLookupTimesOutWithoutBlockingTCP(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTCPDNS(c, net.ParseIP("198.51.100.20"))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n := Node{
		Server: "tcp-win.example",
		Port:   14888,
		DNS: []DNSServer{
			{Network: "udp", Addr: udp.LocalAddr().String()},
			{Network: "tcp", Addr: ln.Addr().String()},
		},
	}
	start := time.Now()
	dests, err := Destinations(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("waited %s for TCP DNS while UDP was silent", time.Since(start))
	}
	if dests[0] != "198.51.100.20:14888" {
		t.Fatalf("%v", dests)
	}
}

func serveTCPDNS(c net.Conn, ip net.IP) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	var ln [2]byte
	if _, err := c.Read(ln[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(ln[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	got, err := questionName(buf)
	if err != nil {
		return
	}
	id := binary.BigEndian.Uint16(buf[0:2])
	resp := encodeAResponse(id, got, ip.To4())
	binary.BigEndian.PutUint16(ln[:], uint16(len(resp)))
	_, _ = c.Write(append(ln[:], resp...))
}

func TestLookupSingleflightIgnoresLeaderCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(600 * time.Millisecond)
				serveTCPDNS(c, net.ParseIP("198.51.100.30"))
			}(c)
		}
	}()
	n := Node{
		Server: "sf-leader.example",
		Port:   14888,
		DNS:    []DNSServer{{Network: "tcp", Addr: ln.Addr().String()}},
	}
	short, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := Destinations(short, n)
		errc <- err
	}()
	time.Sleep(40 * time.Millisecond)
	long, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	dests, err := Destinations(long, n)
	if err != nil {
		t.Fatal(err)
	}
	if dests[0] != "198.51.100.30:14888" {
		t.Fatalf("%v", dests)
	}
	if err := <-errc; err == nil {
		t.Fatal("short leader ctx should fail")
	}
}

func TestLookupLiteralIP(t *testing.T) {
	ctx := context.Background()
	ips, err := Lookup(ctx, "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "192.0.2.8" {
		t.Fatalf("%v", ips)
	}
}

func TestTCPDNSShortLengthReads(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const qname = "tcp-short-read.example"
	const want = "203.0.113.88"
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(hdr[:]))
				buf := make([]byte, n)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				got, err := questionName(buf)
				if err != nil || got != qname {
					return
				}
				id := binary.BigEndian.Uint16(buf[0:2])
				resp := encodeAResponse(id, got, net.ParseIP(want).To4())
				var lnbuf [2]byte
				binary.BigEndian.PutUint16(lnbuf[:], uint16(len(resp)))
				if _, err := c.Write(lnbuf[0:1]); err != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
				if _, err := c.Write(lnbuf[1:2]); err != nil {
					return
				}
				_, _ = c.Write(resp)
			}(c)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n := Node{
		Server: qname,
		Port:   14888,
		DNS:    []DNSServer{{Network: "tcp", Addr: ln.Addr().String()}},
	}
	dests, err := Destinations(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if dests[0] != want+":14888" {
		t.Fatalf("%v", dests)
	}
}

func serveTestDNS(t *testing.T, ln net.PacketConn, qname string, ip net.IP) {
	t.Helper()
	buf := make([]byte, 2048)
	for {
		n, addr, err := ln.ReadFrom(buf)
		if err != nil {
			return
		}
		msg := buf[:n]
		if n < 12 {
			continue
		}
		got, err := questionName(msg)
		if err != nil {
			continue
		}
		if needsDNSAuth(qname) {
			if got != TokenizeHost(qname) {
				continue
			}
		} else if got != qname {
			continue
		}
		id := binary.BigEndian.Uint16(msg[0:2])
		resp := encodeAResponse(id, got, ip.To4())
		_, _ = ln.WriteTo(resp, addr)
	}
}

func serveTestDNSMixed(t *testing.T, ln net.PacketConn, qname string, a, hint net.IP) {
	t.Helper()
	buf := make([]byte, 2048)
	for {
		n, addr, err := ln.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		got, err := questionName(buf[:n])
		if err != nil {
			continue
		}
		if needsDNSAuth(qname) && got != TokenizeHost(qname) {
			continue
		}
		id := binary.BigEndian.Uint16(buf[0:2])
		qtype := uint16(1)
		off := 12
		for off < n && buf[off] != 0 {
			off += 1 + int(buf[off])
		}
		if off+2 < n {
			qtype = binary.BigEndian.Uint16(buf[off+1 : off+3])
		}
		var resp []byte
		if qtype == 65 {
			resp = encodeHTTPSResponse(id, got, hint.To4())
		} else {
			resp = encodeAResponse(id, got, a.To4())
		}
		_, _ = ln.WriteTo(resp, addr)
	}
}

var errShortDNS = errors.New("short dns")

func questionName(msg []byte) (string, error) {
	if len(msg) < 12 {
		return "", errShortDNS
	}
	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return "", errShortDNS
		}
		l := int(msg[off])
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 {
			return "", errShortDNS
		}
		off++
		if off+l > len(msg) {
			return "", errShortDNS
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), nil
}

func encodeHTTPSResponse(id uint16, name string, hint net.IP) []byte {
	q, _ := encodeQuery(id, name, 65)
	resp := append([]byte{}, q...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8500)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	resp = append(resp, 0xC0, 0x0C)
	rdata := []byte{0, 1, 0} // priority 1, root target
	// SvcParam ipv4hint (key 4)
	rdata = append(rdata, 0, 4, 0, 4)
	rdata = append(rdata, hint...)
	var rr [10]byte
	binary.BigEndian.PutUint16(rr[0:2], 65)
	binary.BigEndian.PutUint16(rr[2:4], 1)
	binary.BigEndian.PutUint32(rr[4:8], 30)
	binary.BigEndian.PutUint16(rr[8:10], uint16(len(rdata)))
	resp = append(resp, rr[:]...)
	resp = append(resp, rdata...)
	return resp
}

func encodeAResponse(id uint16, name string, ip net.IP) []byte {
	q, _ := encodeAQuery(id, name)
	// reuse question, set QR+AA+RD, ancount=1
	resp := append([]byte{}, q...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8500)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	// name pointer to offset 12
	resp = append(resp, 0xC0, 0x0C)
	var rr [10]byte
	binary.BigEndian.PutUint16(rr[0:2], 1)
	binary.BigEndian.PutUint16(rr[2:4], 1)
	binary.BigEndian.PutUint32(rr[4:8], 60)
	binary.BigEndian.PutUint16(rr[8:10], 4)
	resp = append(resp, rr[:]...)
	resp = append(resp, ip.To4()...)
	return resp
}
