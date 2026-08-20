package dialer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// CloudNodesDNS is the helper binary's compiled-in resolver, used only when
// the dedicated YAML has no nameserver-policy for the hostname.
const CloudNodesDNS = "124.221.68.73:1053"

func fallbackCloudNodesDNS() []DNSServer {
	return []DNSServer{
		{Network: "udp", Addr: CloudNodesDNS},
		{Network: "tcp", Addr: CloudNodesDNS},
	}
}

// Lookup returns IPv4 addresses using the system resolver, or a literal IP.
func Lookup(ctx context.Context, host string) ([]net.IP, error) {
	return LookupServers(ctx, host, nil)
}

// LookupServers resolves host via the dedicated-profile nameservers (Clash
// proxy-server-nameserver-policy). Empty servers use the system resolver,
// except *.cloud-nodes.com falls back to the helper's compiled DNS.
func LookupServers(ctx context.Context, host string, servers []DNSServer) ([]net.IP, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []net.IP{v4}, nil
		}
		return []net.IP{ip}, nil
	}
	if len(servers) == 0 && needsPrivateDNS(host) {
		servers = fallbackCloudNodesDNS()
	}
	if len(servers) == 0 {
		var r net.Resolver
		return r.LookupIP(ctx, "ip4", host)
	}
	qname := TokenizeHost(host)
	var last error
	var out []net.IP
	seen := map[string]bool{}
	add := func(ips []net.IP) {
		for _, ip := range ips {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			k := v4.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, append(net.IP(nil), v4...))
		}
	}
	for _, s := range servers {
		netw := s.Network
		if netw == "" {
			netw = "udp"
		}
		// Official helper (SnellCore): remainingIPs is A/AAAA plus HTTPS
		// (rrtype 0x41) ipv4hint. Fusion names are queried as
		// base32(ed25519(host|unix/300)).host; a bare query is a decoy.
		hints, herr := lookupHTTPSHints(ctx, qname, s.Addr, netw)
		if herr == nil {
			add(hints)
		}
		ips, err := lookupA(ctx, qname, s.Addr, netw)
		if err == nil {
			add(ips)
		} else {
			last = err
		}
		if len(out) > 0 {
			return out, nil
		}
		if herr != nil && last == nil {
			last = herr
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if last == nil {
		last = fmt.Errorf("no A records")
	}
	return nil, last
}

// Destinations is the ordered host:port list the dial path connects to.
// It does not read OIX_DIAL_IP. Node.DialIP is only an explicit per-node
// override for tests.
func Destinations(ctx context.Context, n Node) ([]string, error) {
	port := n.Port
	if port <= 0 {
		return nil, fmt.Errorf("missing port")
	}
	ps := strconv.Itoa(port)
	if n.DialIP != "" {
		return []string{net.JoinHostPort(n.DialIP, ps)}, nil
	}
	if n.Server == "" {
		return nil, fmt.Errorf("missing server")
	}
	ips, err := LookupServers(ctx, n.Server, n.DNS)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", n.Server, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no A records", n.Server)
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip.String(), ps))
	}
	return out, nil
}

// SelectDestination is the first address Destinations would dial.
func SelectDestination(ctx context.Context, n Node) (string, error) {
	ds, err := Destinations(ctx, n)
	if err != nil {
		return "", err
	}
	return ds[0], nil
}

func lookupA(ctx context.Context, name, dnsAddr, network string) ([]net.IP, error) {
	msg, err := lookupRaw(ctx, name, dnsAddr, network, 1)
	if err != nil {
		return nil, err
	}
	return parseAAnswers(msg)
}

func lookupHTTPSHints(ctx context.Context, name, dnsAddr, network string) ([]net.IP, error) {
	msg, err := lookupRaw(ctx, name, dnsAddr, network, 65) // HTTPS / SVCB
	if err != nil {
		return nil, err
	}
	return parseHTTPSIPv4Hints(msg)
}

func lookupRaw(ctx context.Context, name, dnsAddr, network string, qtype uint16) ([]byte, error) {
	qid := uint16(time.Now().UnixNano())
	req, err := encodeQuery(qid, name, qtype)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	}
	conn, err := d.DialContext(ctx, network, dnsAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if network == "tcp" {
		var ln [2]byte
		binary.BigEndian.PutUint16(ln[:], uint16(len(req)))
		if _, err := conn.Write(append(ln[:], req...)); err != nil {
			return nil, err
		}
		if _, err := conn.Read(ln[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(ln[:]))
		buf := make([]byte, n)
		if _, err := readFull(conn, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func encodeAQuery(id uint16, name string) ([]byte, error) {
	return encodeQuery(id, name, 1)
}

func encodeQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	buf := make([]byte, 0, 512)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf = append(buf, hdr[:]...)
	for _, lab := range labels {
		if lab == "" {
			continue
		}
		if len(lab) > 63 {
			return nil, fmt.Errorf("dns label too long")
		}
		buf = append(buf, byte(len(lab)))
		buf = append(buf, lab...)
	}
	var qtypeb [2]byte
	binary.BigEndian.PutUint16(qtypeb[:], qtype)
	buf = append(buf, 0, qtypeb[0], qtypeb[1], 0, 1)
	return buf, nil
}

func parseAAnswers(msg []byte) ([]net.IP, error) {
	records, err := iterAnswers(msg)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, rr := range records {
		if rr.typ == 1 && len(rr.rdata) == 4 {
			ip := make(net.IP, 4)
			copy(ip, rr.rdata)
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func parseHTTPSIPv4Hints(msg []byte) ([]net.IP, error) {
	records, err := iterAnswers(msg)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, rr := range records {
		if rr.typ != 65 && rr.typ != 64 {
			continue
		}
		ips = append(ips, ipv4HintsFromHTTPS(msg, rr.rdata)...)
	}
	return ips, nil
}

type dnsRR struct {
	typ   uint16
	rdata []byte
}

func iterAnswers(msg []byte) ([]dnsRR, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("short dns response")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		off, err = skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off += 4
		if off > len(msg) {
			return nil, fmt.Errorf("truncated question")
		}
	}
	var out []dnsRR
	for i := 0; i < an; i++ {
		off, err = skipName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, fmt.Errorf("truncated rr")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, fmt.Errorf("truncated rdata")
		}
		out = append(out, dnsRR{typ: typ, rdata: msg[off : off+rdlen]})
		off += rdlen
	}
	return out, nil
}

func ipv4HintsFromHTTPS(msg, rdata []byte) []net.IP {
	if len(rdata) < 3 {
		return nil
	}
	off := 2 // priority
	off, err := skipNameIn(msg, rdata, off)
	if err != nil {
		return nil
	}
	var ips []net.IP
	for off+4 <= len(rdata) {
		key := binary.BigEndian.Uint16(rdata[off : off+2])
		ln := int(binary.BigEndian.Uint16(rdata[off+2 : off+4]))
		off += 4
		if off+ln > len(rdata) {
			break
		}
		val := rdata[off : off+ln]
		off += ln
		if key == 4 && ln%4 == 0 { // ipv4hint
			for i := 0; i+4 <= len(val); i += 4 {
				ip := make(net.IP, 4)
				copy(ip, val[i:i+4])
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func skipNameIn(msg, rdata []byte, off int) (int, error) {
	// Names in rdata may use compression pointers into msg. Walk rdata only
	// for the on-wire length of this name.
	for {
		if off >= len(rdata) {
			return 0, fmt.Errorf("bad name")
		}
		l := int(rdata[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(rdata) {
				return 0, fmt.Errorf("bad pointer")
			}
			return off + 2, nil
		}
		off += 1 + l
	}
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("bad name")
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return 0, fmt.Errorf("bad pointer")
			}
			return off + 2, nil
		}
		off += 1 + l
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		k, err := c.Read(buf[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
