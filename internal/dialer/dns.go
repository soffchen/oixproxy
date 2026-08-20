package dialer

import (
	"net"
	"strconv"
	"strings"
)

// DNSServer is one nameserver taken from the dedicated Clash YAML
// (proxy-server-nameserver-policy / nameserver-policy).
type DNSServer struct {
	Network string // udp or tcp
	Addr    string // host:port
}

// ParseNameserver parses Clash DNS entries such as
// "udp://124.221.68.73:1053", "tcp://host:53", or "1.1.1.1".
// DoH/DoT schemes are skipped (they would recurse through the proxy).
func ParseNameserver(s string) (DNSServer, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DNSServer{}, false
	}
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	network := "udp"
	switch {
	case strings.HasPrefix(s, "udp://"):
		s = strings.TrimPrefix(s, "udp://")
		network = "udp"
	case strings.HasPrefix(s, "tcp://"):
		s = strings.TrimPrefix(s, "tcp://")
		network = "tcp"
	case strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "tls://"), strings.HasPrefix(s, "quic://"), strings.HasPrefix(s, "h3://"):
		return DNSServer{}, false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host = s
		port = "53"
	}
	if host == "" {
		return DNSServer{}, false
	}
	if _, err := strconv.Atoi(port); err != nil {
		port = "53"
	}
	return DNSServer{Network: network, Addr: net.JoinHostPort(host, port)}, true
}

// DomainMatch implements Clash nameserver-policy keys: exact, "+.suffix", "*.suffix".
func DomainMatch(pattern, host string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if p == "" || h == "" {
		return false
	}
	switch {
	case strings.HasPrefix(p, "+."):
		root := strings.TrimPrefix(p, "+")
		return h == strings.TrimPrefix(p, "+.") || strings.HasSuffix(h, root)
	case strings.HasPrefix(p, "*."):
		return strings.HasSuffix(h, p[1:])
	default:
		return h == p
	}
}
