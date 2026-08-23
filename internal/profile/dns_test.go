package profile

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/soffchen/oixproxy/internal/dialer"
)

func TestDNSPolicyExactBeatsWildcard(t *testing.T) {
	p := ParseDNS([]byte(`
dns:
  nameserver-policy:
    "+.example.com": ['udp://192.0.2.1:53']
    example.com: ['udp://192.0.2.2:53']
    "*.example.com": ['udp://192.0.2.3:53']
`))
	got := p.Match("example.com")
	if len(got) != 1 || got[0].Addr != "192.0.2.2:53" {
		t.Fatalf("exact %v", got)
	}
	got = p.Match("foo.example.com")
	if len(got) != 1 || got[0].Addr != "192.0.2.1:53" {
		t.Fatalf("plus %v", got)
	}
	got = p.Match("other.test")
	if len(got) != 0 {
		t.Fatalf("fallback %v", got)
	}
}

func TestDNSPolicyLongerSuffixBeatsBroaderType(t *testing.T) {
	p := ParseDNS([]byte(`
dns:
  nameserver-policy:
    "+.com": ['udp://192.0.2.1:53']
    "*.example.com": ['udp://192.0.2.9:53']
    "+.example.com": ['udp://192.0.2.8:53']
`))
	got := p.Match("www.example.com")
	if len(got) != 1 || got[0].Addr != "192.0.2.8:53" {
		t.Fatalf("plus example %v", got)
	}
	got = p.Match("foo.com")
	if len(got) != 1 || got[0].Addr != "192.0.2.1:53" {
		t.Fatalf("plus com %v", got)
	}

	p = ParseDNS([]byte(`
dns:
  nameserver-policy:
    "+.com": ['udp://192.0.2.1:53']
    "*.example.com": ['udp://192.0.2.9:53']
`))
	got = p.Match("www.example.com")
	if len(got) != 1 || got[0].Addr != "192.0.2.9:53" {
		t.Fatalf("star example %v", got)
	}
}

func TestDestinationsUseRemoteDNSPolicy(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			id := binary.BigEndian.Uint16(buf[0:2])
			q, _ := encodeQuery(id, "fusion_hk_1.cloud-nodes.com")
			resp := append([]byte{}, q...)
			binary.BigEndian.PutUint16(resp[2:4], 0x8500)
			binary.BigEndian.PutUint16(resp[6:8], 1)
			resp = append(resp, 0xC0, 0x0C)
			var rr [10]byte
			binary.BigEndian.PutUint16(rr[0:2], 1)
			binary.BigEndian.PutUint16(rr[2:4], 1)
			binary.BigEndian.PutUint32(rr[4:8], 30)
			binary.BigEndian.PutUint16(rr[8:10], 4)
			resp = append(resp, rr[:]...)
			resp = append(resp, net.ParseIP("203.0.113.77").To4()...)
			_, _ = ln.WriteTo(resp, addr)
		}
	}()

	yaml := strings.ReplaceAll(`
dns:
  proxy-server-nameserver-policy:
    +.cloud-nodes.com: ['udp://DNSADDR']
proxies:
  - { name: "hk 01", type: snell, server: fusion_hk_1.cloud-nodes.com, port: 14888, psk: test-psk, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }
`, "DNSADDR", ln.LocalAddr().String())
	nodes, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes[0].DNS) != 1 || nodes[0].DNS[0].Addr != ln.LocalAddr().String() {
		t.Fatalf("parsed dns %+v want %s", nodes[0].DNS, ln.LocalAddr())
	}
	t.Setenv("OIX_DIAL_IP", "198.51.100.1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := dialer.SelectDestination(ctx, nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	if got != "203.0.113.77:14888" {
		t.Fatalf("got %s", got)
	}
}

func encodeQuery(id uint16, name string) ([]byte, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	for _, lab := range strings.Split(name, ".") {
		buf = append(buf, byte(len(lab)))
		buf = append(buf, lab...)
	}
	buf = append(buf, 0, 0, 1, 0, 1)
	return buf, nil
}
