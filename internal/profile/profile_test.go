package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFlowStyle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "n.yaml")
	yaml := `
proxies:
  - { name: "hk 01", type: snell, server: hk.example, port: 14888, psk: test-psk, version: 4, reuse: true, udp: true, tfo: true, identity: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA, path: /ws-tunnel-test, identity-version: 2, legacy-fallback: false, preconnect: 2, skip-cert-verify: false } }
  - { name: "ss 01", type: ss, server: x, port: 1 }
`
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("got %d", len(nodes))
	}
	n := nodes[0]
	if n.Name != "hk 01" || n.Port != 14888 || n.PSK != "test-psk" || n.ALPN != "snell-ech/1" || n.ECHConfig != "AAAA" || n.Path != "/ws-tunnel-test" || n.IdentityVersion != 2 {
		t.Fatalf("%+v", n)
	}
	if !n.Reuse || !n.TFO || !n.UDP || n.LegacyFallback || n.Preconnect != 2 {
		t.Fatalf("flclash fields %+v", n)
	}
}

func TestParseDNSPolicyFromRemoteYAML(t *testing.T) {
	yaml := `
dns:
  enable: true
  default-nameserver: [119.29.29.29]
  proxy-server-nameserver-policy:
    +.cloud-nodes.com: ['udp://124.221.68.73:1053', 'tcp://124.221.68.73:1053']
  nameserver-policy:
    +.example.com: ['udp://192.0.2.53:53']
proxies:
  - { name: "hk 01", type: snell, server: fusion_hk_1.cloud-nodes.com, port: 14888, psk: test-psk, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }
`
	nodes, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes %d", len(nodes))
	}
	if len(nodes[0].DNS) != 2 {
		t.Fatalf("dns %v", nodes[0].DNS)
	}
	if nodes[0].DNS[0].Addr != "124.221.68.73:1053" || nodes[0].DNS[0].Network != "udp" {
		t.Fatalf("udp server %+v", nodes[0].DNS[0])
	}
	if nodes[0].DNS[1].Addr != "124.221.68.73:1053" || nodes[0].DNS[1].Network != "tcp" {
		t.Fatalf("tcp server %+v", nodes[0].DNS[1])
	}
	if !nodes[0].LegacyFallback {
		t.Fatal("omitted legacy-fallback should default true")
	}
}

func TestParseSurgeLegacyFallbackDefault(t *testing.T) {
	nodes, err := Parse([]byte(`[Proxy]
hk = snell, hk.example, 14888, psk=test-psk, obfs=ech-tls, ech-config=AAAA, obfs-host=cover.example
jp = snell, jp.example, 14888, psk=test-psk, obfs=ech-tls, ech-config=AAAA, obfs-host=cover.example, legacy-fallback=false
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes %d", len(nodes))
	}
	if !nodes[0].LegacyFallback {
		t.Fatal("omitted surge legacy-fallback should default true")
	}
	if nodes[1].LegacyFallback {
		t.Fatal("explicit false must stay false")
	}
}

func TestParseRejectsAnytlsOnly(t *testing.T) {
	_, err := Parse([]byte(`proxies:
  - { name: "edge", type: anytls, server: x, port: 443, password: p }
`))
	if err == nil {
		t.Fatal("anytls-only must fail")
	}
}

func TestLoadDecryptedIfPresent(t *testing.T) {
	p := os.Getenv("OIX_PROFILE")
	if p == "" {
		t.Skip("set OIX_PROFILE to a real yaml to check parsing")
	}
	nodes, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 {
		t.Fatal("empty")
	}
	t.Logf("parsed %d nodes, first=%s", len(nodes), nodes[0].Name)
}
