package serve

import (
	"strings"
	"testing"

	"github.com/soffchen/oixproxy/internal/dialer"
)

func testMaps() []Mapping {
	return []Mapping{
		{Node: dialer.Node{Name: "🇭🇰 香港 Fusion 01", PSK: "secret-psk", ECHConfig: "secret-ech"}, Port: 7200},
		{Node: dialer.Node{Name: "🇯🇵 日本 Fusion 01", PSK: "secret-psk-2", ECHConfig: "secret-ech"}, Port: 7201},
	}
}

func TestClientFacingArtifactsAreLocalSOCKS(t *testing.T) {
	maps := testMaps()
	host := "203.0.113.10"
	clash := ClashConfig(maps, host)
	list := ProxyList(maps, host)
	surge := SurgeConfig(maps, "http://203.0.113.10:6172/", host, nil)

	for name, body := range map[string]string{"clash": clash, "list": list, "surge": surge} {
		if strings.Contains(body, "type: snell") || strings.Contains(body, "type: anytls") {
			t.Fatalf("%s leaked remote protocol", name)
		}
		if strings.Contains(body, "psk:") || strings.Contains(body, "psk=") {
			t.Fatalf("%s leaked psk", name)
		}
		if strings.Contains(body, "ech-config") {
			t.Fatalf("%s leaked ech-config", name)
		}
		if strings.Contains(body, "secret-psk") || strings.Contains(body, "password:") {
			t.Fatalf("%s leaked secret", name)
		}
		if !strings.Contains(strings.ToLower(body), "socks5") {
			t.Fatalf("%s missing socks5", name)
		}
		if !strings.Contains(body, "7200") || !strings.Contains(body, "7201") {
			t.Fatalf("%s missing mapped ports", name)
		}
		if !strings.Contains(body, "🇭🇰 香港 Fusion 01") || !strings.Contains(body, "🇯🇵 日本 Fusion 01") {
			t.Fatalf("%s missing node names", name)
		}
	}
	if !strings.Contains(clash, "type: socks5") {
		t.Fatal("clash proxy type")
	}
	if !strings.Contains(list, "= socks5, 203.0.113.10, 7200") {
		t.Fatalf("list line: %s", list)
	}
	if !strings.Contains(surge, "[Proxy]") || !strings.Contains(surge, " = socks5, 203.0.113.10, 7200") {
		t.Fatal("surge proxy line")
	}
}

func TestRewriteHelperTemplateToLocalSOCKS(t *testing.T) {
	tmpl := []byte(`#!MANAGED-CONFIG https://oics.net/api/v3/download.getFile/x?external-proxy-program=true interval=86400

[Proxy]
Direct = direct
Block = reject

oixCloud = socks5, 127.0.0.1, 7100, udp-relay=true

[Proxy Group]
Proxy = select, oixCloud, Direct
Domestic = select, Direct, Proxy
AdBlock = select, Block, Direct, Proxy
`)
	maps := testMaps()
	got := SurgeConfig(maps, "http://203.0.113.10:6172/", "203.0.113.10", tmpl)
	if strings.Contains(got, "oixCloud") {
		t.Fatal("oixCloud leftover in proxy")
	}
	if strings.Contains(got, "7100") || strings.Contains(got, "udp-relay") {
		t.Fatal("lan should not keep helper 7100/udp-relay")
	}
	if !strings.Contains(got, "🇭🇰 香港 Fusion 01 = socks5, 203.0.113.10, 7200") {
		t.Fatalf("missing socks: %s", got)
	}
	if !strings.Contains(got, "#!MANAGED-CONFIG http://203.0.113.10:6172/") {
		t.Fatal("managed url")
	}
	if !strings.Contains(got, "Proxy = select, Auto - Smart, Auto - UrlTest, Direct") {
		t.Fatalf("proxy group: %s", got)
	}
	if !strings.Contains(got, "Auto - UrlTest = url-test,") || !strings.Contains(got, "Auto - Smart = smart,") {
		t.Fatal("auto groups")
	}
	if !strings.Contains(got, "AdBlock = select, Block, Direct, Proxy") {
		t.Fatal("adblock should stay compact")
	}
	if strings.Contains(got, "psk") || strings.Contains(got, "ech-config") || strings.Contains(got, "snell") {
		t.Fatal("leaked dedicated protocol")
	}
}

func TestLoopbackAddsUDPRelay(t *testing.T) {
	maps := testMaps()
	list := ProxyList(maps, "127.0.0.1")
	if !strings.Contains(list, "udp-relay=true") {
		t.Fatal(list)
	}
	clash := ClashConfig(maps, "127.0.0.1")
	if !strings.Contains(clash, "udp: true") {
		t.Fatal(clash)
	}
	lan := ProxyList(maps, "203.0.113.10")
	if strings.Contains(lan, "udp-relay") {
		t.Fatal(lan)
	}
}
