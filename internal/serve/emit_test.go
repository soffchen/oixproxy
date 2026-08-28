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

func TestRewriteReplacesExistingAutoGroupsOnce(t *testing.T) {
	tmpl := []byte(`[Proxy]
remote = snell, example.com, 443

[Proxy Group]
Auto - UrlTest = url-test, remote, url=https://example.com/generate_204, policy-regex-filter="HK,JP", policy-name-filter="HK\",JP", interval=300, tolerance=50, hidden=true
Auto - Smart = smart, remote, interval=600, include-all-proxies=false
`)
	got := RewriteSurge(tmpl, testMaps(), "http://127.0.0.1:6172/", "127.0.0.1")
	if strings.Count(got, "Auto - UrlTest =") != 1 || strings.Count(got, "Auto - Smart =") != 1 {
		t.Fatalf("自动组重复定义:\n%s", got)
	}
	if strings.Contains(got, "Auto - UrlTest = url-test, remote") || strings.Contains(got, "Auto - Smart = smart, remote") {
		t.Fatalf("自动组仍引用远端节点:\n%s", got)
	}
	for _, option := range []string{
		"url=https://example.com/generate_204",
		`policy-regex-filter="HK,JP"`,
		`policy-name-filter="HK\",JP"`,
		"interval=300",
		"tolerance=50",
		"hidden=true",
		"interval=600",
		"include-all-proxies=false",
	} {
		if !strings.Contains(got, option) {
			t.Fatalf("自动组丢失参数 %s:\n%s", option, got)
		}
	}
	for _, name := range []string{"🇭🇰 香港 Fusion 01", "🇯🇵 日本 Fusion 01"} {
		if !strings.Contains(got, name) {
			t.Fatalf("自动组缺少 %s:\n%s", name, got)
		}
	}
}

func TestSurgeGroupNames(t *testing.T) {
	template := []byte(`[Proxy]
node = socks5, 127.0.0.1, 7200

[Proxy Group]
# comment
Domestic = select, node
AdBlock=select, Block
domestic = select, Direct

[Rule]
FINAL,Domestic
`)
	names := SurgeGroupNames(template)
	if len(names) != 2 || names[0] != "Domestic" || names[1] != "AdBlock" {
		t.Fatalf("names=%v", names)
	}
}

func TestSOCKSAuthEmittedPerMapping(t *testing.T) {
	maps := testMaps()
	maps[0].User, maps[0].Pass = "alice", "secret"
	maps[0].UDP = true
	host := "203.0.113.10"
	list := ProxyList(maps, host)
	if !strings.Contains(list, "🇭🇰 香港 Fusion 01 = socks5, 203.0.113.10, 7200, alice, secret, udp-relay=true") {
		t.Fatalf("list auth: %s", list)
	}
	if strings.Contains(list, "🇯🇵 日本 Fusion 01 = socks5, 203.0.113.10, 7201, alice") {
		t.Fatal("unauthenticated mapping leaked lanAuth")
	}
	clash := ClashConfig(maps, host)
	if !strings.Contains(clash, `username: "alice"`) || !strings.Contains(clash, `password: "secret"`) {
		t.Fatalf("clash auth: %s", clash)
	}
	if strings.Count(clash, `username:`) != 1 {
		t.Fatalf("clash username count: %s", clash)
	}
	surge := SurgeConfig(maps, "http://203.0.113.10:6172/", host, nil)
	if !strings.Contains(surge, "🇭🇰 香港 Fusion 01 = socks5, 203.0.113.10, 7200, alice, secret, udp-relay=true") {
		t.Fatalf("surge auth: %s", surge)
	}
}

func TestMappingCanAdvertiseItsBoundHost(t *testing.T) {
	maps := testMaps()
	maps[0].Host = "192.0.2.10"
	list := ProxyList(maps, "203.0.113.10")
	if !strings.Contains(list, "🇭🇰 香港 Fusion 01 = socks5, 192.0.2.10, 7200") {
		t.Fatalf("固定监听地址未写入列表: %s", list)
	}
	if !strings.Contains(list, "🇯🇵 日本 Fusion 01 = socks5, 203.0.113.10, 7201") {
		t.Fatalf("默认监听地址未使用请求 Host: %s", list)
	}
	clash := ClashConfig(maps, "203.0.113.10")
	if !strings.Contains(clash, "server: 192.0.2.10") || !strings.Contains(clash, "server: 203.0.113.10") {
		t.Fatalf("Clash 地址错误: %s", clash)
	}
}

func TestSOCKSAuthSurgeQuotesSeparators(t *testing.T) {
	maps := testMaps()
	maps[0].User, maps[0].Pass = "al,ice", `se"cret`
	list := ProxyList(maps, "203.0.113.10")
	if !strings.Contains(list, `🇭🇰 香港 Fusion 01 = socks5, 203.0.113.10, 7200, "al,ice", "se\"cret"`) {
		t.Fatalf("quoted list: %s", list)
	}
	clash := ClashConfig(maps, "203.0.113.10")
	if !strings.Contains(clash, `username: "al,ice"`) || !strings.Contains(clash, `password: "se\"cret"`) {
		t.Fatalf("clash: %s", clash)
	}
}

func TestUDPAdvertisedWhenEnabled(t *testing.T) {
	maps := testMaps()
	if strings.Contains(ProxyList(maps, "127.0.0.1"), "udp-relay") {
		t.Fatal("udp off")
	}
	maps[0].UDP = true
	maps[1].UDP = true
	list := ProxyList(maps, "127.0.0.1")
	if !strings.Contains(list, "udp-relay=true") {
		t.Fatal(list)
	}
	clash := ClashConfig(maps, "127.0.0.1")
	if !strings.Contains(clash, "udp: true") {
		t.Fatal(clash)
	}
	listLAN := ProxyList(maps, "203.0.113.10")
	if !strings.Contains(listLAN, "udp-relay=true") {
		t.Fatal(listLAN)
	}
	if !strings.Contains(ClashConfig(maps, "203.0.113.10"), "udp: true") {
		t.Fatal("lan clash should advertise udp")
	}
}
