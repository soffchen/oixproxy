package dialer

import "testing"

func TestParseNameserver(t *testing.T) {
	s, ok := ParseNameserver("udp://124.221.68.73:1053")
	if !ok || s.Network != "udp" || s.Addr != "124.221.68.73:1053" {
		t.Fatalf("%+v %v", s, ok)
	}
	s, ok = ParseNameserver("tcp://124.221.68.73:1053")
	if !ok || s.Network != "tcp" {
		t.Fatalf("%+v", s)
	}
	s, ok = ParseNameserver("119.29.29.29")
	if !ok || s.Addr != "119.29.29.29:53" || s.Network != "udp" {
		t.Fatalf("%+v", s)
	}
	if _, ok := ParseNameserver("https://1.1.1.1/dns-query#Proxy"); ok {
		t.Fatal("doh should be skipped")
	}
}

func TestDomainMatch(t *testing.T) {
	if !DomainMatch("+.cloud-nodes.com", "fusion_hk_1.cloud-nodes.com") {
		t.Fatal("subdomain")
	}
	if !DomainMatch("+.cloud-nodes.com", "cloud-nodes.com") {
		t.Fatal("apex")
	}
	if DomainMatch("+.cloud-nodes.com", "evil.com") {
		t.Fatal("negative")
	}
}
