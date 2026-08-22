package snell

import (
	"bytes"
	"net"
	"testing"
)

func TestUDPRequestIPv4RoundTripShape(t *testing.T) {
	pkt, err := encodeUDPRequest("1.2.3.4", 53, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{cmdUDPForward, 0x00, 0x04, 1, 2, 3, 4, 0, 53, 'a', 'b', 'c'}
	if !bytes.Equal(pkt, want) {
		t.Fatalf("%x", pkt)
	}
}

func TestUDPRequestDomain(t *testing.T) {
	pkt, err := encodeUDPRequest("dns.google", 53, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != cmdUDPForward || pkt[1] != byte(len("dns.google")) {
		t.Fatalf("%x", pkt)
	}
	if string(pkt[2:2+len("dns.google")]) != "dns.google" {
		t.Fatal(string(pkt))
	}
}

func TestUDPResponseParse(t *testing.T) {
	raw := []byte{0x04, 8, 8, 8, 8, 0, 53, 9, 9}
	addr, payload, err := parseUDPResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ua := addr.(*net.UDPAddr)
	if !ua.IP.Equal(net.IPv4(8, 8, 8, 8)) || ua.Port != 53 {
		t.Fatalf("%v", ua)
	}
	if !bytes.Equal(payload, []byte{9, 9}) {
		t.Fatalf("%x", payload)
	}
}
