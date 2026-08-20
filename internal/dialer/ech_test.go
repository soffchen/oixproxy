package dialer

import (
	"encoding/base64"
	"testing"
)

func TestDecodeECH(t *testing.T) {
	raw := []byte{0x00, 0x02, 0xaa, 0xbb}
	b64 := base64.StdEncoding.EncodeToString(raw)
	got, err := decodeECH(b64)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("got %x", got)
	}
	if _, err := decodeECH(""); err == nil {
		t.Fatal("empty ech-config")
	}
}

func TestClientHelloID(t *testing.T) {
	if _, err := clientHelloID("chrome"); err != nil {
		t.Fatal(err)
	}
	if _, err := clientHelloID("chrome120"); err != nil {
		t.Fatal(err)
	}
	if _, err := clientHelloID("not-a-browser"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNodeDefaults(t *testing.T) {
	n := Node{ALPN: "", IdentityVersion: 0, Fingerprint: ""}
	if n.alpn() != "snell-ech/1" {
		t.Fatalf("alpn %s", n.alpn())
	}
	if n.identityVersion() != 2 {
		t.Fatalf("idver %d", n.identityVersion())
	}
	if n.fingerprint() != "chrome" {
		t.Fatalf("fp %s", n.fingerprint())
	}
}
