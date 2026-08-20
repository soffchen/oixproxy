package dialer

import (
	"crypto/ed25519"
	"encoding/base32"
	"strconv"
	"strings"
	"testing"
)

func TestTokenizeHostLeavesPlainNames(t *testing.T) {
	if got := TokenizeHost("example.com"); got != "example.com" {
		t.Fatalf("got %s", got)
	}
	if got := TokenizeHost("192.0.2.1"); got != "192.0.2.1" {
		t.Fatalf("got %s", got)
	}
}

func TestTokenizeHostSignsCloudNodes(t *testing.T) {
	const host = "fusion_hk_1.cloud-nodes.com"
	got := TokenizeHost(host)
	if got == host {
		t.Fatal("missing DNS-Auth labels")
	}
	if !strings.HasSuffix(got, "."+host) {
		t.Fatalf("suffix %s", got)
	}
	labels := strings.Split(got, ".")
	// p1.p2.fusion_hk_1.cloud-nodes.com
	if len(labels) != 5 {
		t.Fatalf("labels %v", labels)
	}
	if len(labels[0]) != 52 || len(labels[1]) != 52 {
		t.Fatalf("label lengths %d %d", len(labels[0]), len(labels[1]))
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	p1, err := enc.DecodeString(strings.ToUpper(labels[0]))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := enc.DecodeString(strings.ToUpper(labels[1]))
	if err != nil {
		t.Fatal(err)
	}
	sig := append(append([]byte{}, p1...), p2...)
	window := dnsAuthNow() / dnsAuthWindow
	msg := []byte(host + "|" + strconv.FormatInt(window, 10))
	dnsAuthInit()
	if !ed25519.Verify(dnsAuthKey.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("signature does not verify")
	}
	again := tokenizeHostWindow(host, window)
	if again != got {
		t.Fatalf("not stable in window: %s vs %s", got, again)
	}
}
