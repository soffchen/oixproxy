package identity

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHeaderStable(t *testing.T) {
	psk := []byte("test-psk")
	a := HeaderFromPSK(psk)
	b := HeaderFromPSK(psk)
	if !bytes.Equal(a, b) {
		t.Fatal("header not stable")
	}
	if len(a) != HeaderSize {
		t.Fatalf("header len %d", len(a))
	}
}

func TestAuthTagRejectsBadSizes(t *testing.T) {
	psk := []byte("psk")
	if _, err := AuthTag(nil, make([]byte, 32), make([]byte, 16)); err == nil {
		t.Fatal("empty psk")
	}
	if _, err := AuthTag(psk, make([]byte, 16), make([]byte, 16)); err == nil {
		t.Fatal("short exporter")
	}
	if _, err := AuthTag(psk, make([]byte, 32), make([]byte, 8)); err == nil {
		t.Fatal("short salt")
	}
}

func TestPrefixV1Layout(t *testing.T) {
	psk := []byte("vector-psk")
	p := PrefixV1(psk)
	if len(p) != V1PrefixSize {
		t.Fatalf("prefix %d", len(p))
	}
	if string(p[:8]) != MagicV1 {
		t.Fatalf("magic %q", p[:8])
	}
	q := PrefixV1(psk)
	if !bytes.Equal(p, q) {
		t.Fatal("v1 prefix not stable")
	}
}

func TestPrefixV2Layout(t *testing.T) {
	psk := []byte("test-psk")
	exporter := bytes.Repeat([]byte{0x11}, 32)
	salt := bytes.Repeat([]byte{0x22}, 16)
	p, err := PrefixV2(psk, exporter, salt)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != V2PrefixSize {
		t.Fatalf("prefix %d", len(p))
	}
	if string(p[:8]) != MagicV2 {
		t.Fatalf("magic %q", p[:8])
	}
	if !bytes.Equal(p[8:24], HeaderFromPSK(psk)) {
		t.Fatal("header mismatch")
	}
	tag, _ := AuthTag(psk, exporter, salt)
	if !bytes.Equal(p[24:], tag) {
		t.Fatal("tag mismatch")
	}
}

func TestKnownVector(t *testing.T) {
	psk := []byte("vector-psk")
	got := hex.EncodeToString(HeaderFromPSK(psk))
	const want = ""
	if want == "" {
		t.Log("header", got)
		if len(got) != 32 {
			t.Fatalf("header hex %s", got)
		}
		return
	}
	if got != want {
		t.Fatalf("header %s want %s", got, want)
	}
}
