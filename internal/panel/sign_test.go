package panel

import (
	"testing"
)

func TestDecodedProtocolConstants(t *testing.T) {
	if len(AppSecret()) != 32 {
		t.Fatalf("app secret len %d", len(AppSecret()))
	}
	if anywherePath() != "/api/v1/managed/anywhere/direct" {
		t.Fatalf("path %q", anywherePath())
	}
	if hdrTimestamp() != "X-Anywhere-Timestamp" {
		t.Fatal(hdrTimestamp())
	}
	if hdrSignature() != "X-Anywhere-Signature" {
		t.Fatal(hdrSignature())
	}
	if hdrAgePubkey() != "X-Anywhere-Age-Pubkey" {
		t.Fatal(hdrAgePubkey())
	}
	if hdrResponseSig() != "X-Anywhere-Response-Signature" {
		t.Fatal(hdrResponseSig())
	}
}

func TestSignAnywhereStable(t *testing.T) {
	a := SignAnywhere("secret", "1700000000", "age1abc")
	b := SignAnywhere("secret", "1700000000", "age1abc")
	if a != b || len(a) != 64 {
		t.Fatalf("%s", a)
	}
	if !VerifyAnywhere("secret", "1700000000", "age1abc", a) {
		t.Fatal("verify")
	}
	if VerifyAnywhere("secret", "1700000000", "age1abc", "00"+a[2:]) {
		t.Fatal("mismatch should fail")
	}
}
