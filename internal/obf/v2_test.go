package obf

import "testing"

func TestDecodeKnownBlobs(t *testing.T) {
	cases := map[string]string{
		"v2:f15kne5YokcS9eEIX2apqw==":                             "oics.net",
		"v2:VQRnXVCqZMl0i4pJtJle9m8iNzo=":                         "oixcloud.com",
		"v2:mrBYIrqYU9P/K9k5LIF6":                                 "Bearer ",
		"v2:4kagqvJlPQLYEWuwR1NenRY1q9/2":                         "Authorization",
		"v2:JuFoMbIXMtklDGf3aOy/9yn6qd4d+bV46NnAtQ==":             "X-Anywhere-Timestamp",
		"v2:krDWnvot6EKI+LcgCv8cNdx+H1BwR1zxV9D/RQ==":             "X-Anywhere-Signature",
		"v2:sy6ISWcFq8+zmuv4SVh2NM9eXmxWPfAlEF6f4GQ=":             "X-Anywhere-Age-Pubkey",
		"v2:6ZXEUFFYYY0hTyxqxMKLxHX9J6bRCAiy0bLORRMdXWaGcn7Oig==": "X-Anywhere-Response-Signature",
		"v2:7UHE0sBVsIHWqgb4E0GWuOnUHpMj9Yq0HbmzNQAzx1N14GCXtNjF": "/api/v1/managed/anywhere/direct",
		"v2:vthOQ13PYKfaGmRQvFRP5GZCmcyG":                         "/api/v1/login",
	}
	for in, want := range cases {
		got := Decode(in)
		if got != want {
			t.Fatalf("%s: got %q want %q", in, got, want)
		}
	}
	if Decode("plain") != "plain" {
		t.Fatal("passthrough")
	}
	for _, blob := range []string{
		"v2:BeMEuTC7THjx4pV6fBQ/ZGnQkHxujeM=",
		"v2:MF9wcQuj4yL5XuoQ40mp22uqNDKrsnej0eg=",
	} {
		got := Decode(blob)
		if got == "" || got == blob {
			t.Fatalf("blob %s did not decode", blob)
		}
	}
}
