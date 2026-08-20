package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/soffchen/oixproxy/internal/obf"
)

// Hardcoded v2: blobs from the official helper (same in v0.0.25 / v0.0.29 / Linux v0.0.28).
const (
	// HMAC key (utf-8 of decoded v2:FOOB/...). The other v2:DDDuMI... blob is not the request MAC key.
	blobAppSecret = "v2:FOOB/BGdy79vGP0h2xqgRlCSaGrlU7/eve3oGxBoEsDZIMtn84HlNw=="
	blobAnywhere  = "v2:7UHE0sBVsIHWqgb4E0GWuOnUHpMj9Yq0HbmzNQAzx1N14GCXtNjF"
	blobTS        = "v2:JuFoMbIXMtklDGf3aOy/9yn6qd4d+bV46NnAtQ=="
	blobSig       = "v2:krDWnvot6EKI+LcgCv8cNdx+H1BwR1zxV9D/RQ=="
	blobAgePub    = "v2:sy6ISWcFq8+zmuv4SVh2NM9eXmxWPfAlEF6f4GQ="
	blobRespSig   = "v2:6ZXEUFFYYY0hTyxqxMKLxHX9J6bRCAiy0bLORRMdXWaGcn7Oig=="
)

var protoOnce sync.Once
var proto struct {
	AppSecret string
	Anywhere  string
	HdrTS     string
	HdrSig    string
	HdrAge    string
	HdrResp   string
}

func protoInit() {
	protoOnce.Do(func() {
		proto.AppSecret = obf.Decode(blobAppSecret)
		proto.Anywhere = obf.Decode(blobAnywhere)
		proto.HdrTS = obf.Decode(blobTS)
		proto.HdrSig = obf.Decode(blobSig)
		proto.HdrAge = obf.Decode(blobAgePub)
		proto.HdrResp = obf.Decode(blobRespSig)
	})
}

const (
	anywhereHost = "https://oics.net"
	anywhereUA   = "anywhere-surge-snell"
)

func AppSecret() string {
	protoInit()
	return proto.AppSecret
}

func anywherePath() string {
	protoInit()
	return proto.Anywhere
}

func hdrTimestamp() string {
	protoInit()
	return proto.HdrTS
}

func hdrSignature() string {
	protoInit()
	return proto.HdrSig
}

func hdrAgePubkey() string {
	protoInit()
	return proto.HdrAge
}

func hdrResponseSig() string {
	protoInit()
	return proto.HdrResp
}

// SignAnywhere is HMAC-SHA256(utf8(secret), utf8(timestamp + "." + payload)) as lowercase hex.
// Reversed from 0x1000905d0 (CryptoKit HMAC<SHA256> + "%02x" join).
func SignAnywhere(secret, timestamp, payload string) string {
	return SignAnywhereKey([]byte(secret), timestamp, payload)
}

func SignAnywhereKey(key []byte, timestamp, payload string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func AppSecretBytes() []byte {
	// Helper HMAC key is UTF-8 of the decoded v2 secret string (FlClash:
	// utf8.encode(Secrets.flClashAppSecret)), not the base64-decoded bytes.
	return []byte(AppSecret())
}

func VerifyAnywhere(secret, timestamp, payload, sig string) bool {
	return VerifyAnywhereKey([]byte(secret), timestamp, payload, sig)
}

func VerifyAnywhereKey(key []byte, timestamp, payload, sig string) bool {
	want := SignAnywhereKey(key, timestamp, payload)
	if len(want) != len(sig) {
		return false
	}
	return hmac.Equal([]byte(want), []byte(sig))
}
