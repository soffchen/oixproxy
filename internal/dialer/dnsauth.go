package dialer

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/soffchen/oixproxy/internal/obf"
)

// Official helper / FlClash DNS-Auth: 1053 answers the real node A only when
// the QNAME is two base32 labels of an Ed25519 signature over
// "{hostname}|{unix/300}". A bare fusion_*.cloud-nodes.com query returns the
// decoy 119.40.182.189.
const (
	blobDNSAuthSeed   = "v2:DDDuMItojgbE/L++M/zoUEkxK5qDdczw7XEeUXbpTdi7E9ht5E3k1j/xO4PHT4ikxyvx1g=="
	blobDNSAuthDomain = "v2:BeMEuTC7THjx4pV6fBQ/ZGnQkHxujeM="
	dnsAuthWindow     = int64(300)
)

var (
	dnsAuthOnce   sync.Once
	dnsAuthKey    ed25519.PrivateKey
	dnsAuthSuffix string
	dnsAuthNow    = func() int64 { return time.Now().Unix() }
)

func dnsAuthInit() {
	dnsAuthOnce.Do(func() {
		dnsAuthSuffix = strings.ToLower(strings.TrimSuffix(obf.Decode(blobDNSAuthDomain), "."))
		raw := strings.TrimSpace(obf.Decode(blobDNSAuthSeed))
		seed, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(seed) != ed25519.SeedSize {
			return
		}
		dnsAuthKey = ed25519.NewKeyFromSeed(seed)
	})
}

func needsDNSAuth(host string) bool {
	dnsAuthInit()
	if dnsAuthKey == nil || dnsAuthSuffix == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return h == dnsAuthSuffix || strings.HasSuffix(h, "."+dnsAuthSuffix)
}

// TokenizeHost prepends the DNS-Auth signature labels used by the official
// helper when resolving dedicated Fusion hostnames. Other names are unchanged.
func TokenizeHost(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" || !needsDNSAuth(h) {
		return host
	}
	return tokenizeHostWindow(h, dnsAuthNow()/dnsAuthWindow)
}

func tokenizeHostWindow(name string, window int64) string {
	dnsAuthInit()
	if dnsAuthKey == nil {
		return name
	}
	msg := make([]byte, 0, len(name)+1+20)
	msg = append(msg, name...)
	msg = append(msg, '|')
	msg = strconv.AppendInt(msg, window, 10)
	sig := ed25519.Sign(dnsAuthKey, msg)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	p1 := strings.ToLower(enc.EncodeToString(sig[:ed25519.SignatureSize/2]))
	p2 := strings.ToLower(enc.EncodeToString(sig[ed25519.SignatureSize/2:]))
	return p1 + "." + p2 + "." + name
}
