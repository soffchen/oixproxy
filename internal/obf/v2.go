// Package obf implements the helper's compile-time v2: string deobfuscation.
//
// Reversed from oixcloud-external-proxy-program (macOS amd64 v0.0.29 @ 0x100088070):
//
//	blob = base64(strip "v2:")
//	key  = SHA256(kA || kB || "oix-obf-v2-exp")
//	ks   = SHA256(key || blob[:8] || be32(i)) for i = 0,1,...
//	plain = blob[8:] XOR ks
package obf

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

const (
	Label  = "oix-obf-v2-exp"
	Prefix = "v2:"
)

// kA and kB are the two static 16-byte arrays hashed with Label (0x100087750).
var (
	kA = []byte{0x2f, 0x84, 0xb1, 0x6d, 0xc0, 0x39, 0x9e, 0x47, 0xf2, 0x1b, 0xa8, 0x53, 0xce, 0x70, 0x35, 0xd9}
	kB = []byte{0x61, 0xcd, 0x0a, 0x97, 0x4e, 0xe3, 0x28, 0xbf, 0x14, 0x8c, 0x52, 0xf9, 0x3d, 0xa6, 0x1f, 0xc7}
)

func expandKey() []byte {
	h := sha256.New()
	h.Write(kA)
	h.Write(kB)
	h.Write([]byte(Label))
	return h.Sum(nil)
}

// Decode expands a v2: blob. Non-v2 input is returned unchanged.
func Decode(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Prefix) {
		return s
	}
	raw, err := base64.StdEncoding.DecodeString(s[len(Prefix):])
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s[len(Prefix):])
	}
	if err != nil || len(raw) < 8 {
		return s
	}
	key := expandKey()
	rest := raw[8:]
	ks := make([]byte, 0, len(rest)+32)
	var ctr uint32
	for len(ks) < len(rest) {
		h := sha256.New()
		h.Write(key)
		h.Write(raw[:8])
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], ctr)
		h.Write(be[:])
		ks = append(ks, h.Sum(nil)...)
		ctr++
	}
	out := make([]byte, len(rest))
	for i := range rest {
		out[i] = rest[i] ^ ks[i]
	}
	return string(out)
}
