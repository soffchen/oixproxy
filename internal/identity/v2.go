// Package identity implements Dler Snell ECH-TLS identity headers.
//
// DLSNID02 binds a PSK-derived identity to the current TLS 1.3 session
// exporter and the Snell v4 salt so a captured first frame cannot be
// replayed on another connection.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

const (
	AuthRootLabel = "oix/snell-ech/2/auth-root"
	IdentityInfo  = "identity"
	AuthInfo      = "authentication"
	MagicV1       = "DLSNID01"
	MagicV2       = "DLSNID02"
	ExporterLabel = "EXPORTER-Dler-Snell-Identity-v2"
	ExporterSize  = 32
	SaltSize      = 16
	HeaderSize    = 16
	TagSize       = 16
	V2PrefixSize  = 8 + HeaderSize + TagSize // 40
	V1PrefixSize  = 8 + HeaderSize           // 24
	ALPNSnellECH  = "snell-ech/1"
)

func identityV2Root(psk []byte) []byte {
	key := sha256.Sum256([]byte(AuthRootLabel))
	mac := hmac.New(sha256.New, key[:])
	mac.Write(psk)
	return mac.Sum(nil)
}

func identityV2Expand(root []byte, info string) []byte {
	mac := hmac.New(sha256.New, root)
	mac.Write([]byte(info))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

// HeaderFromPSK is the 16-byte static identity header derived from the node PSK.
func HeaderFromPSK(psk []byte) []byte {
	root := identityV2Root(psk)
	expanded := identityV2Expand(root, IdentityInfo)
	out := make([]byte, HeaderSize)
	copy(out, expanded[:HeaderSize])
	return out
}

// AuthTag binds the static header to the TLS exporter and the per-connection salt.
func AuthTag(psk, exporter, salt []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("snell identity psk is empty")
	}
	if len(exporter) != ExporterSize {
		return nil, fmt.Errorf("snell identity exporter length %d", len(exporter))
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("snell identity salt length %d", len(salt))
	}
	root := identityV2Root(psk)
	macKey := identityV2Expand(root, AuthInfo)
	header := HeaderFromPSK(psk)
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(MagicV2))
	mac.Write(exporter)
	mac.Write(salt)
	mac.Write(header)
	sum := mac.Sum(nil)
	out := make([]byte, TagSize)
	copy(out, sum[:TagSize])
	return out, nil
}

// PrefixV2 is the plaintext blob written after the client salt on the first frame:
//
//	DLSNID02 || header(16) || tag(16)
func PrefixV2(psk, exporter, salt []byte) ([]byte, error) {
	tag, err := AuthTag(psk, exporter, salt)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, V2PrefixSize)
	out = append(out, MagicV2...)
	out = append(out, HeaderFromPSK(psk)...)
	out = append(out, tag...)
	return out, nil
}
