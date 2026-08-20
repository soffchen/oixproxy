package identity

import "github.com/metacubex/blake3"

// PrefixV1 is the Clash.Meta / Snell v4 identity blob written after the
// client salt: DLSNID01 || blake3-512(psk)[:16].
func PrefixV1(psk []byte) []byte {
	sum := blake3.Sum512(psk)
	out := make([]byte, 0, V1PrefixSize)
	out = append(out, MagicV1...)
	out = append(out, sum[:HeaderSize]...)
	return out
}
