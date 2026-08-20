package identity

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// LoadOrCreateAge loads a standard age X25519 identity from path, or writes one.
func LoadOrCreateAge(path string) (*age.X25519Identity, error) {
	if path == "" {
		return nil, fmt.Errorf("age identity path is empty")
	}
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, fmt.Errorf("parse age identity: %w", err)
			}
			return id, nil
		}
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	body := "# created by oixproxy\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

func DecryptAge(id *age.X25519Identity, ciphertext []byte) ([]byte, error) {
	if id == nil {
		return nil, fmt.Errorf("age identity unavailable")
	}
	in := io.Reader(strings.NewReader(string(ciphertext)))
	if bytes.Contains(ciphertext, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		in = armor.NewReader(in)
	}
	r, err := age.Decrypt(in, id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
