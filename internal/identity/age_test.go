package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func TestLoadOrCreateAgeRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".identity")
	id, err := LoadOrCreateAge(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateAge(path)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != again.String() {
		t.Fatal("identity rewritten")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %o", st.Mode().Perm())
	}

	plain := []byte("proxies:\n  - { name: hk }\n")
	var bin bytes.Buffer
	w, err := age.Encrypt(&bin, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := DecryptAge(id, bin.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}

	var arm bytes.Buffer
	aw := armor.NewWriter(&arm)
	w, err = age.Encrypt(aw, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	got, err = DecryptAge(id, arm.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("armor %q", got)
	}
}
