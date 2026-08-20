package serve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSurgeConfigMatchesOfficialShape(t *testing.T) {
	got := OpenSurgeConfig("http://127.0.0.1:6172/clash", officialProcessName, officialProcessPath)
	for _, want := range []string{
		"proxy-providers:",
		"  oixcloud-nodes:",
		"    type: http",
		`    url: "http://127.0.0.1:6172/clash"`,
		"    path: ./oixcloud-provider.yaml",
		"    interval: 600",
		"      interval: 300",
		"https://www.gstatic.com/generate_204",
		`  - name: "oixCloud"`,
		"    type: select",
		"      - oixcloud-nodes",
		"      - DIRECT",
		`"PROCESS-NAME,oixcloud-external-proxy-program,DIRECT"`,
		`"PROCESS-PATH,/usr/local/bin/oixcloud-external-proxy-program,DIRECT"`,
		`"MATCH,oixCloud"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "psk") || strings.Contains(got, "ech-config") || strings.Contains(got, "snell") {
		t.Fatal("leaked dedicated protocol")
	}
	if strings.Count(got, "PROCESS-NAME,") != 1 || strings.Count(got, "PROCESS-PATH,") != 1 {
		t.Fatalf("duplicate process rules:\n%s", got)
	}
}

func TestOpenSurgeLANAuthInProviderURL(t *testing.T) {
	u := clashInspectURL("127.0.0.1:6172", "alice", "secret")
	if !strings.Contains(u, "alice") || !strings.Contains(u, "secret") {
		t.Fatalf("url %s", u)
	}
	got := OpenSurgeConfig(u, "oixproxy", "/usr/local/bin/oixproxy")
	if !strings.Contains(got, "alice") {
		t.Fatal(got)
	}
	if strings.Count(got, "PROCESS-NAME,") < 2 {
		t.Fatalf("want running + official process names:\n%s", got)
	}
}

func TestWriteOpenSurgeFilePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "OpenSurge.yaml")
	body := OpenSurgeConfig("http://127.0.0.1:6172/clash", "oixproxy", "/bin/oixproxy")
	if err := writeOpenSurgeFile(path, body); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file perm %o", st.Mode().Perm())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "oixcloud-nodes") {
		t.Fatal(string(got))
	}
}
