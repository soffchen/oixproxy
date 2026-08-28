package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthForPerListenAddress(t *testing.T) {
	cfg := Defaults()
	cfg.LANAuth = &LANAuth{Username: "alice", Password: "secret"}

	none := []string{
		"127.0.0.1",
		"127.0.0.1:7200",
		"::1",
		"[::1]:7200",
		"localhost",
		"localhost:6172",
	}
	for _, addr := range none {
		u, p := cfg.AuthFor(addr)
		if u != "" || p != "" {
			t.Fatalf("%s: got %q %q, loopback must skip lanAuth", addr, u, p)
		}
	}

	need := []string{
		"0.0.0.0:7200",
		"192.168.1.9:7200",
		"[::]:6172",
		"::",
		":6172",
		"10.1.0.3",
	}
	for _, addr := range need {
		u, p := cfg.AuthFor(addr)
		if u != "alice" || p != "secret" {
			t.Fatalf("%s: got %q %q, want lanAuth", addr, u, p)
		}
	}

	cfg.LANAuth = nil
	u, p := cfg.AuthFor("0.0.0.0:7200")
	if u != "" || p != "" {
		t.Fatalf("nil lanAuth: %q %q", u, p)
	}
}

func TestLoadRejectsIncompleteLANAuth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"lanAuth":{"username":"alice"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid lanAuth")
	}
}

func TestLoadRejectsLANAuthLineBreaks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"lanAuth":{"username":"alice\nbob","password":"secret"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected line break rejected")
	}
}

func TestLANAuthRejectsProtocolIncompatibleCredentials(t *testing.T) {
	tests := []struct {
		name string
		user string
		pass string
	}{
		{name: "用户名含冒号", user: "al:ice", pass: "secret"},
		{name: "用户名超过 255 字节", user: strings.Repeat("u", 256), pass: "secret"},
		{name: "密码超过 255 字节", user: "alice", pass: strings.Repeat("p", 256)},
		{name: "密码含控制字符", user: "alice", pass: "sec\x01ret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validLANAuth(tt.user, tt.pass); err == nil {
				t.Fatal("期望拒绝 HTTP Basic 或 SOCKS5 无法表示的凭据")
			}
		})
	}
	if err := validLANAuth(strings.Repeat("u", 255), strings.Repeat("p", 255)); err != nil {
		t.Fatalf("255 字节凭据应有效: %v", err)
	}
}

func TestLoadUnknownProxyModePreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"proxyMode":"wireguard"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyMode != "wireguard" {
		t.Fatalf("proxyMode %q", cfg.ProxyMode)
	}
}

func TestDataDirCreatesMissingEnvDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-yet")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("precondition: %v", err)
	}
	t.Setenv("OIXCLOUD_DATA", dir)
	got, err := DataDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("got %s want %s", got, dir)
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		t.Fatalf("created dir: %v", err)
	}
}

func TestDataDirEnvCreateError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIXCLOUD_DATA", filepath.Join(file, "data"))
	if _, err := DataDir(); err == nil {
		t.Fatal("expected mkdir error")
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("Load should fail when OIXCLOUD_DATA cannot be created")
	}
}

func TestIsLoopbackIPv6(t *testing.T) {
	if !isLoopback("::1") || !isLoopback("[::1]") {
		t.Fatal("::1 must be loopback")
	}
	if isLoopback("::") || isLoopback("0.0.0.0") || isLoopback("") {
		t.Fatal("unspecified must not be treated as loopback")
	}
}
