package run

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const snellFixture = `proxies:
  - { name: "🇭🇰 香港 Fusion 01", type: snell, server: fusion_hk_1.example, port: 14888, psk: test-psk-1, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }
  - { name: "🇯🇵 日本 Fusion 01", type: snell, server: fusion_jp_1.example, port: 14888, psk: test-psk-2, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }
`

const anytlsFixture = `proxies:
  - { name: "edge", type: anytls, server: x, port: 443, password: public }
`

func TestCLIUnknownProxyMode(t *testing.T) {
	err := Main([]string{"--profile", "x.yaml", "--mode", "wireguard"})
	if err == nil || !strings.Contains(err.Error(), "proxyMode") {
		t.Fatalf("err %v", err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"proxyMode":"vpn","accessToken":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = Main([]string{"--config", cfg})
	if err == nil || !strings.Contains(err.Error(), "proxyMode") {
		t.Fatalf("config mode err %v", err)
	}
}

func TestCLIServeFalseSkipsHTTP(t *testing.T) {
	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "oixproxy")
	build := exec.Command("go", "build", "-o", bin, "./cmd/oixproxy")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	prof := filepath.Join(t.TempDir(), "nodes.yaml")
	if err := os.WriteFile(prof, []byte(snellFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	httpPort := freePort(t)
	mapPort := freePort(t)
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(bin, "--profile", prof, "--listen", "127.0.0.1:"+strconv.Itoa(httpPort), "--bind", "127.0.0.1", "--map", "--map-base-port", strconv.Itoa(mapPort), "--serve=false")
	cmd.Env = append(os.Environ(), "OIXPROXY_READY_FILE="+ready, "OIXCLOUD_DATA="+t.TempDir())
	cmd.Dir = root
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
	}()
	if err := waitFile(ready, 8*time.Second); err != nil {
		t.Fatal(err)
	}
	_, err := http.Get("http://127.0.0.1:" + strconv.Itoa(httpPort) + "/health")
	if err == nil {
		t.Fatal("HTTP still serving")
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(mapPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	if greet != [2]byte{0x05, 0x00} {
		t.Fatalf("socks greet %v", greet)
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	if err := Main([]string{"--help"}); err != nil {
		t.Fatal(err)
	}
	if err := Main([]string{"-h"}); err != nil {
		t.Fatal(err)
	}
	if err := Main([]string{"--version"}); err != nil {
		t.Fatal(err)
	}
}

func TestCLILaunchTwiceAgainstStubPanel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/information", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-access-key" {
			http.Error(w, `{"ret":401}`, 401)
			return
		}
		w.Write([]byte(`{"ret":200,"msg":"success","data":{}}`))
	})
	mux.HandleFunc("/api/v1/managed/anywhere/direct", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-Anywhere-Signature") == "" {
			http.Error(w, `{"ret":400}`, 400)
			return
		}
		w.Write([]byte("proxies:\n  - { name: \"🇭🇰 香港 Fusion 01\", type: snell, server: fusion_hk_1.example, port: 14888, psk: test-psk-1, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }\n  - { name: \"🇯🇵 日本 Fusion 01\", type: snell, server: fusion_jp_1.example, port: 14888, psk: test-psk-2, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }\n"))
	})
	mux.HandleFunc("/api/v1/managed/surge", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ret":200,"msg":"success","smart":"/dl?dedicated_access=x"}`))
	})
	mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("clash") == "1" {
			w.Write([]byte(anytlsFixture))
			return
		}
		w.Write([]byte(snellFixture))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "oixproxy")
	build := exec.Command("go", "build", "-o", bin, "./cmd/oixproxy")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	httpPort := freePort(t)
	mapPort := freePort(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, []byte(`{"accessToken":"test-access-key","apiBase":"`+ts.URL+`","proxyMode":"map","servePort":`+strconv.Itoa(httpPort)+`,"mapBasePort":`+strconv.Itoa(mapPort)+`,"listenAddress":"127.0.0.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var bodies [2]map[string]string
	for i := 0; i < 2; i++ {
		ready := filepath.Join(t.TempDir(), "ready")
		dataDir := t.TempDir()
		cmd := exec.Command(bin, "--config", cfg, "--listen", "127.0.0.1:"+strconv.Itoa(httpPort), "--bind", "127.0.0.1", "--map", "--map-base-port", strconv.Itoa(mapPort))
		cmd.Env = append(os.Environ(), "OIXPROXY_READY_FILE="+ready, "OIXCLOUD_DATA="+dataDir)
		cmd.Dir = root
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if err := waitFile(ready, 8*time.Second); err != nil {
			_ = cmd.Process.Kill()
			t.Fatal(err)
		}
		base := "http://127.0.0.1:" + strconv.Itoa(httpPort)
		got := map[string]string{}
		for _, p := range []string{"/health", "/", "/clash", "/list", "/opensurge"} {
			resp, err := http.Get(base + p)
			if err != nil {
				_ = cmd.Process.Kill()
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				_ = cmd.Process.Kill()
				t.Fatalf("%s %d", p, resp.StatusCode)
			}
			got[p] = string(b)
		}
		if b, err := os.ReadFile(filepath.Join(dataDir, "OpenSurge.yaml")); err != nil || !strings.Contains(string(b), "oixcloud-nodes") {
			_ = cmd.Process.Kill()
			t.Fatalf("OpenSurge.yaml: %v %q", err, b)
		}
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
		bodies[i] = got
		assertSOCKSArtifacts(t, got, mapPort)
		if ev := evidenceDir(); ev != "" {
			dir := filepath.Join(ev, "cli-"+strconv.Itoa(i+1))
			_ = os.MkdirAll(dir, 0o755)
			_ = os.WriteFile(filepath.Join(dir, "health.txt"), []byte(got["/health"]), 0o644)
			_ = os.WriteFile(filepath.Join(dir, "surge.conf"), []byte(got["/"]), 0o644)
			_ = os.WriteFile(filepath.Join(dir, "clash.yaml"), []byte(got["/clash"]), 0o644)
			_ = os.WriteFile(filepath.Join(dir, "list.txt"), []byte(got["/list"]), 0o644)
			_ = os.WriteFile(filepath.Join(dir, "opensurge.yaml"), []byte(got["/opensurge"]), 0o644)
		}
	}
	if bodies[0]["/clash"] != bodies[1]["/clash"] || bodies[0]["/list"] != bodies[1]["/list"] {
		t.Fatal("two launches disagreed on SOCKS artifacts")
	}
}

func assertSOCKSArtifacts(t *testing.T, got map[string]string, mapPort int) {
	t.Helper()
	if strings.TrimSpace(got["/health"]) == "" {
		t.Fatal("empty health")
	}
	port := strconv.Itoa(mapPort)
	for _, key := range []string{"/", "/clash", "/list"} {
		b := got[key]
		if !strings.Contains(strings.ToLower(b), "socks5") {
			t.Fatalf("%s not socks5", key)
		}
		if !strings.Contains(b, port) {
			t.Fatalf("%s missing port %s", key, port)
		}
		if strings.Contains(b, "type: snell") || strings.Contains(b, "type: anytls") || strings.Contains(b, "psk:") || strings.Contains(b, "ech-config") {
			t.Fatalf("%s leaked dedicated secrets/protocol", key)
		}
	}
	osBody := got["/opensurge"]
	if osBody == "" {
		t.Fatal("empty /opensurge")
	}
	for _, want := range []string{"oixcloud-nodes", "/clash", "PROCESS-NAME", "PROCESS-PATH", "MATCH,oixCloud", "interval: 600"} {
		if !strings.Contains(osBody, want) {
			t.Fatalf("/opensurge missing %s", want)
		}
	}
	if strings.Contains(osBody, "psk") || strings.Contains(osBody, "ech-config") {
		t.Fatal("/opensurge leaked dedicated secrets")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod")
		}
		dir = parent
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func evidenceDir() string {
	d := os.Getenv("OIXPROXY_EVIDENCE")
	if d == "" {
		return ""
	}
	if st, err := os.Stat(d); err == nil && st.IsDir() {
		return d
	}
	return ""
}

func waitFile(path string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(30 * time.Millisecond)
	}
	return os.ErrNotExist
}
