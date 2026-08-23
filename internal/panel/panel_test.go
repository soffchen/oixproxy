package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/soffchen/oixproxy/internal/identity"
	"github.com/soffchen/oixproxy/internal/profile"
)

const snellYAML = `proxies:
  - { name: "🇭🇰 香港 Fusion 01", type: snell, server: fusion_hk_1.example, port: 14888, psk: test-psk-1, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }
  - { name: "🇯🇵 日本 Fusion 01", type: snell, server: fusion_jp_1.example, port: 14888, psk: test-psk-2, version: 4, reuse: true, obfs-opts: { mode: ech-tls, alpn: snell-ech/1, sni: cover.example, ech-config: AAAA } }
`

const anytlsYAML = `proxies:
  - { name: "🇭🇰 香港 Edge 01", type: anytls, server: hk1.example.org, port: 443, password: public-pass, sni: cover.example, udp: true }
`

func TestFetchDedicatedUsesTokenAndSnellNotClash1(t *testing.T) {
	var sawClash1 bool
	var gotBearer string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/information", func(w http.ResponseWriter, r *http.Request) {
		gotBearer = r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("access_token") != "test-access-key" && !strings.Contains(gotBearer, "test-access-key") {
			http.Error(w, `{"ret":401,"msg":"Bearer token is required"}`, 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ret":200,"msg":"success","data":{"plan":"test"}}`))
	})
	mux.HandleFunc("/api/v1/managed/anywhere/direct", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", 405)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-access-key" {
			http.Error(w, `{"ret":401}`, 401)
			return
		}
		if r.Header.Get("X-Anywhere-Timestamp") == "" || r.Header.Get("X-Anywhere-Signature") == "" || r.Header.Get("X-Anywhere-Age-Pubkey") == "" {
			http.Error(w, `{"ret":400,"msg":"missing anywhere headers"}`, 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		cfg, _ := json.Marshal(snellYAML)
		w.Write([]byte(`{"ret":200,"msg":"success","config":` + string(cfg) + `}`))
	})
	mux.HandleFunc("/api/v1/managed/surge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		_ = r.ParseForm()
		if r.Header.Get("Authorization") != "Bearer test-access-key" {
			http.Error(w, `{"ret":401,"msg":"no token"}`, 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ret":200,"msg":"success","name":"oixCloud","smart":"/download?dedicated_access=abc.apk"}`))
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("clash") == "1" {
			sawClash1 = true
			w.Write([]byte(anytlsYAML))
			return
		}
		w.Write([]byte(snellYAML))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := New("test-access-key")
	c.Base = ts.URL
	c.IdentityPath = t.TempDir() + "/.identity"
	nodes, err := c.FetchDedicatedNodes()
	if err != nil {
		t.Fatal(err)
	}
	if sawClash1 {
		t.Fatal("dedicated fetch rewrote download to public clash=1 anytls")
	}
	if !strings.Contains(gotBearer, "test-access-key") {
		t.Fatalf("token not sent, Authorization=%q", gotBearer)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes %d", len(nodes))
	}
	if nodes[0].Name != "🇭🇰 香港 Fusion 01" || nodes[0].PSK != "test-psk-1" {
		t.Fatalf("%+v", nodes[0])
	}

	// Public clash=1 body is anytls and must not parse as dedicated nodes.
	if _, err := profile.Parse([]byte(anytlsYAML)); err == nil {
		t.Fatal("anytls yaml must not be accepted as dedicated snell source")
	}
}

func TestSimpleRulesKeepsDedicatedQueryOrder(t *testing.T) {
	var raw string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/information", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ret":200,"msg":"success"}`))
	})
	mux.HandleFunc("/api/v1/managed/anywhere/direct", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"ret":404}`, 404)
	})
	mux.HandleFunc("/api/v1/managed/surge", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("simplerules") != "true" {
			http.Error(w, `{"ret":400,"msg":"missing simplerules"}`, 400)
			return
		}
		w.Write([]byte(`{"ret":200,"msg":"success","smart":"/download?dedicated_access=abc.apk"}`))
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		raw = r.URL.RawQuery
		if r.URL.Query().Get("clash") == "1" {
			w.Write([]byte(anytlsYAML))
			return
		}
		w.Write([]byte(snellYAML))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := New("test-access-key")
	c.Base = ts.URL
	c.SimpleRules = true
	c.IdentityPath = t.TempDir() + "/.identity"
	nodes, err := c.FetchDedicatedNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes %d", len(nodes))
	}
	if raw != "external-proxy-program=true&simplerules=true&dedicated_access=abc.apk" {
		t.Fatalf("query %q", raw)
	}
}

func TestFetchInlineConfigWhenSmartEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/information", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ret":200,"msg":"success"}`))
	})
	mux.HandleFunc("/api/v1/managed/anywhere/direct", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"ret":404}`, 404)
	})
	mux.HandleFunc("/api/v1/managed/surge", func(w http.ResponseWriter, r *http.Request) {
		cfg, _ := json.Marshal(snellYAML)
		w.Write([]byte(`{"ret":200,"msg":"success","config":` + string(cfg) + `}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := New("test-access-key")
	c.Base = ts.URL
	c.IdentityPath = filepath.Join(t.TempDir(), ".identity")
	nodes, err := c.FetchDedicatedNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes %d", len(nodes))
	}
}

func TestFetchAgeEncryptedInlineConfig(t *testing.T) {
	idPath := filepath.Join(t.TempDir(), ".identity")
	id, err := identity.LoadOrCreateAge(idPath)
	if err != nil {
		t.Fatal(err)
	}
	ct := ageArmor(t, id.Recipient(), []byte(snellYAML))
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/information", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ret":200,"msg":"success"}`))
	})
	mux.HandleFunc("/api/v1/managed/anywhere/direct", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"ret":404}`, 404)
	})
	mux.HandleFunc("/api/v1/managed/surge", func(w http.ResponseWriter, r *http.Request) {
		cfg, _ := json.Marshal(ct)
		w.Write([]byte(`{"ret":200,"msg":"success","config":` + string(cfg) + `}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := New("test-access-key")
	c.Base = ts.URL
	c.IdentityPath = idPath
	nodes, err := c.FetchDedicatedNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes %d", len(nodes))
	}
}

func ageArmor(t *testing.T, recipient age.Recipient, plain []byte) string {
	t.Helper()
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
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
	return buf.String()
}

func TestClash1SourceFailsDedicatedParse(t *testing.T) {
	_, err := profile.Parse([]byte(anytlsYAML))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "snell") {
		t.Fatalf("err %v", err)
	}
}
