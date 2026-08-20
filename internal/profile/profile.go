package profile

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/soffchen/oixproxy/internal/dialer"
)

type rawFile struct {
	Proxies []map[string]any `yaml:"proxies"`
}

func Load(path string) ([]dialer.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse extracts dedicated snell+ech-tls nodes. anytls / public clash=1 nodes are ignored.
// Accepts Clash YAML and Surge [Proxy] snell lines (the helper's two payload shapes).
func Parse(b []byte) ([]dialer.Node, error) {
	if nodes, err := parseYAML(b); err == nil && len(nodes) > 0 {
		return nodes, nil
	}
	if nodes := parseSurge(b); len(nodes) > 0 {
		return nodes, nil
	}
	return nil, fmt.Errorf("no snell ech-tls nodes")
}

func parseYAML(b []byte) ([]dialer.Node, error) {
	var f rawFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	var out []dialer.Node
	for _, p := range f.Proxies {
		n, ok, err := parseNode(p)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no snell ech-tls nodes")
	}
	ApplyDNS(out, ParseDNS(b))
	return out, nil
}

func parseSurge(b []byte) []dialer.Node {
	var out []dialer.Node
	inProxy := false
	for _, line := range splitLines(string(b)) {
		s := trim(line)
		if s == "" || s[0] == '#' || s[0] == ';' {
			continue
		}
		if s[0] == '[' {
			inProxy = s == "[Proxy]" || s == "[proxy]"
			continue
		}
		if !inProxy && !contains(s, " = snell,") {
			continue
		}
		n, ok := parseSurgeLine(s)
		if ok {
			out = append(out, n)
		}
	}
	return out
}

func parseSurgeLine(s string) (dialer.Node, bool) {
	name, rest, ok := cut(s, " = ")
	if !ok {
		return dialer.Node{}, false
	}
	parts := splitCSV(rest)
	if len(parts) < 4 || parts[0] != "snell" {
		return dialer.Node{}, false
	}
	kv := map[string]string{}
	for _, p := range parts[3:] {
		k, v, ok := cut(p, "=")
		if ok {
			kv[k] = v
		}
	}
	if kv["obfs"] != "ech-tls" && kv["obfs-mode"] != "ech-tls" && kv["mode"] != "ech-tls" {
		// helper Surge lines carry ech-config even when obfs key is spelled differently
		if kv["ech-config"] == "" {
			return dialer.Node{}, false
		}
	}
	n := dialer.Node{
		Name:            name,
		Server:          parts[1],
		Port:            asInt(parts[2]),
		PSK:             firstKV(kv, "psk", "psk-key"),
		SNI:             firstKV(kv, "obfs-host", "sni", "host"),
		ECHConfig:       kv["ech-config"],
		ALPN:            firstKV(kv, "alpn"),
		Path:            firstKV(kv, "obfs-uri", "path", "obfs-path"),
		Fingerprint:     firstKV(kv, "client-fingerprint"),
		IdentityVersion: asInt(kv["identity-version"]),
		Reuse:           kv["reuse"] == "true" || kv["reuse"] == "1",
	}
	if n.Name == "" || n.Server == "" || n.Port == 0 || n.PSK == "" || n.ECHConfig == "" {
		return dialer.Node{}, false
	}
	return n, true
}

func firstKV(kv map[string]string, keys ...string) string {
	for _, k := range keys {
		if kv[k] != "" {
			return kv[k]
		}
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		out = append(out, s[start:])
	}
	return out
}

func trim(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

func cut(s, sep string) (string, string, bool) {
	i := indexOf(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

func indexOf(s, sep string) int {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, trim(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trim(s[start:]))
	return out
}

func parseNode(p map[string]any) (dialer.Node, bool, error) {
	if str(p["type"]) != "snell" {
		return dialer.Node{}, false, nil
	}
	obfs, _ := p["obfs-opts"].(map[string]any)
	if obfs == nil {
		// some yaml decoders keep map[string]interface{} with nested maps
		if m, ok := p["obfs-opts"].(map[string]interface{}); ok {
			obfs = m
		}
	}
	if str(obfs["mode"]) != "ech-tls" {
		return dialer.Node{}, false, nil
	}
	n := dialer.Node{
		Name:            str(p["name"]),
		Server:          str(p["server"]),
		Port:            asInt(p["port"]),
		PSK:             str(p["psk"]),
		SNI:             first(obfs, "sni", "host"),
		ECHConfig:       str(obfs["ech-config"]),
		ALPN:            str(obfs["alpn"]),
		Path:            str(obfs["path"]),
		Fingerprint:     first(obfs, "client-fingerprint"),
		IdentityVersion: asInt(obfs["identity-version"]),
		SkipVerify:      asBool(obfs["skip-cert-verify"]) || asBool(obfs["insecure"]),
		Reuse:           asBool(p["reuse"]),
	}
	if n.IdentityVersion == 0 && asBool(p["identity"]) {
		n.IdentityVersion = 2
	}
	if n.Name == "" || n.Server == "" || n.Port == 0 || n.PSK == "" || n.ECHConfig == "" {
		return dialer.Node{}, false, fmt.Errorf("incomplete snell node %q", n.Name)
	}
	return n, true, nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func first(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := str(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case uint64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(t, "%d", &n)
		return n
	default:
		return 0
	}
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	default:
		return false
	}
}
