package serve

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func socksLine(name, host string, port int, udp bool) string {
	if udp {
		return fmt.Sprintf("%s = socks5, %s, %d, udp-relay=true", name, host, port)
	}
	return fmt.Sprintf("%s = socks5, %s, %d", name, host, port)
}

// ClashConfig is the official /clash provider: socks5 proxies only.
func ClashConfig(maps []Mapping, host string) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, m := range maps {
		fmt.Fprintf(&b, "  - name: %q\n", m.Node.Name)
		b.WriteString("    type: socks5\n")
		fmt.Fprintf(&b, "    server: %s\n", host)
		fmt.Fprintf(&b, "    port: %d\n", m.Port)
		if m.UDP {
			b.WriteString("    udp: true\n")
		}
	}
	return b.String()
}

// ProxyList is the official /list Surge policy-path body.
func ProxyList(maps []Mapping, host string) string {
	var b strings.Builder
	for _, m := range maps {
		b.WriteString(socksLine(m.Node.Name, host, m.Port, m.UDP))
		b.WriteByte('\n')
	}
	return b.String()
}

// SurgeConfig is the official / (and /map) managed Surge profile.
// When template is a helper Surge body, [Proxy] is rewritten to local socks5
// and groups are expanded the same way as oixcloud-external-proxy-program.
func SurgeConfig(maps []Mapping, listenURL, host string, template []byte) string {
	if looksLikeSurge(template) {
		return RewriteSurge(template, maps, listenURL, host)
	}
	return minimalSurge(maps, listenURL, host)
}

func looksLikeSurge(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "[Proxy]") || strings.Contains(s, "#!MANAGED-CONFIG")
}

func minimalSurge(maps []Mapping, listenURL, host string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#!MANAGED-CONFIG %s interval=86400 strict=false\n\n", listenURL)
	b.WriteString("[General]\n")
	b.WriteString("loglevel = notify\n")
	b.WriteString("dns-server = system,119.29.29.29,223.5.5.5,223.6.6.6\n")
	b.WriteString("skip-proxy = localhost,*.local,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16\n\n")
	b.WriteString("[Proxy]\n")
	b.WriteString("Direct = direct\n")
	b.WriteString("Block = reject\n\n")
	var names []string
	for _, m := range maps {
		b.WriteString(socksLine(m.Node.Name, host, m.Port, m.UDP))
		b.WriteByte('\n')
		names = append(names, m.Node.Name)
	}
	b.WriteString("\n[Proxy Group]\n")
	b.WriteString("Proxy = select")
	for _, n := range names {
		b.WriteString(", ")
		b.WriteString(n)
	}
	b.WriteString(", Direct\n")
	b.WriteString("\n[Rule]\n")
	b.WriteString("FINAL,Proxy\n")
	return b.String()
}

// RewriteSurge converts a helper/public Surge template into the official
// client-facing profile: local socks5 only, no snell/anytls/psk/ech.
func RewriteSurge(template []byte, maps []Mapping, listenURL, host string) string {
	lines := strings.Split(string(template), "\n")
	var out []string
	section := ""
	wroteProxy := false
	wroteAutos := false
	names := make([]string, 0, len(maps))
	for _, m := range maps {
		names = append(names, m.Node.Name)
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#!MANAGED-CONFIG") {
			out = append(out, "#!MANAGED-CONFIG "+listenURL+" interval=86400 strict=false")
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			if section == "[Proxy Group]" && !wroteAutos && len(names) > 0 {
				out = append(out, autoGroups(names)...)
				wroteAutos = true
			}
			section = trim
			out = append(out, line)
			if strings.EqualFold(section, "[Proxy]") && !wroteProxy {
				// keep walking to copy Direct/Block then replace the rest
			}
			continue
		}
		switch {
		case strings.EqualFold(section, "[Proxy]"):
			low := strings.ToLower(trim)
			if trim == "" || strings.HasPrefix(trim, "#") {
				out = append(out, line)
				continue
			}
			if strings.HasPrefix(low, "direct ") || strings.HasPrefix(low, "direct=") ||
				strings.HasPrefix(low, "block ") || strings.HasPrefix(low, "block=") {
				out = append(out, line)
				continue
			}
			if !wroteProxy {
				if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
					out = append(out, "")
				}
				for _, m := range maps {
					out = append(out, socksLine(m.Node.Name, host, m.Port, m.UDP))
				}
				wroteProxy = true
			}
			// drop oixCloud / snell / anytls / leftover remote lines
			continue
		case strings.EqualFold(section, "[Proxy Group]"):
			if trim == "" || strings.HasPrefix(trim, "#") {
				out = append(out, line)
				continue
			}
			out = append(out, expandGroup(line, names))
		default:
			out = append(out, line)
		}
	}
	if strings.EqualFold(section, "[Proxy Group]") && !wroteAutos && len(names) > 0 {
		out = append(out, autoGroups(names)...)
	}
	if !wroteProxy && len(maps) > 0 {
		// template had no [Proxy]; append one
		out = append(out, "", "[Proxy]", "Direct = direct", "Block = reject")
		for _, m := range maps {
			out = append(out, socksLine(m.Node.Name, host, m.Port, m.UDP))
		}
	}
	body := strings.Join(out, "\n")
	if !strings.HasPrefix(strings.TrimSpace(body), "#!MANAGED-CONFIG") {
		body = "#!MANAGED-CONFIG " + listenURL + " interval=86400 strict=false\n\n" + body
	}
	return body
}

func expandGroup(line string, names []string) string {
	name, rest, ok := strings.Cut(line, " = ")
	if !ok {
		name, rest, ok = strings.Cut(line, "=")
		if !ok {
			return line
		}
		name = strings.TrimSpace(name)
		rest = strings.TrimSpace(rest)
	}
	if strings.EqualFold(name, "Auto - UrlTest") || strings.EqualFold(name, "Auto - Smart") {
		return line
	}
	parts := splitCSV(rest)
	if len(parts) == 0 {
		return line
	}
	kind := strings.ToLower(parts[0])
	hasBlock := false
	var kept []string
	for i, p := range parts {
		if i == 0 {
			kept = append(kept, p)
			continue
		}
		if p == "oixCloud" {
			kept = append(kept, "Auto - Smart", "Auto - UrlTest")
			continue
		}
		if strings.EqualFold(p, "Block") {
			hasBlock = true
		}
		kept = append(kept, p)
	}
	if kind == "select" && !hasBlock {
		have := map[string]bool{}
		for _, p := range kept {
			have[p] = true
		}
		for _, n := range names {
			if !have[n] {
				kept = append(kept, n)
			}
		}
	}
	return name + " = " + strings.Join(kept, ", ")
}

func autoGroups(names []string) []string {
	return []string{
		"Auto - UrlTest = url-test, " + strings.Join(names, ", "),
		"Auto - Smart = smart, " + strings.Join(names, ", "),
	}
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

func managedURL(host, port, path, user, pass string) string {
	u := url.URL{Scheme: "http", Path: path}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	u.Host = net.JoinHostPort(host, port)
	return u.String()
}
