package profile

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/soffchen/oixproxy/internal/dialer"
)

type rawDNSFile struct {
	DNS *rawDNS `yaml:"dns"`
}

type rawDNS struct {
	ProxyServerNameserverPolicy map[string]any `yaml:"proxy-server-nameserver-policy"`
	NameserverPolicy            map[string]any `yaml:"nameserver-policy"`
	ProxyServerNameserver       any            `yaml:"proxy-server-nameserver"`
	DefaultNameserver           any            `yaml:"default-nameserver"`
}

// DNSPolicy is the dedicated-profile DNS used to resolve proxy hostnames.
type DNSPolicy struct {
	Policies []DNSRule
	Fallback []dialer.DNSServer
}

type DNSRule struct {
	Pattern string
	Servers []dialer.DNSServer
}

func ParseDNS(b []byte) DNSPolicy {
	var f rawDNSFile
	if err := yaml.Unmarshal(b, &f); err != nil || f.DNS == nil {
		return DNSPolicy{}
	}
	d := f.DNS
	p := DNSPolicy{}
	p.Policies = append(p.Policies, rulesFromMap(d.ProxyServerNameserverPolicy)...)
	p.Policies = append(p.Policies, rulesFromMap(d.NameserverPolicy)...)
	p.Fallback = append(p.Fallback, parseServerList(d.ProxyServerNameserver)...)
	p.Fallback = append(p.Fallback, parseServerList(d.DefaultNameserver)...)
	return p
}

func (p DNSPolicy) Match(host string) []dialer.DNSServer {
	for _, r := range p.Policies {
		if dialer.DomainMatch(r.Pattern, host) && len(r.Servers) > 0 {
			return r.Servers
		}
	}
	return p.Fallback
}

func ApplyDNS(nodes []dialer.Node, p DNSPolicy) {
	for i := range nodes {
		if len(nodes[i].DNS) > 0 {
			continue
		}
		nodes[i].DNS = p.Match(nodes[i].Server)
	}
}

func rulesFromMap(m map[string]any) []DNSRule {
	if m == nil {
		return nil
	}
	var out []DNSRule
	for k, v := range m {
		k = strings.TrimSpace(k)
		if k == "" || strings.HasPrefix(k, "geosite:") || strings.HasPrefix(k, "geoip:") {
			continue
		}
		out = append(out, DNSRule{Pattern: k, Servers: parseServerList(v)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return dnsRuleLess(out[i].Pattern, out[j].Pattern)
	})
	return out
}

func dnsRuleLess(a, b string) bool {
	sa, sb := dnsSuffix(a), dnsSuffix(b)
	if len(sa) != len(sb) {
		return len(sa) > len(sb)
	}
	ra, rb := dnsPatternRank(a), dnsPatternRank(b)
	if ra != rb {
		return ra < rb
	}
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a < b
}

func dnsSuffix(p string) string {
	switch {
	case strings.HasPrefix(p, "+."), strings.HasPrefix(p, "*."):
		return p[2:]
	default:
		return p
	}
}

func dnsPatternRank(p string) int {
	switch {
	case strings.HasPrefix(p, "+."):
		return 2
	case strings.HasPrefix(p, "*."):
		return 3
	default:
		return 1
	}
}

func parseServerList(v any) []dialer.DNSServer {
	var out []dialer.DNSServer
	for _, s := range asStringSlice(v) {
		if ns, ok := dialer.ParseNameserver(s); ok {
			out = append(out, ns)
		}
	}
	return out
}

func asStringSlice(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, str(x))
		}
		return out
	case []string:
		return t
	default:
		s := str(t)
		if s == "" {
			return nil
		}
		return []string{s}
	}
}
