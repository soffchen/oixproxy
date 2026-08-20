package profile

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/soffchen/oixproxy/internal/dialer"
)

// Filter keeps nodes whose Name matches expr, using Clash Meta proxy-group
// filter syntax: regular expressions separated by ` (OR), applied in order.
// An empty expr returns nodes unchanged.
func Filter(nodes []dialer.Node, expr string) ([]dialer.Node, error) {
	regs, err := compileFilter(expr)
	if err != nil {
		return nil, err
	}
	if len(regs) == 0 {
		return nodes, nil
	}
	seen := make(map[string]bool)
	var out []dialer.Node
	for _, re := range regs {
		for _, n := range nodes {
			if seen[n.Name] {
				continue
			}
			if re.MatchString(n.Name) {
				seen[n.Name] = true
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func compileFilter(expr string) ([]*regexp.Regexp, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	var regs []*regexp.Regexp
	for _, part := range strings.Split(expr, "`") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		re, err := regexp.Compile(part)
		if err != nil {
			return nil, fmt.Errorf("filter %q: %w", part, err)
		}
		regs = append(regs, re)
	}
	return regs, nil
}
