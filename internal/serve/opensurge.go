package serve

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	officialProcessName = "oixcloud-external-proxy-program"
	officialProcessPath = "/usr/local/bin/oixcloud-external-proxy-program"
)

// OpenSurgeConfig is the official /opensurge body (and OpenSurge.yaml export).
// It is a mihomo overlay: HTTP provider at local /clash, TUN-loop DIRECT rules,
// and MATCH,oixCloud. No remote node addresses, PSK, or ECH.
func OpenSurgeConfig(clashURL, processName, processPath string) string {
	if clashURL == "" {
		clashURL = "http://127.0.0.1:6172/clash"
	}
	if processName == "" {
		processName = officialProcessName
	}
	if processPath == "" {
		processPath = officialProcessPath
	}
	var b strings.Builder
	b.WriteString("proxy-providers:\n")
	b.WriteString("  oixcloud-nodes:\n")
	b.WriteString("    type: http\n")
	fmt.Fprintf(&b, "    url: %q\n", clashURL)
	b.WriteString("    path: ./oixcloud-provider.yaml\n")
	b.WriteString("    interval: 600\n")
	b.WriteString("    health-check:\n")
	b.WriteString("      enable: true\n")
	b.WriteString("      url: https://www.gstatic.com/generate_204\n")
	b.WriteString("      interval: 300\n")
	b.WriteString("      lazy: true\n")
	b.WriteString("\n")
	b.WriteString("proxy-groups:\n")
	b.WriteString("  - name: \"oixCloud\"\n")
	b.WriteString("    type: select\n")
	b.WriteString("    use:\n")
	b.WriteString("      - oixcloud-nodes\n")
	b.WriteString("    proxies:\n")
	b.WriteString("      - DIRECT\n")
	b.WriteString("\n")
	b.WriteString("rules:\n")
	seenName := map[string]bool{}
	seenPath := map[string]bool{}
	addName := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seenName[name] {
			return
		}
		seenName[name] = true
		fmt.Fprintf(&b, "  - \"PROCESS-NAME,%s,DIRECT\"\n", name)
	}
	addPath := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seenPath[path] {
			return
		}
		seenPath[path] = true
		fmt.Fprintf(&b, "  - \"PROCESS-PATH,%s,DIRECT\"\n", path)
	}
	addName(processName)
	addPath(processPath)
	addName(officialProcessName)
	addPath(officialProcessPath)
	b.WriteString("  - \"MATCH,oixCloud\"\n")
	return b.String()
}

func clashInspectURL(listen, user, pass string) string {
	port := portOf(listen)
	u := url.URL{Scheme: "http", Path: "/clash"}
	u.Host = net.JoinHostPort("127.0.0.1", port)
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

func writeOpenSurgeFile(path, body string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
