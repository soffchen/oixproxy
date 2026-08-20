package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type LANAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Listener struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // mixed | socks5 | http
	Port   int    `json:"port"`
	Node   string `json:"node"`
	Listen string `json:"listen"`
}

type File struct {
	AccessToken   string     `json:"accessToken"`
	Email         string     `json:"email"`
	Password      string     `json:"password"`
	ProxyMode     string     `json:"proxyMode"`
	ServePort     int        `json:"servePort"`
	MapBasePort   int        `json:"mapBasePort"`
	ListenAddress string     `json:"listenAddress"`
	LANAuth       *LANAuth   `json:"lanAuth"`
	SimpleRules   bool       `json:"simpleRules"`
	Listeners     []Listener `json:"listeners"`
	OixParams     string     `json:"oixParams"`
	APIBase       string     `json:"apiBase,omitempty"`
	CustomConf    string     `json:"-"`
	DataDir       string     `json:"-"`
}

func Defaults() File {
	return File{
		ProxyMode:     "map",
		ServePort:     6172,
		MapBasePort:   7200,
		ListenAddress: "127.0.0.1",
	}
}

// DefaultPath is the official helper config.json location, then the Docker bind.
func DefaultPath() string {
	if v := os.Getenv("OIXCLOUD_CONFIG"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		"/config/config.json",
	}
	if home != "" {
		candidates = append([]string{filepath.Join(home, ".config/oixcloud-external-proxy-program/config.json")}, candidates...)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if home != "" {
		return filepath.Join(home, ".config/oixcloud-external-proxy-program/config.json")
	}
	return "config.json"
}

func Load(path string) (File, error) {
	cfg := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("config.json: %w", err)
	}
	if cfg.ProxyMode == "" {
		cfg.ProxyMode = "map"
	}
	if cfg.ServePort == 0 {
		cfg.ServePort = 6172
	}
	if cfg.MapBasePort == 0 {
		cfg.MapBasePort = 7200
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1"
	}
	if cfg.LANAuth != nil && (cfg.LANAuth.Username == "" || cfg.LANAuth.Password == "") {
		return cfg, fmt.Errorf("invalid lanAuth: username and password required")
	}
	dir := filepath.Dir(path)
	cfg.CustomConf = firstExisting(
		os.Getenv("OIXCLOUD_CUSTOM_CONFIG"),
		filepath.Join(dir, "custom.conf"),
		filepath.Join(DataDir(), "custom.conf"),
		"/config/custom.conf",
	)
	cfg.DataDir = DataDir()
	return cfg, nil
}

func DataDir() string {
	home, _ := os.UserHomeDir()
	return firstExistingDir(
		os.Getenv("OIXCLOUD_DATA"),
		"/data",
		filepath.Join(home, ".config/oixcloud-external-proxy-program"),
	)
}

func (c File) ServeAddr(listenFlag string) string {
	if listenFlag != "" {
		return normalizeListen(listenFlag, c.ListenAddress)
	}
	if v := os.Getenv("OIXCLOUD_SERVE_PORT"); v != "" {
		return netJoin(c.ListenAddress, v)
	}
	return netJoin(c.ListenAddress, strconv.Itoa(c.ServePort))
}

func (c File) BindAddr(bindFlag string) string {
	if bindFlag != "" {
		return bindFlag
	}
	return c.ListenAddress
}

func (c File) AuthFor(bind string) (user, pass string) {
	if c.LANAuth == nil {
		return "", ""
	}
	host := bind
	if h, _, err := splitHostPortSafe(bind); err == nil {
		host = h
	}
	if isLoopback(host) {
		return "", ""
	}
	return c.LANAuth.Username, c.LANAuth.Password
}

func normalizeListen(v, defaultHost string) string {
	if v == "" {
		return netJoin(defaultHost, "6172")
	}
	if !strings.Contains(v, ":") {
		return netJoin(defaultHost, v)
	}
	// host:port or :port
	if strings.HasPrefix(v, ":") {
		return defaultHost + v
	}
	return v
}

func netJoin(host, port string) string {
	if host == "" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func splitHostPortSafe(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("no port")
	}
	return strings.Trim(addr[:i], "[]"), addr[i+1:], nil
}

func isLoopback(host string) bool {
	switch host {
	case "", "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func firstExistingDir(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if paths[i] != "" {
			return paths[i]
		}
	}
	return ""
}
