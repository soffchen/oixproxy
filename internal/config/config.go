package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
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
	Filter        string     `json:"filter"`
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
	if cfg.LANAuth != nil {
		if err := validLANAuth(cfg.LANAuth.Username, cfg.LANAuth.Password); err != nil {
			return cfg, err
		}
	}
	dir := filepath.Dir(path)
	dataDir, err := DataDir()
	if err != nil {
		return cfg, err
	}
	cfg.CustomConf = firstExisting(
		os.Getenv("OIXCLOUD_CUSTOM_CONFIG"),
		filepath.Join(dir, "custom.conf"),
		filepath.Join(dataDir, "custom.conf"),
		"/config/custom.conf",
	)
	cfg.DataDir = dataDir
	return cfg, nil
}

func DataDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv("OIXCLOUD_DATA")); v != "" {
		if err := os.MkdirAll(v, 0o755); err != nil {
			return "", fmt.Errorf("OIXCLOUD_DATA %s: %w", v, err)
		}
		return v, nil
	}
	home, _ := os.UserHomeDir()
	return firstExistingDir(
		"/data",
		filepath.Join(home, ".config/oixcloud-external-proxy-program"),
	), nil
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

func validLANAuth(user, pass string) error {
	if user == "" || pass == "" {
		return fmt.Errorf("invalid lanAuth: username and password required")
	}
	if strings.Contains(user, ":") {
		return fmt.Errorf("invalid lanAuth: username must not contain colon")
	}
	if len(user) > 255 || len(pass) > 255 {
		return fmt.Errorf("invalid lanAuth: username and password must not exceed 255 bytes")
	}
	if strings.ContainsFunc(user, unicode.IsControl) || strings.ContainsFunc(pass, unicode.IsControl) {
		return fmt.Errorf("invalid lanAuth: username and password must not contain control characters")
	}
	return nil
}

func (c File) AuthFor(bind string) (user, pass string) {
	if c.LANAuth == nil {
		return "", ""
	}
	if isLoopback(authHost(bind)) {
		return "", ""
	}
	return c.LANAuth.Username, c.LANAuth.Password
}

func authHost(bind string) string {
	bind = strings.TrimSpace(bind)
	if h, _, err := net.SplitHostPort(bind); err == nil {
		return h
	}
	return strings.Trim(bind, "[]")
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
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
