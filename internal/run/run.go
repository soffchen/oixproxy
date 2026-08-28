package run

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/soffchen/oixproxy/internal/config"
	"github.com/soffchen/oixproxy/internal/dialer"
	"github.com/soffchen/oixproxy/internal/panel"
	"github.com/soffchen/oixproxy/internal/profile"
	"github.com/soffchen/oixproxy/internal/serve"
)

// Version is set at link time by GitHub Actions (-X ...Version=vX.Y.Z).
var Version = "dev"

func Main(args []string) error {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("oixproxy ")
	name := programName()
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText(name)) }

	cfgPath := fs.String("config", "", "")
	fs.StringVar(cfgPath, "c", "", "")
	profilePath := fs.String("profile", "", "")
	listen := fs.String("listen", "", "")
	fs.StringVar(listen, "l", "", "")
	bind := fs.String("bind", "", "")
	mode := fs.String("mode", "", "")
	mapFlag := fs.Bool("map", false, "")
	single := fs.Bool("single", false, "")
	mapBase := fs.Int("map-base-port", 0, "")
	portFlag := fs.String("port", "", "")
	fs.StringVar(portFlag, "p", "", "")
	node := fs.String("node", "", "")
	fs.StringVar(node, "n", "", "")
	filterFlag := fs.String("filter", "", "")
	health := fs.String("healthcheck", "", "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	showVer := fs.Bool("version", false, "")
	fs.BoolVar(showVer, "v", false, "")
	tray := fs.Bool("tray", false, "")
	fs.BoolVar(tray, "menu", false, "")
	fs.BoolVar(tray, "menubar", false, "")
	serveHTTP := fs.Bool("serve", true, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}
	if *showVer {
		fmt.Println(versionLine(name))
		return nil
	}
	if *tray {
		return fmt.Errorf("tray mode is only available on macOS")
	}
	if *health != "" {
		return Healthcheck(*health)
	}

	var cfg config.File
	var err error
	path := *cfgPath
	if path == "" && *profilePath == "" {
		path = config.DefaultPath()
	}
	if path != "" {
		cfg, err = config.Load(path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("missing/invalid config: %s", path)
			}
			return fmt.Errorf("missing/invalid config: %w", err)
		}
	} else {
		cfg = config.Defaults()
		cfg.DataDir, err = config.DataDir()
		if err != nil {
			return err
		}
	}
	if *mapFlag {
		cfg.ProxyMode = "map"
	}
	if *single {
		cfg.ProxyMode = "single"
	}
	if *mode != "" {
		cfg.ProxyMode = *mode
	}
	switch cfg.ProxyMode {
	case "map", "single":
	default:
		return fmt.Errorf("unknown proxyMode %q (want map or single)", cfg.ProxyMode)
	}
	if *mapBase != 0 {
		cfg.MapBasePort = *mapBase
	}
	if *filterFlag != "" {
		cfg.Filter = *filterFlag
	}

	allNodes, tmpl, err := loadNodesRaw(cfg, *profilePath)
	if err != nil {
		return err
	}
	nodes, err := filterNodes(allNodes, cfg.Filter)
	if err != nil {
		return err
	}
	if *node != "" {
		n, err := Find(nodes, *node)
		if err != nil {
			return err
		}
		nodes = []dialer.Node{n}
	}

	listenAddr := cfg.ServeAddr(*listen)
	bindAddr := cfg.BindAddr(*bind)
	if host, p, ok := splitListen(*portFlag); ok {
		if host != "" {
			bindAddr = host
		}
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			cfg.MapBasePort = n
		}
	} else if cfg.ProxyMode == "single" && cfg.MapBasePort == 7200 {
		cfg.MapBasePort = 7100
	}
	if cfg.ProxyMode == "single" && *node == "" && len(nodes) > 1 {
		nodes = nodes[:1]
	}
	httpUser, httpPass := cfg.AuthFor(listenAddr)
	extras, err := extraListeners(cfg, nodes, allNodes, tmpl, bindAddr)
	if err != nil {
		return err
	}

	exe, _ := os.Executable()
	srv := &serve.Server{
		Listen:        listenAddr,
		Bind:          bindAddr,
		BasePort:      cfg.MapBasePort,
		User:          httpUser,
		Pass:          httpPass,
		Auth:          cfg.AuthFor,
		NoHTTP:        !*serveHTTP,
		Nodes:         nodes,
		Extras:        extras,
		Template:      tmpl,
		OpenSurgePath: filepath.Join(cfg.DataDir, "OpenSurge.yaml"),
		ProcessName:   filepath.Base(os.Args[0]),
		ProcessPath:   exe,
	}
	if err := srv.Start(); err != nil {
		return err
	}
	defer srv.Close()

	if p := os.Getenv("OIXPROXY_READY_FILE"); p != "" {
		_ = os.WriteFile(p, []byte(srv.Listen+"\n"), 0o600)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	return nil
}

func extraListeners(cfg config.File, nodes, allNodes []dialer.Node, template []byte, bind string) ([]serve.Extra, error) {
	if cfg.ProxyMode != "map" {
		return nil, nil
	}
	var out []serve.Extra
	seenNames := make(map[string]struct{}, len(allNodes)+len(cfg.Listeners))
	for _, n := range allNodes {
		seenNames[policyNameKey(n.Name)] = struct{}{}
	}
	for _, name := range serve.SurgeGroupNames(template) {
		seenNames[policyNameKey(name)] = struct{}{}
	}
	for i, l := range cfg.Listeners {
		name := strings.TrimSpace(l.Name)
		if err := validateListenerName(name); err != nil {
			return nil, fmt.Errorf("listeners[%d].name: %w", i, err)
		}
		nameKey := policyNameKey(name)
		if _, exists := seenNames[nameKey]; exists {
			return nil, fmt.Errorf("duplicate listener name %q", name)
		}
		if l.Port < 1 || l.Port > 65535 {
			return nil, fmt.Errorf("listeners[%d].port %d is invalid", i, l.Port)
		}
		if _, err := Find(allNodes, l.Node); err != nil {
			return nil, fmt.Errorf("listeners[%d]: %w", i, err)
		}
		n, err := Find(nodes, l.Node)
		if err != nil {
			seenNames[nameKey] = struct{}{}
			continue
		}
		host := strings.Trim(strings.TrimSpace(l.Listen), "[]")
		if host == "" {
			host = strings.Trim(strings.TrimSpace(bind), "[]")
		}
		out = append(out, serve.Extra{Name: name, Node: n, Addr: net.JoinHostPort(host, strconv.Itoa(l.Port))})
		seenNames[nameKey] = struct{}{}
	}
	return out, nil
}

func policyNameKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func validateListenerName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if strings.ContainsAny(name, "\r\n,=\\\"") || strings.ContainsFunc(name, unicode.IsControl) {
		return fmt.Errorf("name contains unsupported characters")
	}
	if strings.HasPrefix(name, "#") || strings.HasPrefix(name, ";") {
		return fmt.Errorf("name must not start with a comment marker")
	}
	for _, reserved := range []string{"Direct", "Block", "Proxy", "Auto - UrlTest", "Auto - Smart", "oixCloud"} {
		if strings.EqualFold(name, reserved) {
			return fmt.Errorf("name %q is reserved", name)
		}
	}
	return nil
}

func splitListen(v string) (host, port string, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", "", false
	}
	if !strings.Contains(v, ":") {
		if _, err := strconv.Atoi(v); err != nil {
			return "", "", false
		}
		return "", v, true
	}
	h, p, err := net.SplitHostPort(v)
	if err != nil {
		return "", "", false
	}
	return h, p, true
}

func programName() string {
	return filepath.Base(os.Args[0])
}

func versionLine(name string) string {
	if v := os.Getenv("OIXCLOUD_HELPER_VERSION"); v != "" {
		return name + " " + v
	}
	return name + " " + Version
}

func usageText(name string) string {
	return "Usage: " + name + ` [options]

  --tray, --menu, --menubar      Start menu bar helper
  --serve                        Local HTTP config server (default on; --serve=false disables)
  --listen, -l [host:]port       Serve address (default 127.0.0.1, config servePort or 6172)
  --port, -p [host:]port         Proxy listen address (SOCKS5 + HTTP)
  --bind <host>                  Bind address for proxy listeners (default 127.0.0.1)
  --node, -n <name>              Force node name for dial mode
  --filter <regexp>              Filter downloaded nodes (Clash Meta filter); mapping and generated configs only see matches
  --mode <single|map>            Select proxy mode (map default)
  --map                          Shortcut for --mode map
  --single                       Shortcut for --mode single
  --map-base-port <port>         Base port for map mode (default 7200)
  --config, -c <path>            Config file path
  --help, -h                     Show this help
  --version, -v                  Show version fingerprint
  --healthcheck [host:]port      Check the local config server health endpoint

Bind a non-loopback address (e.g. --listen 0.0.0.0:6172 / --bind 0.0.0.0)
to reach the config and proxies from other devices on the network. Set
` + "`lanAuth`" + ` in config.json to require one username/password across the HTTP
config endpoints plus SOCKS5 and HTTP proxy listeners. Authentication is
not encryption; only expose listeners on trusted or protected networks.
The generated config uses the address each device used to fetch it, so a
device fetching from http://<host>:6172/ gets proxies pointed at <host>.

Use http://127.0.0.1:6172/list as a Surge policy-path. Existing
policy-regex-filter values continue to filter the local node names.

Use http://127.0.0.1:6172/opensurge to inspect the OpenSurge
imported profile, or write OpenSurge.yaml next to the config data directory.

Map mode also honours a ` + "`listeners`" + ` array in the config file for
declaratively-bound fixed ports (see config.example.json).
`
}

func LoadNodes(cfg config.File, profilePath string) ([]dialer.Node, []byte, error) {
	nodes, tmpl, err := loadNodesRaw(cfg, profilePath)
	if err != nil {
		return nil, tmpl, err
	}
	nodes, err = filterNodes(nodes, cfg.Filter)
	return nodes, tmpl, err
}

func loadNodesRaw(cfg config.File, profilePath string) ([]dialer.Node, []byte, error) {
	var nodes []dialer.Node
	var tmpl []byte
	if profilePath != "" {
		n, err := profile.Load(profilePath)
		if err != nil {
			return nil, nil, err
		}
		nodes = n
	} else {
		if cfg.AccessToken == "" {
			return nil, nil, fmt.Errorf("config.json must contain accessToken (or pass --profile)")
		}
		c := panel.New(cfg.AccessToken)
		if cfg.APIBase != "" {
			c.Base = cfg.APIBase
		}
		if v := os.Getenv("OIXCLOUD_API_BASE"); v != "" {
			c.Base = v
		}
		c.OixParams = cfg.OixParams
		c.SimpleRules = cfg.SimpleRules
		if cfg.DataDir != "" {
			c.IdentityPath = filepath.Join(cfg.DataDir, ".identity")
		}
		n, err := c.FetchDedicatedNodes()
		if err != nil {
			return nil, c.Template, err
		}
		nodes, tmpl = n, c.Template
	}
	return nodes, tmpl, nil
}

func filterNodes(nodes []dialer.Node, filter string) ([]dialer.Node, error) {
	filtered, err := profile.Filter(nodes, filter)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filter) != "" && len(filtered) == 0 {
		return nil, fmt.Errorf("filter matched no nodes")
	}
	return filtered, nil
}

func Find(nodes []dialer.Node, name string) (dialer.Node, error) {
	for _, n := range nodes {
		if n.Name == name {
			return n, nil
		}
	}
	return dialer.Node{}, fmt.Errorf("node %q not found", name)
}

func Healthcheck(addr string) error {
	addrs, err := healthcheckAddrs(addr)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	var errs []error
	for _, candidate := range addrs {
		if err := checkHealth(client, candidate); err == nil {
			return nil
		} else {
			errs = append(errs, fmt.Errorf("health %s: %w", candidate, err))
		}
	}
	return errors.Join(errs...)
}

func healthcheckAddrs(addr string) ([]string, error) {
	addr = strings.TrimSpace(addr)
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if host != "" {
			return []string{addr}, nil
		}
		addr = port
	}
	port, err := strconv.Atoi(addr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid healthcheck address %q", addr)
	}
	ps := strconv.Itoa(port)
	return []string{net.JoinHostPort("127.0.0.1", ps), net.JoinHostPort("::1", ps)}, nil
}

func checkHealth(client *http.Client, addr string) error {
	const maxBody = 64

	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(b) > maxBody {
		return fmt.Errorf("health response exceeds %d bytes", maxBody)
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(b)) != "ok" {
		return fmt.Errorf("health %d %q", resp.StatusCode, b)
	}
	return nil
}
