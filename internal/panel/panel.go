package panel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/soffchen/oixproxy/internal/dialer"
	"github.com/soffchen/oixproxy/internal/identity"
	"github.com/soffchen/oixproxy/internal/profile"
)

// DefaultBase is the panel host used by oixcloud-external-proxy-program
// (POST /api/v1/information and /api/v1/managed/surge).
const DefaultBase = "https://oixcloud.com"

type Client struct {
	Base         string
	Token        string
	OixParams    string
	SimpleRules  bool
	IdentityPath string
	HTTP         *http.Client
	Template     []byte

	ident      *age.X25519Identity
	decryptErr error
}

func New(token string) *Client {
	return &Client{
		Base:  DefaultBase,
		Token: token,
		HTTP:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) base() string {
	if c.Base == "" {
		return DefaultBase
	}
	return strings.TrimRight(c.Base, "/")
}

func (c *Client) postForm(path string, form url.Values) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.dedicatedBase()+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("User-Agent", anywhereUA)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("panel returned HTTP %d: %s", resp.StatusCode, truncate(b, 200))
	}
	return b, nil
}

// Login authenticates with the access token (helper: POST /api/v1/information).
func (c *Client) Login() error {
	form := url.Values{}
	form.Set("access_token", c.Token)
	b, err := c.postForm("/api/v1/information", form)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	ret, msg, _, _ := decodeRet(b)
	if ret != 200 {
		return fmt.Errorf("account authentication failed (ret=%d): %s", ret, msg)
	}
	return nil
}

// FetchDedicated downloads the helper node payload.
// It never rewrites the download to public clash=1 (anytls).
func (c *Client) FetchDedicated() ([]byte, error) {
	nodes, tmpl, err := c.Fetch()
	if err != nil {
		return nil, err
	}
	c.Template = tmpl
	if len(nodes) == 0 {
		return tmpl, fmt.Errorf("no snell ech-tls nodes")
	}
	// Keep a YAML view for callers that persist the body.
	return tmpl, nil
}

func (c *Client) ensureIdentity() error {
	if c.ident != nil {
		return nil
	}
	path := c.IdentityPath
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".config/oixcloud-external-proxy-program", ".identity")
	}
	id, err := identity.LoadOrCreateAge(path)
	if err != nil {
		return err
	}
	c.ident = id
	c.IdentityPath = path
	return nil
}

func (c *Client) agePub() string {
	if c.ident == nil {
		return ""
	}
	return c.ident.Recipient().String()
}

// Fetch logs in, POSTs the reversed dedicated endpoint
// /api/v1/managed/anywhere/direct (signed X-Anywhere-* + age pubkey),
// then loads the Surge template via /api/v1/managed/surge without clash=1.
func (c *Client) Fetch() ([]dialer.Node, []byte, error) {
	if err := c.Login(); err != nil {
		return nil, nil, err
	}
	var nodes []dialer.Node
	if n, _, err := c.fetchAnywhere(); err == nil {
		nodes = n
	}
	tmplNodes, tmpl, tmplErr := c.fetchSurgeTemplate()
	if len(nodes) == 0 {
		nodes = tmplNodes
	}
	if len(nodes) == 0 {
		if tmplErr != nil {
			return nil, tmpl, tmplErr
		}
		return nil, tmpl, fmt.Errorf("no snell ech-tls nodes")
	}
	profile.ApplyDNS(nodes, profile.ParseDNS(tmpl))
	return nodes, tmpl, nil
}

func (c *Client) dedicatedBase() string {
	if c.Base != "" && c.Base != DefaultBase {
		return strings.TrimRight(c.Base, "/")
	}
	return anywhereHost
}

func (c *Client) fetchAnywhere() ([]dialer.Node, []byte, error) {
	if err := c.ensureIdentity(); err != nil {
		return nil, nil, err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	pub := c.agePub()
	path := anywherePath() + "?mode=premium"
	b, hdr, err := c.getSigned(c.dedicatedBase(), path, ts, pub, anywhereUA, hdrTimestamp(), hdrSignature(), hdrAgePubkey())
	if err != nil {
		return nil, nil, err
	}
	_, _, _, cfg := decodeRet(b)
	if sig := hdr.Get(hdrResponseSig()); sig != "" {
		ok := VerifyAnywhere(AppSecret(), ts, string(b), sig)
		if !ok && cfg != nil {
			ok = VerifyAnywhere(AppSecret(), ts, string(cfg), sig)
		}
		if !ok {
			return nil, b, fmt.Errorf("response signature mismatch")
		}
	}
	return c.nodesFromBody(b)
}

func (c *Client) getSigned(host, path, ts, pub, ua, hTS, hSig, hAge string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, host+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("User-Agent", ua)
	req.Header.Set(hTS, ts)
	req.Header.Set(hAge, pub)
	req.Header.Set(hSig, SignAnywhere(AppSecret(), ts, pub))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.Header, err
	}
	if resp.StatusCode >= 400 {
		return nil, resp.Header, fmt.Errorf("anywhere HTTP %d: %s", resp.StatusCode, truncate(b, 200))
	}
	return b, resp.Header, nil
}

func (c *Client) nodesFromBody(b []byte) ([]dialer.Node, []byte, error) {
	ret, msg, _, cfg := decodeRet(b)
	if ret != 0 && ret != 200 {
		return nil, b, fmt.Errorf("config fetch rejected (ret=%d): %s", ret, msg)
	}
	candidates := [][]byte{b}
	if cfg != nil {
		candidates = append([][]byte{cfg}, candidates...)
	}
	for _, raw := range candidates {
		plain := c.maybeDecrypt(raw)
		if nodes, err := profile.Parse(plain); err == nil && len(nodes) > 0 {
			return nodes, plain, nil
		}
	}
	return nil, b, fmt.Errorf("no snell ech-tls nodes")
}

func (c *Client) maybeDecrypt(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return b
	}
	if strings.Contains(s, "-----BEGIN AGE ENCRYPTED FILE-----") || strings.HasPrefix(s, "age-encryption.org/v1") {
		if c.ident != nil {
			out, err := identity.DecryptAge(c.ident, []byte(s))
			if err == nil && len(out) > 0 {
				return out
			}
			c.decryptErr = err
		}
	}
	compact := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	raw, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err == nil && len(raw) > 16 {
		rs := string(raw)
		if strings.Contains(rs, "age-encryption.org/v1") || strings.Contains(rs, "-----BEGIN AGE") {
			if c.ident != nil {
				out, err := identity.DecryptAge(c.ident, raw)
				if err == nil && len(out) > 0 {
					return out
				}
				c.decryptErr = err
			}
		}
		if nodes, err := profile.Parse(raw); err == nil && len(nodes) > 0 {
			return raw
		}
	}
	return b
}

func (c *Client) fetchSurgeTemplate() ([]dialer.Node, []byte, error) {
	form := url.Values{}
	form.Set("external-proxy-program", "true")
	form.Set("access_token", c.Token)
	if c.SimpleRules {
		form.Set("simplerules", "true")
	}
	if c.OixParams != "" {
		for _, part := range strings.Split(c.OixParams, "&") {
			k, v, ok := strings.Cut(part, "=")
			if ok && k != "" && k != "clash" {
				form.Set(k, v)
			}
		}
	}
	b, err := c.postForm("/api/v1/managed/surge", form)
	if err != nil {
		return nil, nil, err
	}
	ret, msg, smart, configField := decodeRet(b)
	if ret != 200 {
		return nil, nil, fmt.Errorf("config fetch rejected (ret=%d): %s", ret, msg)
	}

	var bodies [][]byte
	if configField != nil {
		bodies = append(bodies, c.maybeDecrypt(configField))
	}
	if nodes, err := profile.Parse(b); err == nil {
		return nodes, pickTemplate(bodies, b), nil
	}
	if smart == "" {
		for _, body := range bodies {
			if nodes, err := profile.Parse(body); err == nil && len(nodes) > 0 {
				return nodes, pickTemplate(bodies, body), nil
			}
		}
		if nodes, err := profile.Parse(b); err == nil {
			return nodes, b, nil
		}
		return nil, pickTemplate(bodies, b), fmt.Errorf("empty Surge subscription URL")
	}

	dl := c.dedicatedDownloadURL(smart)
	if dl != "" {
		if body, err := c.get(dl); err == nil {
			bodies = append(bodies, body)
			if nodes, err := profile.Parse(body); err == nil {
				return nodes, pickTemplate(bodies, body), nil
			}
		}
	}

	tmpl := pickTemplate(bodies, b)
	if nodes, err := profile.Parse(tmpl); err == nil {
		return nodes, tmpl, nil
	}
	return nil, tmpl, nil
}

func (c *Client) get(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", anywhereUA)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("subscription HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// FetchDedicatedNodes logs in, downloads the dedicated payload, and parses snell+ech-tls nodes.
func (c *Client) FetchDedicatedNodes() ([]dialer.Node, error) {
	nodes, tmpl, err := c.Fetch()
	c.Template = tmpl
	return nodes, err
}

func (c *Client) dedicatedDownloadURL(smart string) string {
	u, err := url.Parse(smart)
	if err != nil {
		return ""
	}
	if !u.IsAbs() {
		u, err = url.Parse(c.dedicatedBase() + smart)
		if err != nil {
			return ""
		}
	}
	ded := rawQueryParam(u.RawQuery, "dedicated_access")
	if ded == "" {
		return u.String()
	}
	// Official helper uses this exact order; Go's url.Values.Encode sorts
	// keys and oics.net returns 403 if dedicated_access comes first.
	q := "external-proxy-program=true&"
	if c.SimpleRules {
		q += "simplerules=true&"
	}
	q += "dedicated_access=" + ded
	u.RawQuery = q
	return u.String()
}

func rawQueryParam(raw, key string) string {
	for _, part := range strings.Split(raw, "&") {
		k, v, ok := strings.Cut(part, "=")
		if ok && k == key {
			return v
		}
	}
	return ""
}

func pickTemplate(bodies [][]byte, fallback []byte) []byte {
	var best []byte
	for _, b := range bodies {
		if looksLikeSurge(b) && len(b) >= len(best) {
			best = b
		}
	}
	if len(best) > 0 {
		return best
	}
	if looksLikeSurge(fallback) {
		return fallback
	}
	for _, b := range bodies {
		if len(b) > len(best) {
			best = b
		}
	}
	if len(best) > 0 {
		return best
	}
	return fallback
}

func looksLikeSurge(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "[Proxy]") || strings.Contains(s, "#!MANAGED-CONFIG")
}

func decodeRet(b []byte) (int, string, string, []byte) {
	var wrap struct {
		Ret    json.RawMessage `json:"ret"`
		Msg    string          `json:"msg"`
		Smart  string          `json:"smart"`
		Config json.RawMessage `json:"config"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return 0, "", "", nil
	}
	var ret int
	if json.Unmarshal(wrap.Ret, &ret) != nil {
		var rs string
		_ = json.Unmarshal(wrap.Ret, &rs)
		fmt.Sscanf(rs, "%d", &ret)
	}
	var cfg []byte
	if len(wrap.Config) > 0 && string(wrap.Config) != "null" {
		var s string
		if json.Unmarshal(wrap.Config, &s) == nil {
			cfg = []byte(s)
		} else {
			cfg = wrap.Config
		}
	}
	if cfg == nil && len(wrap.Data) > 0 {
		var inner struct {
			Config json.RawMessage `json:"config"`
			Smart  string          `json:"smart"`
		}
		if json.Unmarshal(wrap.Data, &inner) == nil {
			if inner.Smart != "" && wrap.Smart == "" {
				wrap.Smart = inner.Smart
			}
			if len(inner.Config) > 0 && string(inner.Config) != "null" {
				var s string
				if json.Unmarshal(inner.Config, &s) == nil {
					cfg = []byte(s)
				} else {
					cfg = inner.Config
				}
			}
		}
	}
	return ret, wrap.Msg, wrap.Smart, cfg
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
