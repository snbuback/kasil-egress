// Package k8s is a deliberately small Kubernetes client: just enough REST to
// resolve pods to their workload owner and to read the Cilium policy
// inventory. It exists so the collector and the CLI do not drag in client-go
// (and its ~40 MB of transitive dependencies) for six list calls.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	saDir   = "/var/run/secrets/kubernetes.io/serviceaccount"
	saToken = "token"
	saCA    = "ca.crt"
)

// Client talks to the Kubernetes API server.
type Client struct {
	base  *url.URL
	http  *http.Client
	token string
}

// Config configures a Client. The zero value means "in cluster".
type Config struct {
	// Server is a full base URL (http:// or https://). When empty the
	// in-cluster service account environment is used.
	Server string
	Token  string
	// TokenFile is read on every request, so a rotated projected token is
	// picked up without a restart.
	TokenFile string
	CAFile    string
	Insecure  bool
}

// InCluster builds a client from the pod's service account.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST/PORT not set: not running in a cluster (use --kube-server)")
	}
	return New(Config{
		Server:    "https://" + net_JoinHostPort(host, port),
		TokenFile: filepath.Join(saDir, saToken),
		CAFile:    filepath.Join(saDir, saCA),
	})
}

// New builds a client from an explicit configuration.
func New(cfg Config) (*Client, error) {
	server := cfg.Server
	if server == "" {
		server = "https://kubernetes.default.svc"
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("parse server %q: %w", server, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.Insecure},
	}
	if cfg.CAFile != "" && !cfg.Insecure {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", cfg.CAFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	c := &Client{base: u, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}, token: cfg.Token}
	if cfg.TokenFile != "" {
		// Fail fast if the token is not readable; keep reading it per request.
		if _, err := os.ReadFile(cfg.TokenFile); err != nil {
			return nil, fmt.Errorf("read token: %w", err)
		}
		c.token = ""
		c.http.Transport = &tokenTransport{base: tr, file: cfg.TokenFile, static: cfg.Token}
	}
	return c, nil
}

type tokenTransport struct {
	base   http.RoundTripper
	file   string
	static string
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok := t.static
	if t.file != "" {
		if b, err := os.ReadFile(t.file); err == nil {
			tok = strings.TrimSpace(string(b))
		}
	}
	r := req.Clone(req.Context())
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return t.base.RoundTrip(r)
}

// Get fetches a path (e.g. "/api/v1/namespaces") and returns the body.
func (c *Client) Get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s: %s", path, resp.Status, truncate(body, 300))
	}
	return body, nil
}

// Do performs a write request (PATCH/POST) and returns the body and status.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, int, error) {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}

// ListAll lists every page of a collection and returns the concatenated items.
func (c *Client) ListAll(ctx context.Context, path string) ([]json.RawMessage, error) {
	var items []json.RawMessage
	cont := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{"limit": {"500"}}
		if cont != "" {
			q.Set("continue", cont)
		}
		body, err := c.Get(ctx, path, q)
		if err != nil {
			return nil, err
		}
		var l struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(body, &l); err != nil {
			return nil, fmt.Errorf("decode list %s: %w", path, err)
		}
		items = append(items, l.Items...)
		if l.Metadata.Continue == "" {
			return items, nil
		}
		cont = l.Metadata.Continue
	}
	return items, fmt.Errorf("list %s: pagination did not terminate", path)
}

func truncate(b []byte, n int) string {
	b = bytes.TrimSpace(b)
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// net_JoinHostPort avoids importing net just for JoinHostPort on IPv6 literals.
func net_JoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
