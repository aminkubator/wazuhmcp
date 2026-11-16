// Package api is a small client for the Wazuh server (manager) REST API on
// port 55000. It handles JWT login and refresh and exposes only the calls
// this project needs.
//
// Alerts and vulnerability data are NOT here: since Wazuh 4.8 they live in the
// Wazuh Indexer (see package indexer).
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Options configures a Client.
type Options struct {
	BaseURL  string // e.g. https://wazuh.example:55000
	User     string
	Password string
	// CAFile is a PEM bundle to trust (Wazuh ships self-signed certificates).
	CAFile string
	// InsecureSkipVerify disables TLS verification. Avoid; prefer CAFile.
	InsecureSkipVerify bool
	// TLSServerName is the host name the certificate must match. Use it when
	// connecting by IP or through a tunnel (Wazuh certificates carry DNS names
	// such as wazuh.manager, not IP addresses). Verification stays on.
	TLSServerName string
	Timeout       time.Duration
}

// Client talks to the Wazuh manager API.
type Client struct {
	base     *url.URL
	user     string
	password string
	http     *http.Client

	mu    sync.Mutex
	token string
	exp   time.Time
}

// New builds a Client. It does not contact the server.
func New(o Options) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(o.BaseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid Wazuh API URL %q", o.BaseURL)
	}
	hc, err := HTTPClient(o.CAFile, o.InsecureSkipVerify, o.TLSServerName, o.Timeout)
	if err != nil {
		return nil, err
	}
	return &Client{base: u, user: o.User, password: o.Password, http: hc}, nil
}

// HTTPClient builds an http.Client with the TLS settings shared by the API and
// Indexer clients. Proxies from the environment are ignored on purpose.
func HTTPClient(caFile string, insecure bool, serverName string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure, ServerName: serverName} //nolint:gosec // explicit opt-in flag
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no valid certificate")
		}
		tc.RootCAs = pool
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil},
	}, nil
}

// Error is a non-2xx answer from Wazuh.
type Error struct {
	Status int
	Title  string
	Detail string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("wazuh api: HTTP %d", e.Status)
	if e.Title != "" {
		msg += ": " + e.Title
	}
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	return msg
}

// tokenLifetime is conservative: Wazuh tokens last 900 s by default.
const tokenLifetime = 800 * time.Second

func (c *Client) authenticate(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.exp) {
		return c.token, nil
	}
	u := *c.base
	u.Path += "/security/user/authenticate"
	u.RawQuery = "raw=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.user, c.password)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("wazuh api login: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Status: resp.StatusCode, Title: "login failed"}
	}
	c.token = strings.TrimSpace(string(body))
	c.exp = time.Now().Add(tokenLifetime)
	return c.token, nil
}

func (c *Client) invalidate() {
	c.mu.Lock()
	c.token, c.exp = "", time.Time{}
	c.mu.Unlock()
}

// Do sends an authenticated request and decodes the JSON answer into out
// (which may be nil). It retries once with a fresh token on HTTP 401.
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.authenticate(ctx)
		if err != nil {
			return err
		}
		u := *c.base
		u.Path += path
		u.RawQuery = q.Encode()
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("wazuh api: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.invalidate()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			var pe struct {
				Title  string `json:"title"`
				Detail string `json:"detail"`
			}
			_ = json.Unmarshal(raw, &pe)
			return &Error{Status: resp.StatusCode, Title: pe.Title, Detail: pe.Detail}
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("wazuh api: decode response: %w", err)
		}
		return nil
	}
}

// ---------------------------------------------------------------------------
// Typed calls
// ---------------------------------------------------------------------------

// Items is the standard Wazuh answer envelope.
type Items[T any] struct {
	Data struct {
		AffectedItems      []T              `json:"affected_items"`
		TotalAffectedItems int              `json:"total_affected_items"`
		FailedItems        []map[string]any `json:"failed_items"`
	} `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

// Agent is the subset of agent fields we expose.
type Agent struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	IP            string   `json:"ip"`
	Status        string   `json:"status"`
	Version       string   `json:"version"`
	Group         []string `json:"group,omitempty"`
	NodeName      string   `json:"node_name,omitempty"`
	LastKeepAlive string   `json:"lastKeepAlive,omitempty"`
	OS            struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Platform string `json:"platform"`
	} `json:"os"`
}

// ListAgentsParams filters ListAgents.
type ListAgentsParams struct {
	Status string // active, disconnected, never_connected, pending
	Search string
	Group  string
	Limit  int
	Offset int
}

// ListAgents returns agents (GET /agents).
func (c *Client) ListAgents(ctx context.Context, p ListAgentsParams) ([]Agent, int, error) {
	q := url.Values{}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.Group != "" {
		q.Set("group", p.Group)
	}
	if p.Limit <= 0 || p.Limit > 100 {
		p.Limit = 25
	}
	q.Set("limit", fmt.Sprint(p.Limit))
	q.Set("offset", fmt.Sprint(p.Offset))
	q.Set("sort", "+id")
	var out Items[Agent]
	if err := c.Do(ctx, http.MethodGet, "/agents", q, nil, &out); err != nil {
		return nil, 0, err
	}
	return out.Data.AffectedItems, out.Data.TotalAffectedItems, nil
}

// AgentsSummary returns connection status counts (GET /agents/summary/status).
func (c *Client) AgentsSummary(ctx context.Context) (map[string]any, error) {
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := c.Do(ctx, http.MethodGet, "/agents/summary/status", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// ManagerInfo returns the manager version and basics (GET /manager/info).
func (c *Client) ManagerInfo(ctx context.Context) (map[string]any, error) {
	var out Items[map[string]any]
	if err := c.Do(ctx, http.MethodGet, "/manager/info", nil, nil, &out); err != nil {
		return nil, err
	}
	if len(out.Data.AffectedItems) == 0 {
		return map[string]any{}, nil
	}
	return out.Data.AffectedItems[0], nil
}

// AgentPackages lists installed packages of an agent (syscollector).
func (c *Client) AgentPackages(ctx context.Context, agentID, search string, limit int) ([]map[string]any, int, error) {
	q := url.Values{}
	if search != "" {
		q.Set("search", search)
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	q.Set("limit", fmt.Sprint(limit))
	var out Items[map[string]any]
	if err := c.Do(ctx, http.MethodGet, "/syscollector/"+url.PathEscape(agentID)+"/packages", q, nil, &out); err != nil {
		return nil, 0, err
	}
	return out.Data.AffectedItems, out.Data.TotalAffectedItems, nil
}

// ExecResult summarises a write call that targets several agents.
type ExecResult struct {
	OK      []string         `json:"ok"`
	Failed  []map[string]any `json:"failed,omitempty"`
	Message string           `json:"message,omitempty"`
}

// Reasons returns the error message Wazuh gave for each failed agent, for
// example "The command used is not defined in the configuration.".
func (r ExecResult) Reasons() []string {
	var out []string
	for _, f := range r.Failed {
		if e, ok := f["error"].(map[string]any); ok {
			code, _ := e["code"].(float64)
			msg, _ := e["message"].(string)
			out = append(out, fmt.Sprintf("%v (code %d)", msg, int(code)))
		}
	}
	return out
}

func agentsQuery(ids []string) url.Values {
	return url.Values{"agents_list": {strings.Join(ids, ",")}}
}

func execResult(out Items[string]) ExecResult {
	return ExecResult{OK: out.Data.AffectedItems, Failed: out.Data.FailedItems, Message: out.Message}
}

// ActiveResponse runs an active-response command (PUT /active-response).
// alert carries the data the script reads, typically {"data":{"srcip":"..."}}.
func (c *Client) ActiveResponse(ctx context.Context, agentIDs []string, command string, args []string, alert map[string]any) (ExecResult, error) {
	body := map[string]any{"command": command, "arguments": args}
	if args == nil {
		body["arguments"] = []string{}
	}
	if alert != nil {
		body["alert"] = alert
	}
	var out Items[string]
	if err := c.Do(ctx, http.MethodPut, "/active-response", agentsQuery(agentIDs), body, &out); err != nil {
		return ExecResult{}, err
	}
	return execResult(out), nil
}

// RestartAgents restarts agents (PUT /agents/restart).
func (c *Client) RestartAgents(ctx context.Context, agentIDs []string) (ExecResult, error) {
	var out Items[string]
	if err := c.Do(ctx, http.MethodPut, "/agents/restart", agentsQuery(agentIDs), nil, &out); err != nil {
		return ExecResult{}, err
	}
	return execResult(out), nil
}

// RunSyscheck starts a FIM scan (PUT /syscheck).
func (c *Client) RunSyscheck(ctx context.Context, agentIDs []string) (ExecResult, error) {
	var out Items[string]
	if err := c.Do(ctx, http.MethodPut, "/syscheck", agentsQuery(agentIDs), nil, &out); err != nil {
		return ExecResult{}, err
	}
	return execResult(out), nil
}
