// Package indexer is a read-only client for the Wazuh Indexer (OpenSearch,
// port 9200), where Wazuh 4.8+ stores alerts and vulnerability state.
//
// Index names are constants and queries are built from typed parameters (see
// queries.go). The AI never sends raw query DSL.
package indexer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wazuhmcp/internal/wazuh/api"
)

// Index patterns for Wazuh 4.14.
const (
	AlertsIndex = "wazuh-alerts-4.x-*"
	VulnIndex   = "wazuh-states-vulnerabilities-*"
)

// Options configures a Client.
type Options struct {
	BaseURL            string // e.g. https://wazuh.example:9200
	User               string
	Password           string
	CAFile             string
	InsecureSkipVerify bool
	TLSServerName      string // certificate host name to expect, see api.Options
	Timeout            time.Duration
}

// Client queries the indexer.
type Client struct {
	base     *url.URL
	user     string
	password string
	http     *http.Client
}

// New builds a Client. It does not contact the server.
func New(o Options) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(o.BaseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid Wazuh Indexer URL %q", o.BaseURL)
	}
	hc, err := api.HTTPClient(o.CAFile, o.InsecureSkipVerify, o.TLSServerName, o.Timeout)
	if err != nil {
		return nil, err
	}
	return &Client{base: u, user: o.User, password: o.Password, http: hc}, nil
}

// Hit is one matching document.
type Hit struct {
	ID     string         `json:"id"`
	Source map[string]any `json:"source"`
	Sort   []any          `json:"-"` // sort values, for search_after paging
}

// Result is a parsed _search answer.
type Result struct {
	Total        int64
	Hits         []Hit
	Aggregations map[string]any
}

// Search runs a query against one of the fixed index patterns.
func (c *Client) Search(ctx context.Context, index string, body map[string]any) (*Result, error) {
	if index != AlertsIndex && index != VulnIndex {
		return nil, fmt.Errorf("index %q is not allowed", index)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	u := *c.base
	u.Path += "/" + index + "/_search"
	u.RawQuery = "ignore_unavailable=true&track_total_hits=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wazuh indexer: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wazuh indexer: HTTP %d", resp.StatusCode)
	}
	return parseResult(raw)
}

func parseResult(raw []byte) (*Result, error) {
	var env struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
			Hits []struct {
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
				Sort   []any          `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations map[string]any `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("wazuh indexer: decode response: %w", err)
	}
	res := &Result{Total: env.Hits.Total.Value, Aggregations: env.Aggregations}
	for _, h := range env.Hits.Hits {
		res.Hits = append(res.Hits, Hit{ID: h.ID, Source: h.Source, Sort: h.Sort})
	}
	return res, nil
}
