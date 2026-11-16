package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeWazuh struct {
	logins   atomic.Int32
	revoked  atomic.Bool // next authenticated call gets 401 once
	lastBody atomic.Value
	lastQ    atomic.Value
}

func (f *fakeWazuh) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != "wazuh-api" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n := f.logins.Add(1)
		if r.URL.Query().Get("raw") != "true" {
			t.Error("login must use raw=true")
		}
		io.WriteString(w, "token-"+string(rune('0'+n)))
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if f.revoked.CompareAndSwap(true, false) || r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /agents", authed(func(w http.ResponseWriter, r *http.Request) {
		f.lastQ.Store(r.URL.RawQuery)
		io.WriteString(w, `{"data":{"affected_items":[{"id":"001","name":"web-1","ip":"10.0.0.5","status":"active","os":{"name":"Ubuntu","version":"22.04","platform":"ubuntu"},"version":"Wazuh v4.14.9"}],"total_affected_items":1},"error":0}`)
	}))
	mux.HandleFunc("PUT /active-response", authed(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.lastBody.Store(string(b))
		f.lastQ.Store(r.URL.RawQuery)
		io.WriteString(w, `{"data":{"affected_items":["001"],"total_affected_items":1,"failed_items":[]},"message":"AR command was sent to all agents","error":0}`)
	}))
	mux.HandleFunc("PUT /agents/restart", authed(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"title":"Permission Denied","detail":"agent:restart denied"}`)
	}))
	return mux
}

func newFake(t *testing.T) (*Client, *fakeWazuh) {
	f := &fakeWazuh{}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	c, err := New(Options{BaseURL: srv.URL + "/", User: "wazuh-api", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestListAgentsAndTokenReuse(t *testing.T) {
	c, f := newFake(t)
	for i := 0; i < 3; i++ {
		agents, total, err := c.ListAgents(context.Background(), ListAgentsParams{Status: "active", Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || agents[0].ID != "001" || agents[0].OS.Name != "Ubuntu" {
			t.Fatalf("agents = %+v", agents)
		}
	}
	if f.logins.Load() != 1 {
		t.Errorf("logged in %d times, want 1 (token must be reused)", f.logins.Load())
	}
	q := f.lastQ.Load().(string)
	if want := "limit=25"; !strings.Contains(q, want) { // 1000 is clamped
		t.Errorf("query %q should clamp the limit (%s)", q, want)
	}
	if !strings.Contains(q, "status=active") {
		t.Errorf("query %q misses the status filter", q)
	}
}

func TestRefreshesTokenOn401(t *testing.T) {
	c, f := newFake(t)
	if _, _, err := c.ListAgents(context.Background(), ListAgentsParams{}); err != nil {
		t.Fatal(err)
	}
	f.revoked.Store(true)
	if _, _, err := c.ListAgents(context.Background(), ListAgentsParams{}); err != nil {
		t.Fatalf("a 401 must trigger one re-login and a retry: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Errorf("logins = %d, want 2", f.logins.Load())
	}
}

func TestBadCredentials(t *testing.T) {
	f := &fakeWazuh{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c, _ := New(Options{BaseURL: srv.URL, User: "wazuh-api", Password: "wrong"})
	_, _, err := c.ListAgents(context.Background(), ListAgentsParams{})
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("err = %v, want *Error 401", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Error("error must never contain the password")
	}
}

func TestActiveResponseRequest(t *testing.T) {
	c, f := newFake(t)
	res, err := c.ActiveResponse(context.Background(), []string{"001", "004"}, "firewall-drop", nil,
		map[string]any{"data": map[string]any{"srcip": "203.0.113.9"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.OK) != 1 || res.OK[0] != "001" {
		t.Fatalf("res = %+v", res)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(f.lastBody.Load().(string)), &body); err != nil {
		t.Fatal(err)
	}
	if body["command"] != "firewall-drop" {
		t.Errorf("body = %v", body)
	}
	if args, ok := body["arguments"].([]any); !ok || len(args) != 0 {
		t.Errorf("arguments must be an empty list, got %v", body["arguments"])
	}
	if q := f.lastQ.Load().(string); !strings.Contains(q, "agents_list=001%2C004") {
		t.Errorf("query = %q", q)
	}
}

func TestErrorDetailsFromWazuh(t *testing.T) {
	c, _ := newFake(t)
	_, err := c.RestartAgents(context.Background(), []string{"001"})
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Title != "Permission Denied" {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidatesURL(t *testing.T) {
	for _, bad := range []string{"", "localhost:55000", "://x"} {
		if _, err := New(Options{BaseURL: bad}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if _, err := New(Options{BaseURL: "https://x:55000", CAFile: "/nonexistent.pem"}); err == nil {
		t.Error("missing CA file must be an error")
	}
}
