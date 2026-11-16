package indexer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseWindow(t *testing.T) {
	for in, want := range map[string]string{"15m": "now-15m", "6h": "now-6h", "7d": "now-7d", "30d": "now-30d"} {
		got, err := ParseWindow(in)
		if err != nil || got != want {
			t.Errorf("ParseWindow(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0m", "31d", "99999m", "1w", "now-1h", "1h; drop", "-5m", "5"} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("ParseWindow(%q) should fail", bad)
		}
	}
}

func TestClampLimit(t *testing.T) {
	if ClampLimit(0) != DefaultLimit || ClampLimit(-3) != DefaultLimit || ClampLimit(7) != 7 || ClampLimit(5000) != MaxLimit {
		t.Error("ClampLimit misbehaves")
	}
}

func TestAlertsQueryShape(t *testing.T) {
	q, err := AlertsQuery(AlertFilter{Window: "15m", MinLevel: 10, AgentID: "001", SrcIP: "203.0.113.9", MitreID: "T1110", Group: "authentication_failed", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if q["size"] != MaxLimit {
		t.Errorf("size = %v, want capped at %d", q["size"], MaxLimit)
	}
	b, _ := json.Marshal(q)
	s := string(b)
	for _, want := range []string{`"now-15m"`, `"rule.level"`, `"agent.id":"001"`, `"data.srcip":"203.0.113.9"`, `"rule.mitre.id":"T1110"`, `"rule.groups":"authentication_failed"`} {
		if !strings.Contains(s, want) {
			t.Errorf("query misses %s: %s", want, s)
		}
	}
}

func TestAlertsQueryRejectsInjection(t *testing.T) {
	bad := []AlertFilter{
		{AgentID: `001" OR 1=1`},
		{SrcIP: "1.2.3.4 OR *"},
		{Group: `x"}},{"match_all":{}`},
		{MitreID: "T1110; drop"},
		{RuleID: "5710 OR 1"},
		{MinLevel: 99},
		{Window: "1h OR 1"},
		{Text: strings.Repeat("a", 201)},
	}
	for i, f := range bad {
		if _, err := AlertsQuery(f); err == nil {
			t.Errorf("case %d (%+v) should be rejected", i, f)
		}
	}
	if _, err := AlertByIDQuery(`abc"}},"size":10000,{"x":{`); err == nil {
		t.Error("alert id with quotes must be rejected")
	}
}

func TestVulnFilters(t *testing.T) {
	q, err := VulnQuery(VulnFilter{Severity: "critical", CVE: "cve-2024-12345", AgentID: "003"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(q)
	for _, want := range []string{`"vulnerability.severity":"Critical"`, `"vulnerability.id":"CVE-2024-12345"`, `"agent.id":"003"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	for _, bad := range []VulnFilter{{Severity: "urgent"}, {CVE: "CVE-1"}, {AgentID: "x"}} {
		if _, err := VulnQuery(bad); err == nil {
			t.Errorf("%+v should be rejected", bad)
		}
	}
}

func TestSearchOnlyFixedIndices(t *testing.T) {
	c, _ := New(Options{BaseURL: "https://127.0.0.1:1"})
	if _, err := c.Search(context.Background(), "*", map[string]any{}); err == nil {
		t.Fatal("arbitrary index must be refused")
	}
	if _, err := c.Search(context.Background(), "wazuh-monitoring-*", map[string]any{}); err == nil {
		t.Fatal("arbitrary index must be refused")
	}
}

func TestSearchParsesAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if user != "u" || pass != "p" || r.URL.Path != "/wazuh-alerts-4.x-*/_search" {
			t.Errorf("unexpected request: %s auth=%s/%s", r.URL.Path, user, pass)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"size":0`) {
			t.Errorf("body = %s", body)
		}
		io.WriteString(w, `{"hits":{"total":{"value":42},"hits":[{"_id":"a1","_source":{"rule":{"id":"5710"}}}]},"aggregations":{"top_rules":{"buckets":[]}}}`)
	}))
	defer srv.Close()
	c, err := New(Options{BaseURL: srv.URL, User: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Search(context.Background(), AlertsIndex, map[string]any{"size": 0})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 42 || len(res.Hits) != 1 || res.Hits[0].ID != "a1" || res.Aggregations["top_rules"] == nil {
		t.Fatalf("parsed = %+v", res)
	}
}
