package indexer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
		io.WriteString(w, `{"hits":{"total":{"value":42},"hits":[{"_id":"a1","_source":{"rule":{"id":"5710"}},"sort":[1794992299000,"1794992299.123"]}]},"aggregations":{"top_rules":{"buckets":[]}}}`)
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
	// The sort values of the last hit become a cursor that the next page accepts as-is.
	after, err := DecodeCursor(EncodeCursor(res.Hits[0].Sort))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(after)
	if string(b) != `[1794992299000,"1794992299.123"]` {
		t.Fatalf("cursor round trip = %s", b)
	}
}

func TestAbsoluteTimeRange(t *testing.T) {
	q, err := AlertsQuery(AlertFilter{From: "2026-08-01", To: "2026-11-01T08:00:00+07:00", Window: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(q)
	if !strings.Contains(string(b), `"gte":"2026-08-01T00:00:00Z","lte":"2026-11-01T01:00:00Z"`) {
		t.Fatalf("range not absolute UTC: %s", b)
	}
	for _, f := range []AlertFilter{
		{To: "2026-11-01"},                     // to without from
		{From: "2026-11-02", To: "2026-11-01"}, // reversed
		{From: "yesterday"},
		{From: "2026-11-01T08:00:00Z;x"},
	} {
		if _, err := AlertsQuery(f); err == nil {
			t.Errorf("%+v should fail", f)
		}
	}
	start, err := AlertFilter{Window: "7d"}.Start(time.Unix(1_000_000, 0))
	if err != nil || start.Unix() != 1_000_000-7*86400 {
		t.Errorf("Start = %v, %v", start, err)
	}
}

func TestTimelineQuery(t *testing.T) {
	q, err := TimelineQuery(AlertFilter{Window: "1d", Limit: 5000}, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(q)
	if q["size"] != TimelineMax || !strings.Contains(string(b), `{"@timestamp":"asc"}`) || q["search_after"] != nil {
		t.Fatalf("timeline query = %s", b)
	}
	cur := EncodeCursor([]any{float64(1794992299000), "1794992299.1"})
	q, err = TimelineQuery(AlertFilter{Window: "1d"}, cur)
	if err != nil || q["search_after"] == nil {
		t.Fatalf("cursor not applied: %v", err)
	}
	for _, bad := range []string{"x", EncodeCursor([]any{"a", "b"}), EncodeCursor([]any{float64(1), "id;drop"}), strings.Repeat("A", 300)} {
		if _, err := TimelineQuery(AlertFilter{Window: "1d"}, bad); err == nil {
			t.Errorf("cursor %q should be refused", bad)
		}
	}
}

func TestInvestigationQueriesNeedTheirKey(t *testing.T) {
	if _, err := AttackerProfileQuery(AlertFilter{Window: "1d"}); err == nil {
		t.Error("profile without srcip must fail")
	}
	if _, err := HostActivityQuery(AlertFilter{Window: "1d"}); err == nil {
		t.Error("host activity without agent must fail")
	}
	hq, _ := HostActivityQuery(AlertFilter{AgentID: "001", Window: "1d"})
	if hb, _ := json.Marshal(hq); !strings.Contains(string(hb), `"rule.id":"40112"`) {
		t.Error("host logins must include rule 40112 (success after brute force)")
	}
	if _, err := AttackerProfileQuery(AlertFilter{SrcIP: "10.0.0.5", ExcludeAgentID: "../x"}); err == nil {
		t.Error("bad exclude agent id must fail")
	}
	q, err := AttackerProfileQuery(AlertFilter{SrcIP: "10.0.0.5", Window: "30d"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(q)
	if !strings.Contains(string(b), `"data.srcip":"10.0.0.5"`) || !strings.Contains(string(b), "authentication_success") || !strings.Contains(string(b), `"rule.id":"40112"`) {
		t.Fatalf("profile query = %s", b)
	}
}
