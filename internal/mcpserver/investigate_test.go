package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/wazuh/indexer"
)

func aggs(t *testing.T, js string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHostTriageFlagsCompromise(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.ReadOnly})
	h.idx.result = &indexer.Result{Total: 3, Aggregations: aggs(t, `{
		"logins":{"doc_count":1,"from_ip":{"buckets":[{"key":"203.0.113.9","doc_count":1,
			"first_seen":{"value_as_string":"2026-10-01T02:00:00.000Z"},"last_seen":{"value_as_string":"2026-10-01T02:00:00.000Z"},
			"users":{"buckets":[{"key":"deploy","doc_count":1}]}}]}},
		"rootcheck":{"doc_count":2,"findings":{"buckets":[]}},
		"file_changes":{"doc_count":2,"paths":{"buckets":[
			{"key":"/etc/cron.d/x","doc_count":1,"event":{"buckets":[{"key":"added"}]},"first_seen":{"value_as_string":"2026-10-01T03:00:00.000Z"}},
			{"key":"/etc/motd","doc_count":1,"event":{"buckets":[{"key":"modified"}]},"first_seen":{"value_as_string":"2026-10-01T03:00:00.000Z"}}]}},
		"agents_targeted":{"buckets":[{"key":"002","doc_count":3,"first_seen":{"value_as_string":"2026-10-02T00:00:00.000Z"}}]}
	}`)}
	out, res := h.call(t, "host_triage", map[string]any{"agent_id": "001", "window": "1h"})
	if res.IsError {
		t.Fatal(text(res))
	}
	ind := strings.Join(func() []string {
		var s []string
		for _, v := range out["indicators"].([]any) {
			s = append(s, v.(string))
		}
		return s
	}(), "\n")
	for _, want := range []string{
		"runs from /tmp/",                   // process in /tmp
		"known attacker/miner tool name",    // nc
		"nc listens on 0.0.0.0:4444",        // bind shell, process name taken from pid
		`account "toor" has uid 0`,          // second root
		"successful login from 203.0.113.9", // alert
		"rootcheck alerts",                  // alert
		"as SOURCE against 1 agent(s)",      // lateral movement from 10.0.0.5
		"file added in a persistence location: /etc/cron.d/x",
		"port 8081/tcp is open on 0.0.0.0 but the owning process is unknown",
		`password of "deploy" changed in the period`, // day-granular value, 1h period
	} {
		if !strings.Contains(ind, want) {
			t.Errorf("missing indicator %q in:\n%s", want, ind)
		}
	}
	if strings.Contains(ind, "/etc/motd") || strings.Contains(ind, "port 25/") {
		t.Error("non-persistence file or loopback port must not be flagged")
	}
	if strings.Contains(ind, `"root" has uid 0`) {
		t.Error("root itself must not be flagged")
	}
	if n := len(out["login_users"].([]any)); n != 3 {
		t.Errorf("login_users = %d, want 3 (nologin excluded)", n)
	}
	// The "attacks from this host" search must leave out alerts raised on the host itself.
	self := false
	for _, b := range h.idx.bodies {
		js, _ := json.Marshal(b)
		if strings.Contains(string(js), `"data.srcip":"10.0.0.5"`) {
			self = strings.Contains(string(js), `"must_not":[{"term":{"agent.id":"001"}}]`)
		}
	}
	if !self {
		t.Error("attacks-from-this-host query does not exclude the agent itself")
	}
	if out["agent"].(map[string]any)["name"] != "web-1[31m" {
		t.Errorf("agent name not cleaned: %v", out["agent"])
	}

	if _, res := h.call(t, "host_triage", map[string]any{"agent_id": "../manager"}); !res.IsError {
		t.Error("bad agent id must be refused")
	}
}

func TestAttackerProfileFindsLoginAndInternalHost(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.ReadOnly})
	h.idx.result = &indexer.Result{Total: 9, Aggregations: aggs(t, `{
		"first_seen":{"value_as_string":"2026-09-01T00:00:00.000Z"},
		"agents_targeted":{"buckets":[
			{"key":"003","doc_count":2,"first_seen":{"value_as_string":"2026-09-05T00:00:00.000Z"},"name":{"buckets":[{"key":"db-1"}]}},
			{"key":"002","doc_count":7,"first_seen":{"value_as_string":"2026-09-01T00:00:00.000Z"},"name":{"buckets":[{"key":"web-2"}]}}]},
		"successful_logins":{"doc_count":1,"agents":{"buckets":[{"key":"db-1","doc_count":1,
			"first_seen":{"value_as_string":"2026-09-05T01:00:00.000Z"},"users":{"buckets":[{"key":"postgres"}]}}]}}
	}`)}
	out, res := h.call(t, "attacker_profile", map[string]any{"srcip": "10.0.0.5"})
	if res.IsError {
		t.Fatal(text(res))
	}
	got := out["agents_targeted"].([]any)
	if got[0].(map[string]any)["key"] != "002" {
		t.Errorf("agents not in first-seen order: %v", got)
	}
	f, _ := json.Marshal(out["findings"])
	for _, want := range []string{"belongs to our agent 001", "SUCCESSFUL LOGIN from 10.0.0.5 on db-1 as postgres", "touched 2 agents"} {
		if !strings.Contains(string(f), want) {
			t.Errorf("missing finding %q in %s", want, f)
		}
	}
	if _, res := h.call(t, "attacker_profile", map[string]any{"srcip": "not-an-ip"}); !res.IsError {
		t.Error("bad srcip must be refused")
	}

	// A failed agent lookup must be said, not read as "external source".
	h = newHarnessWith(t, policy.Config{Default: policy.ReadOnly}, failingAgents{})
	out, _ = h.call(t, "attacker_profile", map[string]any{"srcip": "10.0.0.5"})
	if f, _ := json.Marshal(out["findings"]); !strings.Contains(string(f), "could not check whether this IP is one of our agents") {
		t.Errorf("agent lookup failure hidden: %s", f)
	}
}

func TestTimelinePagesOldestFirst(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.ReadOnly})
	h.idx.result = &indexer.Result{Total: 5, Hits: []indexer.Hit{
		{ID: "a", Source: map[string]any{"@timestamp": "t1", "rule": map[string]any{"id": "5710"}}, Sort: []any{1.0, "1.1"}},
		{ID: "b", Source: map[string]any{"@timestamp": "t2", "data": map[string]any{"srcip": "10.0.0.5"}}, Sort: []any{2.0, "1.2"}},
	}}
	out, res := h.call(t, "alerts_timeline", map[string]any{"from": "2026-09-01", "limit": 2})
	if res.IsError {
		t.Fatal(text(res))
	}
	b, _ := json.Marshal(h.idx.lastBody)
	if !strings.Contains(string(b), `"gte":"2026-09-01T00:00:00Z"`) || !strings.Contains(string(b), `"asc"`) {
		t.Fatalf("query = %s", b)
	}
	cur, _ := out["next_cursor"].(string)
	if cur == "" {
		t.Fatal("full page must return next_cursor")
	}
	if _, res := h.call(t, "alerts_timeline", map[string]any{"from": "2026-09-01", "limit": 2, "cursor": cur}); res.IsError {
		t.Fatal(text(res))
	}
	if h.idx.lastBody["search_after"] == nil {
		t.Error("cursor not sent as search_after")
	}
}
