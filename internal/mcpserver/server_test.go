package mcpserver

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wazuhmcp/internal/plans"
	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/response"
	"wazuhmcp/internal/wazuh/api"
	"wazuhmcp/internal/wazuh/indexer"
)

// ---- fakes -----------------------------------------------------------------

type fakeManager struct{}

func (fakeManager) ListAgents(context.Context, api.ListAgentsParams) ([]api.Agent, int, error) {
	return []api.Agent{{ID: "001", Name: "web-1\x1b[31m", Status: "active"}}, 1, nil
}
func (fakeManager) AgentsSummary(context.Context) (map[string]any, error) {
	return map[string]any{"connection": map[string]any{"active": 3}}, nil
}
func (fakeManager) ManagerInfo(context.Context) (map[string]any, error) {
	return map[string]any{"version": "v4.14.9"}, nil
}
func (fakeManager) AgentPackages(context.Context, string, string, int) ([]map[string]any, int, error) {
	return nil, 0, nil
}

type fakeIndexer struct {
	lastBody map[string]any
	result   *indexer.Result
}

func (f *fakeIndexer) Search(_ context.Context, index string, body map[string]any) (*indexer.Result, error) {
	f.lastBody = body
	if f.result != nil {
		return f.result, nil
	}
	return &indexer.Result{}, nil
}

type fakeExec struct{ calls int }

func (f *fakeExec) ActiveResponse(_ context.Context, ids []string, _ string, _ []string, _ map[string]any) (api.ExecResult, error) {
	f.calls++
	return api.ExecResult{OK: ids}, nil
}
func (f *fakeExec) RestartAgents(_ context.Context, ids []string) (api.ExecResult, error) {
	f.calls++
	return api.ExecResult{OK: ids}, nil
}
func (f *fakeExec) RunSyscheck(_ context.Context, ids []string) (api.ExecResult, error) {
	f.calls++
	return api.ExecResult{OK: ids}, nil
}

// ---- harness ---------------------------------------------------------------

type harness struct {
	sess *mcp.ClientSession
	svc  *response.Service
	idx  *fakeIndexer
	exec *fakeExec
}

func newHarness(t *testing.T, cfg policy.Config) *harness {
	t.Helper()
	if cfg.AllowedTTLs == nil {
		cfg.AllowedTTLs = response.DefaultCommands().TTLs()
	}
	pol, err := policy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ex := &fakeExec{}
	svc := response.New(pol, plans.NewStore(time.Hour), nil, ex, response.DefaultCommands(), nil)
	idx := &fakeIndexer{}
	srv := New(Deps{Manager: fakeManager{}, Indexer: idx, Response: svc}, "test")

	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return &harness{sess: sess, svc: svc, idx: idx, exec: ex}
}

func (h *harness) tools(t *testing.T) []string {
	t.Helper()
	res, err := h.sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	sort.Strings(names)
	return names
}

func (h *harness) call(t *testing.T, name string, args map[string]any) (map[string]any, *mcp.CallToolResult) {
	t.Helper()
	res, err := h.sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	var out map[string]any
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &out)
	}
	return out, res
}

func text(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func has(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// ---- tests -----------------------------------------------------------------

var readTools = []string{"health", "agents_list", "agent_packages", "alerts_search", "alerts_summary", "alert_get",
	"vulns_search", "vulns_summary", "mitigation_options", "autonomy_status"}

func TestToolsRegisteredPerAutonomyLevel(t *testing.T) {
	cases := []struct {
		name    string
		cfg     policy.Config
		plan    bool
		execute bool
	}{
		{"readonly", policy.Config{Default: policy.ReadOnly}, false, false},
		{"propose", policy.Config{Default: policy.Propose}, true, false},
		{"approve", policy.Config{Default: policy.Approve}, true, true},
		{"auto", policy.Config{Default: policy.Auto}, true, true},
		{"readonly with one action on auto", policy.Config{Default: policy.ReadOnly, Overrides: map[policy.Action]policy.Level{policy.ScanFIM: policy.Auto}}, true, true},
		{"auto lowered to propose", policy.Config{Default: policy.Auto, Overrides: func() map[policy.Action]policy.Level {
			m := map[policy.Action]policy.Level{}
			for _, a := range policy.Actions() {
				m[a.Action] = policy.Propose
			}
			return m
		}()}, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			names := newHarness(t, c.cfg).tools(t)
			for _, rt := range readTools {
				if !has(names, rt) {
					t.Errorf("read tool %s missing", rt)
				}
			}
			for _, pt := range []string{"response_propose", "response_plans", "blocks_list"} {
				if has(names, pt) != c.plan {
					t.Errorf("%s registered=%v, want %v", pt, has(names, pt), c.plan)
				}
			}
			if has(names, "response_execute") != c.execute {
				t.Errorf("response_execute registered=%v, want %v", has(names, "response_execute"), c.execute)
			}
		})
	}
}

func TestAnnotations(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Auto})
	res, _ := h.sess.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		a := tl.Annotations
		if a == nil {
			t.Errorf("%s has no annotations", tl.Name)
			continue
		}
		switch tl.Name {
		case "response_execute":
			if a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint {
				t.Errorf("response_execute must be marked destructive: %+v", a)
			}
		case "response_propose":
			if a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
				t.Errorf("response_propose must be non-destructive, not read-only: %+v", a)
			}
		default:
			if !a.ReadOnlyHint {
				t.Errorf("%s must be read-only", tl.Name)
			}
		}
	}
}

func TestAlertsSearchBuildsSafeQueryAndSanitizes(t *testing.T) {
	h := newHarness(t, policy.Config{})
	h.idx.result = &indexer.Result{Total: 1234, Hits: []indexer.Hit{{ID: "x1", Source: map[string]any{
		"rule":     map[string]any{"id": "5710", "level": 5},
		"full_log": "Failed password for \x1b[2Jroot " + strings.Repeat("A", 5000),
	}}}}
	out, res := h.call(t, "alerts_search", map[string]any{"window": "15m", "srcip": "203.0.113.9", "limit": 999})
	if res.IsError {
		t.Fatal(text(res))
	}
	if out["total_matching"].(float64) != 1234 {
		t.Errorf("out = %v", out)
	}
	if h.idx.lastBody["size"] != indexer.MaxLimit {
		t.Errorf("size = %v, want capped", h.idx.lastBody["size"])
	}
	log := out["alerts"].([]any)[0].(map[string]any)["alert"].(map[string]any)["full_log"].(string)
	if strings.ContainsRune(log, 0x1b) {
		t.Error("escape characters must be stripped")
	}
	if len(log) > maxFullLogLen+20 || !strings.HasSuffix(log, "[truncated]") {
		t.Errorf("full_log not clipped (len %d)", len(log))
	}
}

func TestAlertsSearchRejectsBadInputAsToolError(t *testing.T) {
	h := newHarness(t, policy.Config{})
	_, res := h.call(t, "alerts_search", map[string]any{"agent_id": `001" OR 1=1`})
	if !res.IsError {
		t.Fatal("injection attempt must come back as a tool error")
	}
	if h.idx.lastBody != nil {
		t.Error("the indexer must not be queried with invalid input")
	}
}

func TestAgentNamesAreCleaned(t *testing.T) {
	h := newHarness(t, policy.Config{})
	out, _ := h.call(t, "agents_list", nil)
	name := out["agents"].([]any)[0].(map[string]any)["name"].(string)
	if strings.ContainsRune(name, 0x1b) {
		t.Errorf("name %q still has an escape", name)
	}
}

func TestProposeAndExecuteFlowAuto(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Auto})
	out, res := h.call(t, "response_propose", map[string]any{
		"action": "block_ip", "agent_ids": []string{"001"}, "ip": "203.0.113.9", "ttl_seconds": 300,
		"reason": "ssh brute force", "source": "alert-1",
	})
	if res.IsError {
		t.Fatal(text(res))
	}
	if out["autonomy_level"] != "auto" || !strings.Contains(out["next_step"].(string), "response_execute") {
		t.Errorf("out = %v", out)
	}
	if h.exec.calls != 0 {
		t.Fatal("proposing must not touch Wazuh")
	}
	id := out["plan"].(map[string]any)["id"].(string)
	out, res = h.call(t, "response_execute", map[string]any{"plan_id": id})
	if res.IsError {
		t.Fatal(text(res))
	}
	if out["plan"].(map[string]any)["status"] != "executed" || h.exec.calls != 1 {
		t.Errorf("out = %v calls=%d", out, h.exec.calls)
	}
	blocks, _ := h.call(t, "blocks_list", nil)
	if len(blocks["blocks"].([]any)) != 1 {
		t.Errorf("blocks = %v", blocks)
	}
}

func TestApproveLevelBlocksAIUntilHumanApproves(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Approve})
	out, _ := h.call(t, "response_propose", map[string]any{
		"action": "scan_fim", "agent_ids": []string{"001"}, "reason": "check changes on web-1",
	})
	id := out["plan"].(map[string]any)["id"].(string)
	if !strings.Contains(out["next_step"].(string), "human approval") {
		t.Errorf("next_step = %v", out["next_step"])
	}
	_, res := h.call(t, "response_execute", map[string]any{"plan_id": id})
	if !res.IsError || h.exec.calls != 0 {
		t.Fatal("unapproved plan must not run")
	}
	if _, err := h.svc.Decide(response.ActorAdmin, id, true); err != nil {
		t.Fatal(err)
	}
	_, res = h.call(t, "response_execute", map[string]any{"plan_id": id})
	if res.IsError || h.exec.calls != 1 {
		t.Fatalf("approved plan must run: %s", text(res))
	}
}

func TestProposeAtProposeLevelCannotBeExecutedByAI(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Propose})
	out, _ := h.call(t, "response_propose", map[string]any{
		"action": "restart_agent", "agent_ids": []string{"001"}, "reason": "agent seems hung",
	})
	if !strings.Contains(out["next_step"].(string), "human must run") {
		t.Errorf("next_step = %v", out["next_step"])
	}
	if names := h.tools(t); has(names, "response_execute") {
		t.Error("no execute tool should exist at propose level")
	}
}

func TestProposeRefusesProtectedTargets(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Auto, ProtectedIPs: []string{"203.0.113.0/24"}})
	_, res := h.call(t, "response_propose", map[string]any{
		"action": "block_ip", "agent_ids": []string{"001"}, "ip": "203.0.113.9", "ttl_seconds": 300, "reason": "block it please",
	})
	if !res.IsError || !strings.Contains(text(res), "protected") {
		t.Errorf("want protected error, got %q", text(res))
	}
	_, res = h.call(t, "response_propose", map[string]any{
		"action": "restart_agent", "agent_ids": []string{"000"}, "reason": "restart the manager",
	})
	if !res.IsError {
		t.Error("the manager agent (000) must never be targeted")
	}
}

func TestAutonomyStatusReportsLevels(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Propose, Overrides: map[policy.Action]policy.Level{policy.ScanFIM: policy.Auto}})
	out, _ := h.call(t, "autonomy_status", nil)
	if ttls, _ := out["block_durations_seconds"].([]any); len(ttls) != 2 || ttls[0].(float64) != 300 {
		t.Errorf("autonomy_status must list the allowed block durations, got %v", out["block_durations_seconds"])
	}
	for _, a := range out["actions"].([]any) {
		if a.(map[string]any)["action"] == "unblock_ip" {
			t.Error("unblock_ip must not exist: Wazuh's API cannot lift a block early")
		}
	}
	levels := map[string]string{}
	for _, a := range out["actions"].([]any) {
		m := a.(map[string]any)
		levels[m["action"].(string)] = m["autonomy_level"].(string)
	}
	if levels["scan_fim"] != "auto" || levels["block_ip"] != "propose" {
		t.Errorf("levels = %v", levels)
	}
}

func TestMitigationOptionsForAlert(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Approve, ProtectedIPs: []string{"198.51.100.0/24"}})
	h.idx.result = &indexer.Result{Hits: []indexer.Hit{{ID: "a1", Source: map[string]any{
		"rule":  map[string]any{"id": "5712", "level": 10, "description": "sshd: brute force", "groups": []any{"syslog", "sshd"}},
		"agent": map[string]any{"id": "001"},
		"data":  map[string]any{"srcip": "203.0.113.9"},
	}}}}
	out, res := h.call(t, "mitigation_options", map[string]any{"alert_id": "a1"})
	if res.IsError {
		t.Fatal(text(res))
	}
	opts := out["options"].([]any)
	first := opts[0].(map[string]any)
	if first["kind"] != "action" || first["action"] != "block_ip" || first["allowed"] != true || first["autonomy_level"] != "approve" {
		t.Errorf("first option = %v", first)
	}
	if ttl := first["params"].(map[string]any)["ttl_seconds"].(float64); ttl != 3600 {
		t.Errorf("suggested ttl = %v, want an allowed duration (3600)", ttl)
	}

	// Protected source: the option is shown but marked not allowed, with the reason.
	h.idx.result.Hits[0].Source["data"] = map[string]any{"srcip": "198.51.100.7"}
	out, _ = h.call(t, "mitigation_options", map[string]any{"alert_id": "a1"})
	first = out["options"].([]any)[0].(map[string]any)
	if first["allowed"] == true || !strings.Contains(first["note"].(string), "protected") {
		t.Errorf("protected source must not be allowed: %v", first)
	}
}

func TestMitigationOptionsForCVEIsManualAdvice(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.Auto})
	h.idx.result = &indexer.Result{Total: 2, Hits: []indexer.Hit{
		{Source: map[string]any{"agent": map[string]any{"id": "001", "name": "web-1"}, "package": map[string]any{"name": "openssl", "version": "3.0.2"}, "vulnerability": map[string]any{"severity": "Critical"}}},
		{Source: map[string]any{"agent": map[string]any{"id": "002", "name": "db-1"}, "package": map[string]any{"name": "openssl", "version": "3.0.2"}}},
	}}
	out, res := h.call(t, "mitigation_options", map[string]any{"cve": "CVE-2024-12345"})
	if res.IsError {
		t.Fatal(text(res))
	}
	for _, o := range out["options"].([]any) {
		if o.(map[string]any)["kind"] != "manual" {
			t.Errorf("CVE advice must not offer automated actions: %v", o)
		}
	}
	if !strings.Contains(out["summary"].(string), "2 agent") {
		t.Errorf("summary = %v", out["summary"])
	}
}

func TestMitigationOptionsNeedsExactlyOneSource(t *testing.T) {
	h := newHarness(t, policy.Config{})
	for _, args := range []map[string]any{{}, {"alert_id": "a", "cve": "CVE-2024-12345"}} {
		if _, res := h.call(t, "mitigation_options", args); !res.IsError {
			t.Errorf("args %v should fail", args)
		}
	}
}

func TestHealth(t *testing.T) {
	h := newHarness(t, policy.Config{})
	out, res := h.call(t, "health", nil)
	if res.IsError || out["indexer_ok"] != true || out["manager"].(map[string]any)["version"] != "v4.14.9" {
		t.Errorf("out = %v", out)
	}
}

func TestSanitizeAndClip(t *testing.T) {
	if got := cleanText("a\x00b\x1b[0mc\td\n"); got != "ab[0mc\td\n" {
		t.Errorf("cleanText = %q", got)
	}
	s := strings.Repeat("é", 400) // 2 bytes per rune
	c := clip(s, 601)
	if !strings.HasSuffix(c, "[truncated]") {
		t.Fatal("not clipped")
	}
	for _, r := range c {
		if r == '�' {
			t.Fatal("clip split a multi-byte character")
		}
	}
	nested := sanitize(map[string]any{"a": []any{"x\x1b", map[string]any{"b": "y\x07"}}, "n": 5}).(map[string]any)
	if nested["a"].([]any)[0] != "x" || nested["n"] != 5 {
		t.Errorf("nested = %v", nested)
	}
}
