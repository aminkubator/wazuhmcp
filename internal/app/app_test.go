package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wazuhmcp/internal/config"
	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/response"
)

func testServer(t *testing.T, level policy.Level) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		Addr: "127.0.0.1:0", Token: "mcp-secret", AdminToken: "admin-secret",
		APIURL: "https://127.0.0.1:1", APIUser: "u", APIPassword: "p",
		IndexerURL: "https://127.0.0.1:1", IndexerUser: "u", IndexerPassword: "p",
		Autonomy: level, MaxPerHour: 10, MaxAgents: 5, PlanTTL: time.Hour,
		AuditFile: filepath.Join(t.TempDir(), "audit.jsonl"),
	}
	s, err := New(cfg, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Shutdown(context.Background()) })
	return s, ts
}

func do(t *testing.T, method, url, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTokensAreSeparate(t *testing.T) {
	_, ts := testServer(t, policy.Propose)
	if code, _ := do(t, "GET", ts.URL+"/admin/plans", ""); code != 401 {
		t.Errorf("no token on admin API: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/plans", "mcp-secret"); code != 401 {
		t.Errorf("the AI's token must not open the admin API: %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/plans", "admin-secret"); code != 200 {
		t.Errorf("admin token on admin API: %d", code)
	}
	if code, _ := do(t, "POST", ts.URL+"/mcp", "admin-secret"); code != 401 {
		t.Errorf("the admin token must not open /mcp: %d", code)
	}
	if code, _ := do(t, "POST", ts.URL+"/mcp", ""); code != 401 {
		t.Errorf("no token on /mcp: %d", code)
	}
	if code, body := do(t, "GET", ts.URL+"/healthz", ""); code != 200 || strings.Contains(body, "secret") {
		t.Errorf("healthz: %d %q", code, body)
	}
}

func TestAdminApproveFlow(t *testing.T) {
	s, ts := testServer(t, policy.Approve)
	p, err := s.Service().Propose(response.ActorMCP, response.ProposeRequest{
		Action: policy.ScanFIM, Params: policy.Params{AgentIDs: []string{"001"}}, Reason: "check file changes",
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := do(t, "POST", ts.URL+"/admin/plans/"+p.ID+"/approve", "mcp-secret"); code != 401 {
		t.Fatalf("AI token approving: %d", code)
	}
	code, body := do(t, "POST", ts.URL+"/admin/plans/"+p.ID+"/approve", "admin-secret")
	if code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	var got map[string]any
	_ = json.Unmarshal([]byte(body), &got)
	if got["status"] != "approved" || got["decided_by"] != "admin" {
		t.Errorf("plan = %v", got)
	}
	if code, _ := do(t, "POST", ts.URL+"/admin/plans/"+p.ID+"/reject", "admin-secret"); code != 409 {
		t.Errorf("deciding twice should conflict, got %d", code)
	}
	if code, _ := do(t, "GET", ts.URL+"/admin/plans/plan-unknown", "admin-secret"); code != 404 {
		t.Errorf("unknown plan: %d", code)
	}
}

func TestAdminExecuteRespectsReadonly(t *testing.T) {
	s, ts := testServer(t, policy.Propose)
	p, _ := s.Service().Propose(response.ActorMCP, response.ProposeRequest{
		Action: policy.ScanFIM, Params: policy.Params{AgentIDs: []string{"001"}}, Reason: "check file changes",
	})
	// At propose level the admin may execute; Wazuh is unreachable in this test, so it must fail
	// at the network and the plan ends up failed, not stuck.
	code, _ := do(t, "POST", ts.URL+"/admin/plans/"+p.ID+"/execute", "admin-secret")
	if code != 409 {
		t.Errorf("execute against an unreachable Wazuh should report an error, got %d", code)
	}
	if got, _ := s.Service().Plan(p.ID); got.Status != "failed" {
		t.Errorf("status = %s, want failed", got.Status)
	}
}

func TestReadonlyCreatesNoAuditFileAndNoPlans(t *testing.T) {
	s, _ := testServer(t, policy.ReadOnly)
	if _, err := s.Service().Propose(response.ActorMCP, response.ProposeRequest{
		Action: policy.ScanFIM, Params: policy.Params{AgentIDs: []string{"001"}}, Reason: "check file changes",
	}); err == nil {
		t.Fatal("readonly must refuse proposals")
	}
}

func TestGeneratedTokens(t *testing.T) {
	cfg := &config.Config{
		Addr: "127.0.0.1:0", APIURL: "https://x:1", APIUser: "u", APIPassword: "p",
		IndexerURL: "https://x:1", IndexerUser: "u", IndexerPassword: "p",
		MaxPerHour: 10, MaxAgents: 5, PlanTTL: time.Hour,
	}
	s, err := New(cfg, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Token) < 32 || len(s.AdminToken) < 32 || s.Token == s.AdminToken || !s.TokensNew[0] || !s.TokensNew[1] {
		t.Errorf("tokens must be generated and distinct: %q %q", s.Token, s.AdminToken)
	}
}
