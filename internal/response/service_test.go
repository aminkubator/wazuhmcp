package response

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wazuhmcp/internal/audit"
	"wazuhmcp/internal/plans"
	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/wazuh/api"
)

type fakeExec struct {
	mu     sync.Mutex
	calls  []string
	fail   error
	empty  bool             // answer 200 but accept no agent
	failed []map[string]any // failed_items returned together with empty
}

func (f *fakeExec) record(s string, ids []string) (api.ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
	if f.fail != nil {
		return api.ExecResult{}, f.fail
	}
	if f.empty {
		return api.ExecResult{Failed: f.failed, Message: "AR command was not sent to any agent"}, nil
	}
	return api.ExecResult{OK: ids}, nil
}
func (f *fakeExec) ActiveResponse(_ context.Context, ids []string, cmd string, args []string, alert map[string]any) (api.ExecResult, error) {
	ip, _ := alert["data"].(map[string]any)["srcip"].(string)
	return f.record("ar:"+cmd+":"+strings.Join(args, ",")+":"+ip, ids)
}
func (f *fakeExec) RestartAgents(_ context.Context, ids []string) (api.ExecResult, error) {
	return f.record("restart", ids)
}
func (f *fakeExec) RunSyscheck(_ context.Context, ids []string) (api.ExecResult, error) {
	return f.record("syscheck", ids)
}
func (f *fakeExec) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func setup(t *testing.T, cfg policy.Config) (*Service, *fakeExec, string) {
	t.Helper()
	if cfg.AllowedTTLs == nil {
		cfg.AllowedTTLs = DefaultCommands().TTLs()
	}
	pol, err := policy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	aud, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })
	ex := &fakeExec{}
	return New(pol, plans.NewStore(time.Hour), aud, ex, DefaultCommands(), nil), ex, path
}

var block = ProposeRequest{
	Action: policy.BlockIP,
	Params: policy.Params{AgentIDs: []string{"001"}, IP: "203.0.113.9", TTLSeconds: 3600},
	Reason: "ssh brute force from this address",
}

func TestProposeRequiresEnabledActionAndReason(t *testing.T) {
	svc, _, _ := setup(t, policy.Config{Default: policy.ReadOnly})
	if _, err := svc.Propose(ActorMCP, block); !errors.Is(err, ErrDisabled) {
		t.Fatalf("readonly must refuse proposals, got %v", err)
	}
	svc, _, _ = setup(t, policy.Config{Default: policy.Propose})
	r := block
	r.Reason = "x"
	if _, err := svc.Propose(ActorMCP, r); err == nil {
		t.Error("short reason must be refused")
	}
	bad := block
	bad.Params.IP = "10.0.0.1; reboot"
	if _, err := svc.Propose(ActorMCP, bad); err == nil {
		t.Error("invalid params must be refused at proposal time")
	}
}

func TestAutonomyMatrix(t *testing.T) {
	type want struct{ mcpOK, adminOK bool }
	// For each level: can the AI execute a freshly proposed plan, and can the
	// AI execute after the admin approved it, and can the admin execute?
	cases := []struct {
		level        policy.Level
		mcpFresh     bool
		mcpApproved  bool
		adminExecute bool
	}{
		{policy.Propose, false, false, true},
		{policy.Approve, false, true, true},
		{policy.Auto, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.level.String(), func(t *testing.T) {
			// fresh plan, AI executes
			svc, ex, _ := setup(t, policy.Config{Default: c.level})
			p, err := svc.Propose(ActorMCP, block)
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.Execute(context.Background(), ActorMCP, p.ID)
			if (err == nil) != c.mcpFresh {
				t.Errorf("AI execute of fresh plan: err=%v, want ok=%v", err, c.mcpFresh)
			}
			if !c.mcpFresh && ex.count() != 0 {
				t.Error("nothing may reach Wazuh when refused")
			}

			// approved plan, AI executes
			svc, _, _ = setup(t, policy.Config{Default: c.level})
			p, _ = svc.Propose(ActorMCP, block)
			if _, err := svc.Decide(ActorAdmin, p.ID, true); err != nil {
				t.Fatal(err)
			}
			_, err = svc.Execute(context.Background(), ActorMCP, p.ID)
			if (err == nil) != c.mcpApproved {
				t.Errorf("AI execute of approved plan: err=%v, want ok=%v", err, c.mcpApproved)
			}

			// admin executes directly
			svc, _, _ = setup(t, policy.Config{Default: c.level})
			p, _ = svc.Propose(ActorMCP, block)
			_, err = svc.Execute(context.Background(), ActorAdmin, p.ID)
			if (err == nil) != c.adminExecute {
				t.Errorf("admin execute: err=%v, want ok=%v", err, c.adminExecute)
			}
		})
	}
}

func TestAIExecuteDeniedErrorsAreTyped(t *testing.T) {
	svc, _, _ := setup(t, policy.Config{Default: policy.Propose})
	p, _ := svc.Propose(ActorMCP, block)
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); !errors.Is(err, ErrDisabledForAI) {
		t.Fatalf("got %v, want ErrDisabledForAI", err)
	}
}

func TestPerActionOverride(t *testing.T) {
	svc, ex, _ := setup(t, policy.Config{
		Default:   policy.Propose,
		Overrides: map[policy.Action]policy.Level{policy.ScanFIM: policy.Auto},
	})
	scan, err := svc.Propose(ActorMCP, ProposeRequest{Action: policy.ScanFIM, Params: policy.Params{AgentIDs: []string{"001"}}, Reason: "check file changes"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Execute(context.Background(), ActorMCP, scan.ID); err != nil {
		t.Fatalf("scan_fim is auto: %v", err)
	}
	blockPlan, _ := svc.Propose(ActorMCP, block)
	if _, err := svc.Execute(context.Background(), ActorMCP, blockPlan.ID); err == nil {
		t.Fatal("block_ip stays at propose")
	}
	if ex.count() != 1 {
		t.Fatalf("exactly the scan must have run, calls=%v", ex.calls)
	}
}

func TestOnlyAdminDecides(t *testing.T) {
	svc, _, _ := setup(t, policy.Config{Default: policy.Approve})
	p, _ := svc.Propose(ActorMCP, block)
	if _, err := svc.Decide(ActorMCP, p.ID, true); err == nil {
		t.Fatal("the AI must never approve its own plan")
	}
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err == nil {
		t.Fatal("unapproved plan must not run at level approve")
	}
	if _, err := svc.Decide(ActorAdmin, p.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err == nil {
		t.Fatal("rejected plan must not run")
	}
}

func TestPlanRunsOnlyOnce(t *testing.T) {
	svc, ex, _ := setup(t, policy.Config{Default: policy.Auto})
	p, _ := svc.Propose(ActorMCP, block)
	var wg sync.WaitGroup
	var okCount int
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if okCount != 1 || ex.count() != 1 {
		t.Fatalf("plan ran %d times (calls=%d), want exactly once", okCount, ex.count())
	}
}

func TestGuardrailsApplyAtEveryLevel(t *testing.T) {
	svc, ex, _ := setup(t, policy.Config{Default: policy.Auto, MaxPerHour: 1, ProtectedIPs: []string{"203.0.113.0/24"}})
	// Protected IPs are refused already at proposal time.
	if _, err := svc.Propose(ActorMCP, block); err == nil {
		t.Fatal("protected ip must be refused")
	}
	// Rate limit: second execution within the hour is refused even for the admin.
	svc, ex, _ = setup(t, policy.Config{Default: policy.Auto, MaxPerHour: 1})
	a, _ := svc.Propose(ActorMCP, block)
	b, _ := svc.Propose(ActorMCP, block)
	if _, err := svc.Execute(context.Background(), ActorMCP, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Execute(context.Background(), ActorAdmin, b.ID); err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("want rate limit error, got %v", err)
	}
	if ex.count() != 1 {
		t.Fatalf("calls=%v", ex.calls)
	}
	// A refused (rate limited) plan is not burned: it stays usable later.
	if got, _ := svc.Plan(b.ID); got.Status != plans.Pending {
		t.Fatalf("status = %s, want pending", got.Status)
	}
}

func TestExecuteFailureAndEmptyResult(t *testing.T) {
	svc, ex, _ := setup(t, policy.Config{Default: policy.Auto})
	ex.fail = errors.New("boom")
	p, _ := svc.Propose(ActorMCP, block)
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err == nil {
		t.Fatal("expected error")
	}
	if got, _ := svc.Plan(p.ID); got.Status != plans.Failed {
		t.Fatalf("status = %s, want failed", got.Status)
	}
	if len(svc.ActiveBlocks()) != 0 {
		t.Fatal("a failed block must not be tracked")
	}

	svc, ex, _ = setup(t, policy.Config{Default: policy.Auto})
	ex.empty = true
	p, _ = svc.Propose(ActorMCP, block)
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err == nil {
		t.Fatal("a 200 with no agent applied must be reported as failure")
	}
}

func TestBlockUsesCommandForItsDuration(t *testing.T) {
	svc, ex, _ := setup(t, policy.Config{Default: policy.Auto})
	for ttl, want := range map[int]string{300: "ar:firewall-drop300::203.0.113.9", 3600: "ar:firewall-drop3600::203.0.113.9"} {
		r := block
		r.Params.TTLSeconds = ttl
		p, err := svc.Propose(ActorMCP, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err != nil {
			t.Fatal(err)
		}
		if got := ex.calls[len(ex.calls)-1]; got != want {
			t.Errorf("ttl %d: call = %q, want %q", ttl, got, want)
		}
	}
	// A duration without a configured command is refused at proposal time.
	r := block
	r.Params.TTLSeconds = 600
	if _, err := svc.Propose(ActorMCP, r); err == nil || !strings.Contains(err.Error(), "ttl_seconds must be one of") {
		t.Fatalf("got %v", err)
	}
	if len(svc.ActiveBlocks()) != 2 {
		t.Fatalf("blocks = %v", svc.ActiveBlocks())
	}
}

func TestReapOnlyForgetsAndNeverCallsWazuh(t *testing.T) {
	svc, ex, path := setup(t, policy.Config{Default: policy.Auto})
	p, _ := svc.Propose(ActorMCP, block)
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err != nil {
		t.Fatal(err)
	}
	svc.Reap(context.Background())
	if len(svc.ActiveBlocks()) != 1 {
		t.Fatal("not expired yet")
	}
	svc.mu.Lock()
	svc.blocks[0].Expires = time.Now().Add(-time.Second)
	svc.mu.Unlock()
	before := ex.count()
	svc.Reap(context.Background())
	if len(svc.ActiveBlocks()) != 0 {
		t.Fatal("expired block must be forgotten")
	}
	if ex.count() != before {
		t.Fatal("Wazuh lifts the block itself: nothing may be sent on expiry")
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), `"event":"expire"`) {
		t.Error("expiry must be audited")
	}
}

func TestWazuhFailureReasonIsReported(t *testing.T) {
	svc, ex, _ := setup(t, policy.Config{Default: policy.Auto})
	ex.empty = true
	ex.failed = []map[string]any{{"id": []any{"001"}, "error": map[string]any{
		"code": float64(1652), "message": "The command used is not defined in the configuration."}}}
	p, _ := svc.Propose(ActorMCP, block)
	_, err := svc.Execute(context.Background(), ActorMCP, p.ID)
	if err == nil || !strings.Contains(err.Error(), "not defined in the configuration") || !strings.Contains(err.Error(), "1652") {
		t.Fatalf("the reason from Wazuh must reach the caller, got: %v", err)
	}
}

func TestAuditTrail(t *testing.T) {
	svc, _, path := setup(t, policy.Config{Default: policy.Approve})
	p, _ := svc.Propose(ActorMCP, block)
	svc.Decide(ActorAdmin, p.ID, true)
	svc.Execute(context.Background(), ActorMCP, p.ID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	for _, ev := range []string{`"event":"propose"`, `"event":"approve"`, `"event":"execute_start"`, `"event":"execute"`, `"actor":"admin"`, `"level":"approve"`} {
		if !strings.Contains(log, ev) {
			t.Errorf("audit log misses %s:\n%s", ev, log)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("audit file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestNoAuditNoAction(t *testing.T) {
	pol, _ := policy.New(policy.Config{Default: policy.Auto})
	aud, err := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ex := &fakeExec{}
	svc := New(pol, plans.NewStore(time.Hour), aud, ex, DefaultCommands(), nil)
	p, err := svc.Propose(ActorMCP, block)
	if err != nil {
		t.Fatal(err)
	}
	aud.Close() // audit becomes unwritable
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); err == nil {
		t.Fatal("must refuse to act when the audit log cannot be written")
	}
	if ex.count() != 0 {
		t.Fatal("nothing may reach Wazuh without an audit record")
	}
}

func TestExpiredPlanCannotRun(t *testing.T) {
	pol, _ := policy.New(policy.Config{Default: policy.Auto})
	ex := &fakeExec{}
	svc := New(pol, plans.NewStore(time.Millisecond), nil, ex, DefaultCommands(), nil)
	p, _ := svc.Propose(ActorMCP, block)
	time.Sleep(10 * time.Millisecond)
	if _, err := svc.Execute(context.Background(), ActorMCP, p.ID); !errors.Is(err, plans.ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
	if ex.count() != 0 {
		t.Fatal("expired plan must not run")
	}
}
