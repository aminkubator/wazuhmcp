// Package response is the only place where response actions are proposed,
// approved and executed. The MCP tools and the admin REST API are thin
// wrappers around Service, so the autonomy rules and guardrails cannot be
// bypassed by taking another entry point.
package response

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"wazuhmcp/internal/audit"
	"wazuhmcp/internal/plans"
	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/wazuh/api"
)

// Actor says who is calling.
type Actor string

const (
	ActorMCP    Actor = "mcp"    // the AI client
	ActorAdmin  Actor = "admin"  // a human using the admin REST API / UI
	ActorSystem Actor = "system" // background jobs (TTL expiry)
)

// Executor is the part of the Wazuh API client used for write actions.
// *api.Client implements it; tests use a fake.
type Executor interface {
	ActiveResponse(ctx context.Context, agentIDs []string, command string, args []string, alert map[string]any) (api.ExecResult, error)
	RestartAgents(ctx context.Context, agentIDs []string) (api.ExecResult, error)
	RunSyscheck(ctx context.Context, agentIDs []string) (api.ExecResult, error)
}

// Commands maps a block duration (seconds) to the Wazuh active-response
// command that blocks for that long.
//
// Wazuh's API can only run commands listed in the manager's ar.conf, which it
// builds from <active-response> blocks as "<command><timeout>" (for example
// firewall-drop3600 for a block with <timeout>3600</timeout>). Wazuh itself
// lifts the block when the timeout ends; the API has no way to unblock early.
type Commands struct {
	Block map[int]string
}

// DefaultCommands matches the lab setup: two active-response blocks for
// firewall-drop with timeouts of 5 minutes and 1 hour.
func DefaultCommands() Commands {
	return Commands{Block: map[int]string{300: "firewall-drop300", 3600: "firewall-drop3600"}}
}

// TTLs returns the configured block durations.
func (c Commands) TTLs() []int {
	out := make([]int, 0, len(c.Block))
	for t := range c.Block {
		out = append(out, t)
	}
	return out
}

// Errors callers can match.
var (
	ErrDisabledForAI = errors.New("execution is not enabled for the AI for this action at the current autonomy level")
	ErrDisabled      = errors.New("this action is disabled (autonomy level readonly)")
	errNoBlockCmd    = errors.New("no active-response command is configured for this block duration")
)

// Service ties policy, plans, audit and the executor together.
type Service struct {
	pol   *policy.Policy
	store *plans.Store
	aud   *audit.Logger
	exec  Executor
	cmds  Commands
	log   *slog.Logger

	mu     sync.Mutex
	blocks []*activeBlock
}

type activeBlock struct {
	PlanID   string
	IP       string
	AgentIDs []string
	Expires  time.Time
}

// New builds a Service. aud may be nil (no audit file), but production use
// should always pass one.
func New(pol *policy.Policy, store *plans.Store, aud *audit.Logger, exec Executor, cmds Commands, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if len(cmds.Block) == 0 {
		cmds = DefaultCommands()
	}
	return &Service{pol: pol, store: store, aud: aud, exec: exec, cmds: cmds, log: log}
}

// Policy returns the policy, for read-only introspection.
func (s *Service) Policy() *policy.Policy { return s.pol }

// Plan returns one plan.
func (s *Service) Plan(id string) (plans.Plan, error) { return s.store.Get(id) }

// Plans lists plans newest first, optionally filtered by status.
func (s *Service) Plans(status plans.Status) []plans.Plan { return s.store.List(status) }

// ProposeRequest is the input of Propose.
type ProposeRequest struct {
	Action policy.Action
	Params policy.Params
	Reason string
	Source string
}

// Propose validates a request and stores it as a pending plan. It never
// touches Wazuh.
func (s *Service) Propose(actor Actor, r ProposeRequest) (plans.Plan, error) {
	info, ok := policy.Info(r.Action)
	if !ok {
		return plans.Plan{}, fmt.Errorf("unknown action %q", r.Action)
	}
	level := s.pol.LevelFor(r.Action)
	if level == policy.ReadOnly {
		return plans.Plan{}, ErrDisabled
	}
	reason := strings.TrimSpace(r.Reason)
	if len(reason) < 5 || len(reason) > 500 {
		return plans.Plan{}, errors.New("reason is required (5-500 characters): say why this action is needed")
	}
	if err := s.pol.Validate(r.Action, r.Params); err != nil {
		_ = s.audit(actor, "propose", "", r.Action, level, r.Params, false, err.Error())
		return plans.Plan{}, err
	}
	r.Params.IP = strings.TrimSpace(r.Params.IP)
	plan, err := s.store.Create(plans.Plan{
		Action: r.Action, Params: r.Params, Reason: reason, Source: r.Source,
		Risk: info.Risk, CreatedBy: string(actor),
	})
	if err != nil {
		return plans.Plan{}, err
	}
	if err := s.audit(actor, "propose", plan.ID, r.Action, level, r.Params, true, reason); err != nil {
		return plans.Plan{}, fmt.Errorf("audit log unavailable, plan not created: %w", err)
	}
	return plan, nil
}

// Decide approves or rejects a pending plan. Only the admin actor may.
func (s *Service) Decide(actor Actor, id string, approve bool) (plans.Plan, error) {
	if actor != ActorAdmin {
		return plans.Plan{}, errors.New("only a human admin can approve or reject plans")
	}
	p, err := s.store.Decide(id, string(actor), approve)
	event := "reject"
	if approve {
		event = "approve"
	}
	_ = s.audit(actor, event, id, p.Action, s.pol.LevelFor(p.Action), p.Params, err == nil, errString(err))
	return p, err
}

// Execute runs a plan if the autonomy level and guardrails allow it for this
// actor. A plan runs at most once.
func (s *Service) Execute(ctx context.Context, actor Actor, id string) (plans.Plan, error) {
	plan, err := s.store.Get(id)
	if err != nil {
		return plans.Plan{}, err
	}
	level := s.pol.LevelFor(plan.Action)

	needApproved := false
	switch {
	case level == policy.ReadOnly:
		return plan, ErrDisabled
	case actor == ActorMCP && level == policy.Propose:
		_ = s.audit(actor, "execute", id, plan.Action, level, plan.Params, false, "denied by autonomy level")
		return plan, ErrDisabledForAI
	case actor == ActorMCP && level == policy.Approve:
		needApproved = true
	case actor != ActorMCP && actor != ActorAdmin:
		return plan, errors.New("unsupported actor")
	}

	// Guardrails apply to everyone, every time.
	if err := s.pol.Validate(plan.Action, plan.Params); err != nil {
		_ = s.audit(actor, "execute", id, plan.Action, level, plan.Params, false, err.Error())
		return plan, err
	}
	if err := s.pol.Allow(plan.Action); err != nil {
		_ = s.audit(actor, "execute", id, plan.Action, level, plan.Params, false, err.Error())
		return plan, err
	}
	claimed, err := s.store.Claim(id, needApproved)
	if err != nil {
		s.pol.Refund(plan.Action)
		_ = s.audit(actor, "execute", id, plan.Action, level, plan.Params, false, err.Error())
		return claimed, err
	}
	// Write intent to the audit log before acting: no audit, no action.
	if err := s.audit(actor, "execute_start", id, plan.Action, level, plan.Params, true, ""); err != nil {
		s.pol.Refund(plan.Action)
		s.store.Finish(id, err, "")
		return claimed, fmt.Errorf("audit log unavailable, action not executed: %w", err)
	}

	res, execErr := s.run(ctx, plan)
	msg := summarize(res)
	s.store.Finish(id, execErr, msg)
	if execErr == nil && len(res.OK) == 0 {
		// Wazuh answered 200 but no agent accepted the command.
		execErr = fmt.Errorf("wazuh did not apply the action to any agent: %s", msg)
		s.store.Finish(id, execErr, msg)
	}
	if execErr == nil {
		s.trackBlock(plan)
	}
	_ = s.audit(actor, "execute", id, plan.Action, level, plan.Params, execErr == nil, firstNonEmpty(errString(execErr), msg))
	out, _ := s.store.Get(id)
	return out, execErr
}

func (s *Service) run(ctx context.Context, p plans.Plan) (api.ExecResult, error) {
	ids := p.Params.AgentIDs
	switch p.Action {
	case policy.BlockIP:
		cmd, ok := s.cmds.Block[p.Params.TTLSeconds]
		if !ok {
			return api.ExecResult{}, errNoBlockCmd
		}
		return s.exec.ActiveResponse(ctx, ids, cmd, nil, srcAlert(p.Params.IP))
	case policy.RestartAgent:
		return s.exec.RestartAgents(ctx, ids)
	case policy.ScanFIM:
		return s.exec.RunSyscheck(ctx, ids)
	}
	return api.ExecResult{}, fmt.Errorf("unsupported action %q", p.Action)
}

func srcAlert(ip string) map[string]any {
	return map[string]any{"data": map[string]any{"srcip": ip}}
}

// ---------------------------------------------------------------------------
// Block tracking and TTL expiry
// ---------------------------------------------------------------------------

func (s *Service) trackBlock(p plans.Plan) {
	if p.Action != policy.BlockIP {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocks = append(s.blocks, &activeBlock{
		PlanID: p.ID, IP: p.Params.IP, AgentIDs: p.Params.AgentIDs,
		Expires: time.Now().Add(time.Duration(p.Params.TTLSeconds) * time.Second),
	})
}

// BlockInfo is a block this server set that is expected to still be active.
type BlockInfo struct {
	PlanID   string    `json:"plan_id"`
	IP       string    `json:"ip"`
	AgentIDs []string  `json:"agent_ids"`
	Expires  time.Time `json:"expires"`
}

// ActiveBlocks lists blocks set by this server whose timeout has not passed.
// It is a record of what we asked for; Wazuh enforces and lifts the blocks.
func (s *Service) ActiveBlocks() []BlockInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BlockInfo, 0, len(s.blocks))
	for _, b := range s.blocks {
		out = append(out, BlockInfo{b.PlanID, b.IP, b.AgentIDs, b.Expires})
	}
	return out
}

// Reap forgets blocks whose timeout passed and audits it. It sends nothing to
// Wazuh: the manager's active-response timeout removes the rule on the agent.
func (s *Service) Reap(_ context.Context) {
	s.mu.Lock()
	var gone []*activeBlock
	kept := s.blocks[:0]
	for _, b := range s.blocks {
		if time.Now().After(b.Expires) {
			gone = append(gone, b)
		} else {
			kept = append(kept, b)
		}
	}
	s.blocks = kept
	s.mu.Unlock()

	for _, b := range gone {
		_ = s.audit(ActorSystem, "expire", b.PlanID, policy.BlockIP, s.pol.LevelFor(policy.BlockIP),
			policy.Params{AgentIDs: b.AgentIDs, IP: b.IP}, true, "timeout reached; Wazuh removes the block by itself")
	}
}

// ---------------------------------------------------------------------------

func (s *Service) audit(a Actor, event, planID string, act policy.Action, lvl policy.Level, params any, ok bool, msg string) error {
	return s.aud.Log(audit.Entry{
		Actor: string(a), Event: event, PlanID: planID, Action: string(act),
		Level: lvl.String(), Params: params, OK: ok, Message: msg,
	})
}

func summarize(r api.ExecResult) string {
	msg := fmt.Sprintf("applied to %d agent(s)", len(r.OK))
	if len(r.Failed) > 0 {
		msg += fmt.Sprintf(", failed on %d", len(r.Failed))
	}
	if r.Message != "" {
		msg += ": " + r.Message
	}
	if reasons := r.Reasons(); len(reasons) > 0 {
		msg += " [" + strings.Join(reasons, "; ") + "]"
	}
	return msg
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
