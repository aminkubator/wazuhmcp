package mcpserver

// Mitigation tools: advice (always on), plans and execution (gated by the
// autonomy level, see server.go).

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wazuhmcp/internal/plans"
	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/response"
	"wazuhmcp/internal/wazuh/indexer"
)

func errField(name string) error { return fmt.Errorf("%s is required", name) }
func errNotFound(kind, id string) error {
	return fmt.Errorf("%s %q not found", kind, id)
}

// ---------------------------------------------------------------------------
// autonomy_status
// ---------------------------------------------------------------------------

type autonomyArgs struct{}

type actionStatus struct {
	policy.ActionInfo
	Level string `json:"autonomy_level"`
	Can   string `json:"what_you_can_do"`
}

type autonomyOut struct {
	DefaultLevel string         `json:"default_level"`
	Actions      []actionStatus `json:"actions"`
	ActiveBlocks int            `json:"active_blocks"`
	BlockTTLs    []int          `json:"block_durations_seconds,omitempty"`
	Notes        []string       `json:"notes"`
}

func describeLevel(l policy.Level) string {
	switch l {
	case policy.ReadOnly:
		return "nothing: this action is disabled"
	case policy.Propose:
		return "create a plan with response_propose; a human must execute it"
	case policy.Approve:
		return "create a plan; after a human approves it, run it with response_execute"
	case policy.Auto:
		return "create a plan and run it yourself with response_execute (guardrails still apply)"
	}
	return ""
}

func addAutonomyTool(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "autonomy_status",
		Description: "Show what you are allowed to do for each response action (disabled, propose only, needs human approval, or automatic). Call this before proposing any action.",
		Annotations: readOnly(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ autonomyArgs) (*mcp.CallToolResult, autonomyOut, error) {
		pol := d.Response.Policy()
		out := autonomyOut{DefaultLevel: pol.Default().String()}
		for _, info := range policy.Actions() {
			l := pol.LevelFor(info.Action)
			out.Actions = append(out.Actions, actionStatus{ActionInfo: info, Level: l.String(), Can: describeLevel(l)})
		}
		out.ActiveBlocks = len(d.Response.ActiveBlocks())
		out.BlockTTLs = pol.AllowedTTLs()
		out.Notes = []string{
			"Protected IPs and agents, per-hour rate limits and parameter limits apply at every level and cannot be changed from here.",
			"Every proposal and execution is written to an audit log.",
		}
		return nil, out, nil
	})
}

// ---------------------------------------------------------------------------
// mitigation_options
// ---------------------------------------------------------------------------

type mitigationArgs struct {
	AlertID string `json:"alert_id,omitempty" jsonschema:"alert id from alerts_search; gives options based on that attack"`
	CVE     string `json:"cve,omitempty" jsonschema:"CVE id such as CVE-2024-12345; gives options based on affected agents"`
}

type option struct {
	Kind        string         `json:"kind"` // "action" runs through response_propose, "manual" is advice for a human
	Action      policy.Action  `json:"action,omitempty"`
	Params      *policy.Params `json:"params,omitempty"`
	Description string         `json:"description"`
	Allowed     bool           `json:"allowed"`
	Level       string         `json:"autonomy_level,omitempty"`
	Note        string         `json:"note,omitempty"`
}

type mitigationOut struct {
	Source  string   `json:"source"`
	Summary string   `json:"summary"`
	Options []option `json:"options"`
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

func strList(m map[string]any, key string) []string {
	var out []string
	if l, ok := m[key].([]any); ok {
		for _, v := range l {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func addMitigationTools(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "mitigation_options",
		Description: "Suggest ways to mitigate an alert or a CVE. Options of kind \"action\" come with ready parameters for response_propose and say whether policy would allow them; options of kind \"manual\" are advice for a human (for example patching). Read-only: nothing is changed.",
		Annotations: readOnly(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a mitigationArgs) (*mcp.CallToolResult, mitigationOut, error) {
		switch {
		case a.AlertID != "" && a.CVE != "":
			return nil, mitigationOut{}, errors.New("give either alert_id or cve, not both")
		case a.AlertID != "":
			return alertOptions(ctx, d, a.AlertID)
		case a.CVE != "":
			return cveOptions(ctx, d, a.CVE)
		}
		return nil, mitigationOut{}, errors.New("alert_id or cve is required")
	})
}

func actionOption(d Deps, act policy.Action, p policy.Params, desc string) option {
	pol := d.Response.Policy()
	o := option{Kind: "action", Action: act, Params: &p, Description: desc, Level: pol.LevelFor(act).String()}
	if pol.LevelFor(act) == policy.ReadOnly {
		o.Note = "disabled by the autonomy configuration"
		return o
	}
	if err := pol.Validate(act, p); err != nil {
		o.Note = "policy would refuse this: " + err.Error()
		return o
	}
	o.Allowed = true
	return o
}

func alertOptions(ctx context.Context, d Deps, id string) (*mcp.CallToolResult, mitigationOut, error) {
	q, err := indexer.AlertByIDQuery(id)
	if err != nil {
		return nil, mitigationOut{}, err
	}
	res, err := d.Indexer.Search(ctx, indexer.AlertsIndex, q)
	if err != nil {
		return nil, mitigationOut{}, err
	}
	if len(res.Hits) == 0 {
		return nil, mitigationOut{}, errNotFound("alert", id)
	}
	src := res.Hits[0].Source
	agent := str(src, "agent", "id")
	ip := str(src, "data", "srcip")
	desc := clip(cleanText(str(src, "rule", "description")), 200)
	rule, _ := src["rule"].(map[string]any)
	groups := strList(rule, "groups")

	out := mitigationOut{
		Source:  "alert " + id,
		Summary: fmt.Sprintf("Rule %s level %v: %s (agent %s)", str(src, "rule", "id"), rule["level"], desc, agent),
	}
	if ip != "" && agent != "" {
		ttl := d.Response.Policy().DefaultBlockTTL()
		note := ""
		if addr, err := netip.ParseAddr(ip); err == nil && (addr.IsPrivate() || addr.IsLinkLocalUnicast()) {
			note = "The source is an internal address: check the host before blocking, it may be a legitimate machine."
		}
		o := actionOption(d, policy.BlockIP, policy.Params{AgentIDs: []string{agent}, IP: ip, TTLSeconds: ttl},
			fmt.Sprintf("Block %s on agent %s for %s through active response.", ip, agent, (time.Duration(ttl)*time.Second).String()))
		if note != "" {
			o.Note = strings.TrimSpace(o.Note + " " + note)
		}
		out.Options = append(out.Options, o)
	}
	for _, g := range groups {
		if g == "syscheck" && agent != "" {
			out.Options = append(out.Options, actionOption(d, policy.ScanFIM, policy.Params{AgentIDs: []string{agent}},
				"File integrity changed: run a FIM scan on the agent to see the full set of modified files."))
			break
		}
	}
	out.Options = append(out.Options, option{
		Kind:        "manual",
		Description: "Investigate: use alerts_search with the same srcip and agent_id to see the wider activity, and vulns_search on the agent to see exploitable weaknesses.",
		Allowed:     true,
	})
	return nil, out, nil
}

func cveOptions(ctx context.Context, d Deps, cve string) (*mcp.CallToolResult, mitigationOut, error) {
	q, err := indexer.VulnQuery(indexer.VulnFilter{CVE: cve, Limit: indexer.MaxLimit})
	if err != nil {
		return nil, mitigationOut{}, err
	}
	res, err := d.Indexer.Search(ctx, indexer.VulnIndex, q)
	if err != nil {
		return nil, mitigationOut{}, err
	}
	if len(res.Hits) == 0 {
		return nil, mitigationOut{}, errNotFound("finding for", strings.ToUpper(cve))
	}
	agents := map[string]bool{}
	pkgs := map[string]bool{}
	var sev string
	for _, h := range res.Hits {
		agents[str(h.Source, "agent", "id")+" ("+clip(cleanText(str(h.Source, "agent", "name")), 64)+")"] = true
		pkgs[clip(cleanText(str(h.Source, "package", "name")+" "+str(h.Source, "package", "version")), 100)] = true
		if sev == "" {
			sev = str(h.Source, "vulnerability", "severity")
		}
	}
	out := mitigationOut{
		Source:  strings.ToUpper(cve),
		Summary: fmt.Sprintf("%s severity %s affects %d agent(s) (%d finding(s) in total).", strings.ToUpper(cve), sev, len(agents), res.Total),
	}
	out.Options = append(out.Options,
		option{Kind: "manual", Allowed: true, Description: "Update the affected package(s) on: " + joinKeys(agents) + ". Packages: " + joinKeys(pkgs) + ". Wazuh detects vulnerabilities but does not patch them; use your package manager or patch tool."},
		option{Kind: "manual", Allowed: true, Description: "If patching must wait, reduce exposure: restrict the service to trusted networks, and watch alerts_search on these agents for exploitation attempts."},
		option{Kind: "manual", Allowed: true, Description: "After patching, confirm with vulns_search (cve filter) that the finding disappears at the next scan."},
	)
	return nil, out, nil
}

func joinKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	if len(keys) > 10 {
		return strings.Join(keys[:10], ", ") + fmt.Sprintf(" and %d more", len(keys)-10)
	}
	return strings.Join(keys, ", ")
}

// ---------------------------------------------------------------------------
// plans (propose, list)
// ---------------------------------------------------------------------------

type proposeArgs struct {
	Action     string   `json:"action" jsonschema:"one of block_ip, restart_agent, scan_fim (see autonomy_status)"`
	AgentIDs   []string `json:"agent_ids" jsonschema:"agents to act on, such as [\"001\"]"`
	IP         string   `json:"ip,omitempty" jsonschema:"IP address, for block_ip"`
	TTLSeconds int      `json:"ttl_seconds,omitempty" jsonschema:"how long to block, in seconds; required for block_ip and must be one of the durations autonomy_status lists (default 3600)"`
	Reason     string   `json:"reason" jsonschema:"why this action is needed, 5-500 characters; shown to the human and written to the audit log"`
	Source     string   `json:"source,omitempty" jsonschema:"alert id or CVE that motivated the action"`
}

type planOut struct {
	Plan      plans.Plan `json:"plan"`
	Level     string     `json:"autonomy_level"`
	NextStep  string     `json:"next_step"`
	ExpiresIn string     `json:"expires_in"`
}

func nextStep(l policy.Level, id string) string {
	switch l {
	case policy.Propose:
		return fmt.Sprintf("Plan %s is recorded. You cannot execute it: a human must run it from the admin API.", id)
	case policy.Approve:
		return fmt.Sprintf("Plan %s waits for human approval. Once approved, call response_execute with plan_id=%s.", id, id)
	case policy.Auto:
		return fmt.Sprintf("Call response_execute with plan_id=%s to run it now.", id)
	}
	return ""
}

type plansArgs struct {
	ID     string `json:"id,omitempty" jsonschema:"show one plan"`
	Status string `json:"status,omitempty" jsonschema:"filter: pending, approved, rejected, executed or failed"`
}

type plansOut struct {
	Plans []plans.Plan `json:"plans"`
}

type blocksArgs struct{}

type blocksOut struct {
	Blocks []response.BlockInfo `json:"blocks"`
}

func addResponseReadTools(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "response_plans",
		Description: "List response plans and their status (pending, approved, rejected, executed, failed), or show one by id.",
		Annotations: readOnly(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a plansArgs) (*mcp.CallToolResult, plansOut, error) {
		if a.ID != "" {
			p, err := d.Response.Plan(a.ID)
			if err != nil {
				return nil, plansOut{}, err
			}
			return nil, plansOut{Plans: []plans.Plan{p}}, nil
		}
		return nil, plansOut{Plans: d.Response.Plans(plans.Status(a.Status))}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "blocks_list",
		Description: "List IP blocks set by this server that are still active, with their expiry time.",
		Annotations: readOnly(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ blocksArgs) (*mcp.CallToolResult, blocksOut, error) {
		return nil, blocksOut{Blocks: d.Response.ActiveBlocks()}, nil
	})
}

func addProposeTool(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "response_propose",
		Description: "Create a response plan (block an IP, restart an agent, run a FIM scan). This only records the plan and validates it against policy: nothing is changed on any agent. The answer tells you what happens next, which depends on the autonomy level.",
		Annotations: additive(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a proposeArgs) (*mcp.CallToolResult, planOut, error) {
		plan, err := d.Response.Propose(response.ActorMCP, response.ProposeRequest{
			Action: policy.Action(a.Action),
			Params: policy.Params{AgentIDs: a.AgentIDs, IP: a.IP, TTLSeconds: a.TTLSeconds},
			Reason: a.Reason,
			Source: clip(cleanText(a.Source), 128),
		})
		if err != nil {
			return nil, planOut{}, err
		}
		lvl := d.Response.Policy().LevelFor(plan.Action)
		return nil, planOut{Plan: plan, Level: lvl.String(), NextStep: nextStep(lvl, plan.ID), ExpiresIn: "30m"}, nil
	})
}

type executeArgs struct {
	PlanID string `json:"plan_id" jsonschema:"id of a plan created with response_propose"`
}

type executeOut struct {
	Plan plans.Plan `json:"plan"`
}

func addExecuteTool(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "response_execute",
		Description: "Execute a response plan on the Wazuh agents. This changes the monitored environment. It works only if the autonomy level for that action allows you to (approve: after human approval; auto: directly). A plan runs at most once and expires after 30 minutes.",
		Annotations: impactful(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a executeArgs) (*mcp.CallToolResult, executeOut, error) {
		if a.PlanID == "" {
			return nil, executeOut{}, errField("plan_id")
		}
		plan, err := d.Response.Execute(ctx, response.ActorMCP, a.PlanID)
		if err != nil {
			return nil, executeOut{}, err
		}
		return nil, executeOut{Plan: plan}, nil
	})
}
