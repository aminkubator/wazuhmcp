// Package policy decides what the AI is allowed to do with response actions.
//
// Two independent layers live here:
//
//   - Autonomy: a feature flag with four levels, set globally and optionally
//     overridden per action. It answers "who may execute this action?".
//   - Guardrails: hard limits (protected IPs and agents, parameter validation,
//     rate limit) that apply to EVERY execution, whatever the autonomy level
//     and whoever triggers it.
//
// Everything is configured at startup from flags/env. Nothing here can be
// changed through an MCP tool, so an agent cannot widen its own permissions.
package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is how much freedom the AI has to act.
type Level int

const (
	// ReadOnly: no response tools are registered at all.
	ReadOnly Level = iota
	// Propose: the AI can create plans, but only a human can execute them.
	Propose
	// Approve: the AI can execute a plan only after a human approved it.
	Approve
	// Auto: the AI can execute a plan itself, within the guardrails.
	Auto
)

var levelNames = [...]string{"readonly", "propose", "approve", "auto"}

func (l Level) String() string {
	if l < 0 || int(l) >= len(levelNames) {
		return "unknown"
	}
	return levelNames[l]
}

// ParseLevel converts a flag value into a Level.
func ParseLevel(s string) (Level, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range levelNames {
		if s == n {
			return Level(i), nil
		}
	}
	return ReadOnly, fmt.Errorf("unknown autonomy level %q (want readonly, propose, approve or auto)", s)
}

// Action is a response action the server knows how to perform. The set is
// fixed in code on purpose.
type Action string

const (
	BlockIP      Action = "block_ip"
	RestartAgent Action = "restart_agent"
	ScanFIM      Action = "scan_fim"
)

// Risk is a rough impact rating shown to the human and the AI.
type Risk string

const (
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

// ActionInfo describes one action.
type ActionInfo struct {
	Action      Action `json:"action"`
	Risk        Risk   `json:"risk"`
	Description string `json:"description"`
	NeedsIP     bool   `json:"needs_ip"`
	NeedsTTL    bool   `json:"needs_ttl"`
}

var registry = map[Action]ActionInfo{
	BlockIP:      {BlockIP, RiskMedium, "Block a source IP on the chosen agents through Wazuh active response (firewall-drop). Wazuh lifts the block by itself when the timeout ends.", true, true},
	RestartAgent: {RestartAgent, RiskHigh, "Restart the Wazuh agent service on the chosen agents (briefly stops monitoring).", false, false},
	ScanFIM:      {ScanFIM, RiskLow, "Start a File Integrity Monitoring (syscheck) scan on the chosen agents.", false, false},
}

// Info returns the metadata of an action.
func Info(a Action) (ActionInfo, bool) {
	i, ok := registry[a]
	return i, ok
}

// Actions lists every known action, sorted by name.
func Actions() []ActionInfo {
	out := make([]ActionInfo, 0, len(registry))
	for _, i := range registry {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Action < out[b].Action })
	return out
}

// ParseOverrides parses "block_ip=auto,restart_agent=approve".
func ParseOverrides(s string) (map[Action]Level, error) {
	out := map[Action]Level{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid autonomy override %q (want action=level)", part)
		}
		act := Action(strings.TrimSpace(k))
		if _, known := registry[act]; !known {
			return nil, fmt.Errorf("unknown action %q in autonomy override", act)
		}
		lvl, err := ParseLevel(v)
		if err != nil {
			return nil, err
		}
		out[act] = lvl
	}
	return out, nil
}

// Config is the policy setup.
type Config struct {
	// Default is the autonomy level for every action without an override.
	Default Level
	// Overrides sets a different level for individual actions.
	Overrides map[Action]Level
	// ProtectedIPs are addresses or CIDRs that can never be blocked
	// (gateway, DNS, jump hosts, the Wazuh manager...).
	ProtectedIPs []string
	// ProtectedAgents are agent IDs that no action may touch. "000" (the
	// manager) is always protected.
	ProtectedAgents []string
	// MaxPerHour caps executions per action per rolling hour. 0 = default 10.
	MaxPerHour int
	// MaxAgents caps how many agents one plan may target. 0 = default 5.
	MaxAgents int
	// AllowedTTLs are the block durations (seconds) the manager has an
	// active-response timeout for. Wazuh's API can only run commands listed in
	// ar.conf, one per timeout, so a block's duration must be one of them.
	// Empty = any value between MinTTL and MaxTTL.
	AllowedTTLs []int
	// MinTTL and MaxTTL bound block durations when AllowedTTLs is empty.
	// 0 = defaults (1m, 7d).
	MinTTL, MaxTTL time.Duration
}

// Policy evaluates actions against a Config. It is safe for concurrent use.
type Policy struct {
	cfg       Config
	protNets  []netip.Prefix
	protAgent map[string]bool

	mu    sync.Mutex
	times map[Action][]time.Time
	now   func() time.Time
}

var agentIDRe = regexp.MustCompile(`^\d{3,}$`)

// New validates cfg and returns a Policy.
func New(cfg Config) (*Policy, error) {
	if cfg.MaxPerHour <= 0 {
		cfg.MaxPerHour = 10
	}
	if cfg.MaxAgents <= 0 {
		cfg.MaxAgents = 5
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = time.Minute
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 7 * 24 * time.Hour
	}
	p := &Policy{cfg: cfg, protAgent: map[string]bool{"000": true}, times: map[Action][]time.Time{}, now: time.Now}
	for _, s := range cfg.ProtectedIPs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			p.protNets = append(p.protNets, pfx.Masked())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid protected IP %q", s)
		}
		p.protNets = append(p.protNets, netip.PrefixFrom(addr, addr.BitLen()))
	}
	for _, id := range cfg.ProtectedAgents {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if !agentIDRe.MatchString(id) {
			return nil, fmt.Errorf("invalid protected agent id %q", id)
		}
		p.protAgent[id] = true
	}
	return p, nil
}

// LevelFor is the effective autonomy level of an action.
func (p *Policy) LevelFor(a Action) Level {
	if l, ok := p.cfg.Overrides[a]; ok {
		return l
	}
	return p.cfg.Default
}

// MaxLevel is the highest level of any action. It decides which tools get
// registered: nothing at ReadOnly, plan tools from Propose, the execute tool
// from Approve.
func (p *Policy) MaxLevel() Level {
	max := ReadOnly
	for a := range registry {
		if l := p.LevelFor(a); l > max {
			max = l
		}
	}
	return max
}

// AllowedTTLs returns the permitted block durations in seconds, ascending, or
// nil when any duration in range is accepted.
func (p *Policy) AllowedTTLs() []int {
	out := append([]int(nil), p.cfg.AllowedTTLs...)
	sort.Ints(out)
	return out
}

// DefaultBlockTTL is the duration suggested for a block: one hour when
// allowed, otherwise the shortest allowed duration.
func (p *Policy) DefaultBlockTTL() int {
	allowed := p.AllowedTTLs()
	if len(allowed) == 0 {
		return 3600
	}
	for _, t := range allowed {
		if t == 3600 {
			return t
		}
	}
	return allowed[0]
}

// Default returns the global level.
func (p *Policy) Default() Level { return p.cfg.Default }

// Params are the inputs of an action, as validated by the policy.
type Params struct {
	AgentIDs   []string `json:"agent_ids"`
	IP         string   `json:"ip,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

// Validate checks parameters against the action definition and the
// guardrails (protected IPs and agents, limits). It does not consume the rate
// limit; see Allow.
func (p *Policy) Validate(a Action, pr Params) error {
	info, ok := registry[a]
	if !ok {
		return fmt.Errorf("unknown action %q", a)
	}
	if len(pr.AgentIDs) == 0 {
		return fmt.Errorf("agent_ids is required")
	}
	if len(pr.AgentIDs) > p.cfg.MaxAgents {
		return fmt.Errorf("too many agents: %d (max %d per plan)", len(pr.AgentIDs), p.cfg.MaxAgents)
	}
	seen := map[string]bool{}
	for _, id := range pr.AgentIDs {
		if !agentIDRe.MatchString(id) {
			return fmt.Errorf("invalid agent id %q (want digits such as 001)", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate agent id %q", id)
		}
		seen[id] = true
		if p.protAgent[id] {
			return fmt.Errorf("agent %s is protected and cannot be targeted", id)
		}
	}
	if info.NeedsIP {
		addr, err := netip.ParseAddr(strings.TrimSpace(pr.IP))
		if err != nil {
			return fmt.Errorf("ip is required and must be a valid address")
		}
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			return fmt.Errorf("ip %s is not a valid block target (loopback, unspecified, multicast or link-local)", addr)
		}
		for _, n := range p.protNets {
			if n.Contains(addr) {
				return fmt.Errorf("ip %s is in the protected list", addr)
			}
		}
	} else if pr.IP != "" {
		return fmt.Errorf("ip is not used by action %s", a)
	}
	if info.NeedsTTL {
		if len(p.cfg.AllowedTTLs) > 0 {
			ok := false
			for _, t := range p.cfg.AllowedTTLs {
				ok = ok || t == pr.TTLSeconds
			}
			if !ok {
				return fmt.Errorf("ttl_seconds must be one of %v (the timeouts configured as active-response on the manager)", p.AllowedTTLs())
			}
		} else if ttl := time.Duration(pr.TTLSeconds) * time.Second; ttl < p.cfg.MinTTL || ttl > p.cfg.MaxTTL {
			return fmt.Errorf("ttl_seconds must be between %d and %d", int(p.cfg.MinTTL.Seconds()), int(p.cfg.MaxTTL.Seconds()))
		}
	} else if pr.TTLSeconds != 0 {
		return fmt.Errorf("ttl_seconds is not used by action %s", a)
	}
	return nil
}

// Allow consumes one execution from the rolling-hour budget of the action.
// It returns an error when the budget is exhausted.
func (p *Policy) Allow(a Action) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	cut := now.Add(-time.Hour)
	kept := p.times[a][:0]
	for _, t := range p.times[a] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= p.cfg.MaxPerHour {
		p.times[a] = kept
		return fmt.Errorf("rate limit: %d executions of %s in the last hour (max %d)", len(kept), a, p.cfg.MaxPerHour)
	}
	p.times[a] = append(kept, now)
	return nil
}

// Refund gives back one execution of the budget, used when the call failed
// before reaching Wazuh.
func (p *Policy) Refund(a Action) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.times[a]); n > 0 {
		p.times[a] = p.times[a][:n-1]
	}
}
