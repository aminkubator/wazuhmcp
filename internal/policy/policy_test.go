package policy

import (
	"strings"
	"testing"
	"time"
)

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"readonly": ReadOnly, " Propose ": Propose, "APPROVE": Approve, "auto": Auto} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("yolo"); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestParseOverrides(t *testing.T) {
	m, err := ParseOverrides("block_ip=auto, restart_agent=propose")
	if err != nil || m[BlockIP] != Auto || m[RestartAgent] != Propose || len(m) != 2 {
		t.Fatalf("got %v, %v", m, err)
	}
	for _, bad := range []string{"block_ip", "nope=auto", "block_ip=maybe"} {
		if _, err := ParseOverrides(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestLevelForAndMaxLevel(t *testing.T) {
	p, _ := New(Config{Default: ReadOnly, Overrides: map[Action]Level{BlockIP: Auto, RestartAgent: Propose}})
	if p.LevelFor(BlockIP) != Auto || p.LevelFor(ScanFIM) != ReadOnly || p.LevelFor(RestartAgent) != Propose {
		t.Error("wrong effective levels")
	}
	if p.MaxLevel() != Auto {
		t.Errorf("MaxLevel = %v, want auto", p.MaxLevel())
	}
	// A default of auto lowered for every action: max follows the overrides.
	all := map[Action]Level{}
	for _, a := range Actions() {
		all[a.Action] = Propose
	}
	p2, _ := New(Config{Default: Auto, Overrides: all})
	if p2.MaxLevel() != Propose {
		t.Errorf("MaxLevel = %v, want propose", p2.MaxLevel())
	}
	p3, _ := New(Config{})
	if p3.MaxLevel() != ReadOnly {
		t.Errorf("zero config must be readonly, got %v", p3.MaxLevel())
	}
}

func newPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := New(Config{ProtectedIPs: []string{"10.0.0.1", "192.168.1.0/24"}, ProtectedAgents: []string{"002"}, MaxAgents: 2})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidate(t *testing.T) {
	p := newPolicy(t)
	ok := Params{AgentIDs: []string{"001"}, IP: "203.0.113.9", TTLSeconds: 3600}
	if err := p.Validate(BlockIP, ok); err != nil {
		t.Fatalf("valid params refused: %v", err)
	}
	cases := map[string]struct {
		act Action
		pr  Params
		sub string
	}{
		"no agents":       {BlockIP, Params{IP: "203.0.113.9", TTLSeconds: 3600}, "agent_ids"},
		"manager":         {RestartAgent, Params{AgentIDs: []string{"000"}}, "protected"},
		"protected agent": {ScanFIM, Params{AgentIDs: []string{"002"}}, "protected"},
		"bad agent id":    {ScanFIM, Params{AgentIDs: []string{"1;rm"}}, "invalid agent id"},
		"too many":        {ScanFIM, Params{AgentIDs: []string{"001", "003", "004"}}, "too many"},
		"duplicate":       {ScanFIM, Params{AgentIDs: []string{"001", "001"}}, "duplicate"},
		"protected ip":    {BlockIP, Params{AgentIDs: []string{"001"}, IP: "10.0.0.1", TTLSeconds: 3600}, "protected"},
		"protected cidr":  {BlockIP, Params{AgentIDs: []string{"001"}, IP: "192.168.1.77", TTLSeconds: 3600}, "protected"},
		"loopback":        {BlockIP, Params{AgentIDs: []string{"001"}, IP: "127.0.0.1", TTLSeconds: 3600}, "not a valid block target"},
		"garbage ip":      {BlockIP, Params{AgentIDs: []string{"001"}, IP: "1.2.3.4; reboot", TTLSeconds: 3600}, "valid address"},
		"ttl missing":     {BlockIP, Params{AgentIDs: []string{"001"}, IP: "203.0.113.9"}, "ttl_seconds"},
		"ttl too long":    {BlockIP, Params{AgentIDs: []string{"001"}, IP: "203.0.113.9", TTLSeconds: 10 * 24 * 3600}, "ttl_seconds"},
		"ip on scan":      {ScanFIM, Params{AgentIDs: []string{"001"}, IP: "203.0.113.9"}, "not used"},
		"ttl on scan":     {ScanFIM, Params{AgentIDs: []string{"001"}, TTLSeconds: 60}, "not used"},
		"no unblock":      {Action("unblock_ip"), Params{AgentIDs: []string{"001"}, IP: "203.0.113.9"}, "unknown action"},
		"unknown action":  {Action("rm_rf"), Params{AgentIDs: []string{"001"}}, "unknown action"},
	}
	for name, c := range cases {
		err := p.Validate(c.act, c.pr)
		if err == nil || !strings.Contains(err.Error(), c.sub) {
			t.Errorf("%s: got %v, want error containing %q", name, err, c.sub)
		}
	}
}

func TestNewRejectsBadProtectedEntries(t *testing.T) {
	if _, err := New(Config{ProtectedIPs: []string{"not-an-ip"}}); err == nil {
		t.Error("expected error for bad protected ip")
	}
	if _, err := New(Config{ProtectedAgents: []string{"abc"}}); err == nil {
		t.Error("expected error for bad protected agent")
	}
}

func TestRateLimit(t *testing.T) {
	p, _ := New(Config{MaxPerHour: 2})
	now := time.Now()
	p.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if err := p.Allow(BlockIP); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if err := p.Allow(BlockIP); err == nil {
		t.Fatal("third call must be limited")
	}
	if err := p.Allow(ScanFIM); err != nil {
		t.Fatalf("other actions have their own budget: %v", err)
	}
	p.Refund(BlockIP)
	if err := p.Allow(BlockIP); err != nil {
		t.Fatalf("refund should free a slot: %v", err)
	}
	now = now.Add(61 * time.Minute)
	if err := p.Allow(BlockIP); err != nil {
		t.Fatalf("window should have rolled over: %v", err)
	}
}

func TestAllowedTTLs(t *testing.T) {
	p, _ := New(Config{AllowedTTLs: []int{3600, 300}})
	base := Params{AgentIDs: []string{"001"}, IP: "203.0.113.9"}
	for _, ttl := range []int{300, 3600} {
		base.TTLSeconds = ttl
		if err := p.Validate(BlockIP, base); err != nil {
			t.Errorf("ttl %d should be allowed: %v", ttl, err)
		}
	}
	for _, ttl := range []int{0, 60, 600, 7200} {
		base.TTLSeconds = ttl
		err := p.Validate(BlockIP, base)
		if err == nil || !strings.Contains(err.Error(), "[300 3600]") {
			t.Errorf("ttl %d: got %v, want an error listing the allowed durations", ttl, err)
		}
	}
	if got := p.AllowedTTLs(); len(got) != 2 || got[0] != 300 {
		t.Errorf("AllowedTTLs must be sorted ascending: %v", got)
	}
	if p.DefaultBlockTTL() != 3600 {
		t.Errorf("default = %d, want 3600", p.DefaultBlockTTL())
	}
	short, _ := New(Config{AllowedTTLs: []int{900, 300}})
	if short.DefaultBlockTTL() != 300 {
		t.Errorf("without 3600 the shortest is suggested, got %d", short.DefaultBlockTTL())
	}
	free, _ := New(Config{})
	if free.AllowedTTLs() != nil || free.DefaultBlockTTL() != 3600 {
		t.Error("no allowed set means any ttl in range")
	}
}
