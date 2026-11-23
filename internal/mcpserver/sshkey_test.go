package mcpserver

import (
	"strings"
	"testing"
	"time"

	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/wazuh/indexer"
)

const testFP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func sshHit(ago time.Duration, agent, user, ip, fp string) indexer.Hit {
	return indexer.Hit{Source: map[string]any{
		"@timestamp": time.Now().UTC().Add(-ago).Format("2006-01-02T15:04:05.000Z"),
		"agent":      map[string]any{"id": agent, "name": "srv" + agent},
		"full_log":   "sshd[1]: Accepted publickey for " + user + " from " + ip + " port 4242 ssh2: ED25519 " + fp,
	}}
}

func TestSSHKeyUsageFlagsNewPairOnly(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.ReadOnly})
	other := "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	h.idx.result = &indexer.Result{Total: 5, Hits: []indexer.Hit{
		sshHit(time.Hour, "002", "deploy", "10.0.0.5", testFP),      // known pair, recent
		sshHit(2*time.Hour, "003", "deploy", "10.0.0.66", testFP),   // NEW source to 003
		sshHit(3*24*time.Hour, "002", "deploy", "10.0.0.5", testFP), // baseline
		sshHit(time.Hour, "002", "deploy", "10.0.0.5", other),       // other key: filtered out
		{Source: map[string]any{"@timestamp": time.Now().UTC().Format(time.RFC3339), "full_log": "Accepted publickey for x from 1.2.3.4 port 1 ssh2: RSA aa:bb"}},
	}}
	out, res := h.call(t, "ssh_key_usage", map[string]any{"fingerprint": testFP})
	if res.IsError {
		t.Fatal(text(res))
	}
	if out["new_pairs"] != float64(1) || out["logins_without_fingerprint"] != float64(2) || out["truncated"] != false {
		t.Fatalf("unexpected counts: %v", out)
	}
	pairs := out["pairs"].([]any)
	first := pairs[0].(map[string]any)
	if len(pairs) != 2 || first["srcip"] != "10.0.0.66" || first["new"] != true {
		t.Fatalf("new pair must be listed first: %v", pairs)
	}
	known := pairs[1].(map[string]any)
	if known["logins_recent"] != float64(1) || known["logins_baseline"] != float64(1) || known["new"] != false {
		t.Errorf("known pair miscounted: %v", known)
	}
	if f := out["findings"].([]any); !strings.Contains(f[0].(string), "NEW: key "+testFP) {
		t.Errorf("findings = %v", f)
	}
}

func TestSSHKeyUsageRejectsBadInput(t *testing.T) {
	h := newHarness(t, policy.Config{Default: policy.ReadOnly})
	for _, args := range []map[string]any{
		{"fingerprint": `SHA256:x" OR *`},
		{"window": "99d"},
		{"baseline": "1w"},
	} {
		if _, res := h.call(t, "ssh_key_usage", args); !res.IsError {
			t.Errorf("%v should be rejected", args)
		}
	}
	if len(h.idx.bodies) != 0 {
		t.Error("bad input must fail before querying the indexer")
	}
}
