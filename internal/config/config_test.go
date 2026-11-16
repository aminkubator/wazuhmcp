package config

import (
	"io"
	"strings"
	"testing"

	"wazuhmcp/internal/policy"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var creds = map[string]string{
	"WAZUHMCP_API_USER": "wazuh-wui", "WAZUHMCP_API_PASSWORD": "a",
	"WAZUHMCP_INDEXER_USER": "reader", "WAZUHMCP_INDEXER_PASSWORD": "b",
}

func merge(extra map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range creds {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestDefaultsAreSafe(t *testing.T) {
	c, err := Parse(nil, env(creds), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Autonomy != policy.ReadOnly || len(c.AutonomyActions) != 0 {
		t.Errorf("default autonomy must be readonly, got %v %v", c.Autonomy, c.AutonomyActions)
	}
	if !strings.HasPrefix(c.Addr, "127.0.0.1:") {
		t.Errorf("default must listen on loopback, got %s", c.Addr)
	}
	if c.APIURL != "https://localhost:55000" || c.IndexerURL != "https://localhost:9200" {
		t.Errorf("urls = %s %s", c.APIURL, c.IndexerURL)
	}
	if c.Insecure {
		t.Error("TLS verification must be on by default")
	}
}

func TestFlagBeatsEnvBeatsDefault(t *testing.T) {
	c, err := Parse([]string{"-autonomy", "auto"}, env(merge(map[string]string{"WAZUHMCP_AUTONOMY": "approve", "WAZUHMCP_MAX_AGENTS": "3"})), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Autonomy != policy.Auto {
		t.Errorf("flag must win over env, got %v", c.Autonomy)
	}
	if c.MaxAgents != 3 {
		t.Errorf("env must win over default, got %d", c.MaxAgents)
	}
	c, _ = Parse(nil, env(merge(map[string]string{"WAZUHMCP_AUTONOMY": "approve"})), io.Discard)
	if c.Autonomy != policy.Approve {
		t.Errorf("env = %v", c.Autonomy)
	}
}

func TestAutonomyOverridesAndLists(t *testing.T) {
	c, err := Parse([]string{
		"-autonomy", "propose", "-autonomy-action", "scan_fim=auto,block_ip=approve",
		"-protected-ips", "10.0.0.1, 192.168.0.0/16", "-protected-agents", "002,003",
		"-plan-ttl", "10m",
	}, env(creds), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.AutonomyActions[policy.ScanFIM] != policy.Auto || c.AutonomyActions[policy.BlockIP] != policy.Approve {
		t.Errorf("overrides = %v", c.AutonomyActions)
	}
	if len(c.ProtectedIPs) != 2 || len(c.ProtectedAgents) != 2 || c.PlanTTL.Minutes() != 10 {
		t.Errorf("cfg = %+v", c)
	}
}

func TestInvalidValues(t *testing.T) {
	bad := [][]string{
		{"-autonomy", "yolo"},
		{"-autonomy-action", "block_ip=maybe"},
		{"-autonomy-action", "format_disk=auto"},
		{"-plan-ttl", "soon"},
		{"-token", "same", "-admin-token", "same"},
		{"stray"},
	}
	for _, a := range bad {
		if _, err := Parse(a, env(creds), io.Discard); err == nil {
			t.Errorf("args %v should fail", a)
		}
	}
}

func TestCredentialsRequired(t *testing.T) {
	if _, err := Parse(nil, env(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "API credentials") {
		t.Errorf("err = %v", err)
	}
	m := map[string]string{"WAZUHMCP_API_USER": "u", "WAZUHMCP_API_PASSWORD": "p"}
	if _, err := Parse(nil, env(m), io.Discard); err == nil || !strings.Contains(err.Error(), "Indexer credentials") {
		t.Errorf("err = %v", err)
	}
}

func TestBlockCommands(t *testing.T) {
	c, err := Parse(nil, env(creds), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockCommands[300] != "firewall-drop300" || c.BlockCommands[3600] != "firewall-drop3600" || len(c.BlockCommands) != 2 {
		t.Errorf("defaults = %v", c.BlockCommands)
	}
	c, err = Parse([]string{"-block-commands", "900=host-deny900"}, env(creds), io.Discard)
	if err != nil || len(c.BlockCommands) != 1 || c.BlockCommands[900] != "host-deny900" {
		t.Errorf("custom = %v, %v", c.BlockCommands, err)
	}
	for _, bad := range []string{"", "3600", "x=firewall-drop", "0=firewall-drop", "60=!custom.sh", "60=a b", "60=a;rm", "-5=x"} {
		if _, err := ParseBlockCommands(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}
