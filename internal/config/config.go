// Package config reads the server settings from flags and environment.
// Priority: flag > environment > default. Secrets (passwords, tokens) should
// come from the environment so they stay out of the process list.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wazuhmcp/internal/policy"
)

// Config is the full server configuration.
type Config struct {
	Addr       string
	TLSCert    string // serve HTTPS when set (with TLSKey)
	TLSKey     string
	Token      string // MCP clients
	AdminToken string // humans: approve / reject / execute plans

	APIURL      string
	APIUser     string
	APIPassword string

	IndexerURL      string
	IndexerUser     string
	IndexerPassword string

	CAFile   string
	Insecure bool
	// Certificate host names to expect when connecting by IP or via a tunnel.
	APITLSName     string
	IndexerTLSName string

	// Autonomy
	Autonomy        policy.Level
	AutonomyActions map[policy.Action]policy.Level
	ProtectedIPs    []string
	ProtectedAgents []string
	MaxPerHour      int
	MaxAgents       int
	PlanTTL         time.Duration
	AuditFile       string

	// BlockCommands maps a block duration in seconds to the active-response
	// command for it, e.g. 3600 -> firewall-drop3600 (see response.Commands).
	BlockCommands map[int]string
}

// Usage is the help text.
const Usage = `WazuhMCP - MCP server for reading and responding in Wazuh 4.14

Usage:
  wazuhmcp serve [flags]
  wazuhmcp version | help

Connection (secrets: prefer the environment variables):
  -addr                 listen address (default 127.0.0.1:8090)          WAZUHMCP_ADDR
  -tls-cert, -tls-key   serve HTTPS with this PEM certificate and key
                        (needed when -addr is not loopback)    WAZUHMCP_TLS_CERT / WAZUHMCP_TLS_KEY
  -token                token for MCP clients; generated when empty       WAZUHMCP_TOKEN
  -admin-token          token for the admin API (approve/execute plans);
                        generated when empty. Must differ from -token.    WAZUHMCP_ADMIN_TOKEN
  -api-url              Wazuh manager API (default https://localhost:55000)  WAZUHMCP_API_URL
  -api-user                                                                WAZUHMCP_API_USER
  (password)            environment only                                  WAZUHMCP_API_PASSWORD
  -indexer-url          Wazuh Indexer (default https://localhost:9200)    WAZUHMCP_INDEXER_URL
  -indexer-user                                                           WAZUHMCP_INDEXER_USER
  (password)            environment only                                  WAZUHMCP_INDEXER_PASSWORD
  -ca-file              PEM file to trust (Wazuh uses self-signed certs)   WAZUHMCP_CA_FILE
  -api-tls-name         certificate name to expect from the API, e.g. wazuh.manager,
                        when you connect by IP or through a tunnel         WAZUHMCP_API_TLS_NAME
  -indexer-tls-name     same for the Indexer, e.g. wazuh.indexer          WAZUHMCP_INDEXER_TLS_NAME
  -insecure-skip-verify disable TLS verification (not recommended)         WAZUHMCP_INSECURE

Autonomy (how much the AI may do; default readonly):
  -autonomy             readonly | propose | approve | auto               WAZUHMCP_AUTONOMY
      readonly  no response tools at all
      propose   AI creates plans, only a human executes them
      approve   AI executes a plan only after a human approved it
      auto      AI executes plans itself, within the guardrails
  -autonomy-action      per-action override, e.g. "block_ip=auto,restart_agent=propose"
                        actions: block_ip, unblock_ip, restart_agent, scan_fim
                                                                         WAZUHMCP_AUTONOMY_ACTIONS
  -protected-ips        IPs/CIDRs that can never be blocked               WAZUHMCP_PROTECTED_IPS
  -protected-agents     agent ids no action may touch (000 always is)     WAZUHMCP_PROTECTED_AGENTS
  -max-per-hour         executions per action per hour (default 10)       WAZUHMCP_MAX_PER_HOUR
  -max-agents           agents per plan (default 5)                       WAZUHMCP_MAX_AGENTS
  -plan-ttl             how long a plan stays valid (default 30m)         WAZUHMCP_PLAN_TTL
  -audit-file           audit log, JSON lines (default ~/.local/state/wazuhmcp/audit.jsonl)
                                                                         WAZUHMCP_AUDIT_FILE
  -block-commands       block duration -> active-response command, as seconds=command.
                        Wazuh's API only runs commands listed in the manager's ar.conf,
                        named "<command><timeout>" (needs a matching <active-response>
                        block with that <timeout>). Wazuh lifts the block by itself.
                        (default "300=firewall-drop300,3600=firewall-drop3600")
                                                                         WAZUHMCP_BLOCK_COMMANDS
`

// Parse reads configuration from args and the given environment lookup.
func Parse(args []string, env func(string) string, errOut io.Writer) (*Config, error) {
	if env == nil {
		env = os.Getenv
	}
	e := func(k, def string) string {
		if v := strings.TrimSpace(env(k)); v != "" {
			return v
		}
		return def
	}
	c := &Config{
		APIPassword:     env("WAZUHMCP_API_PASSWORD"),
		IndexerPassword: env("WAZUHMCP_INDEXER_PASSWORD"),
	}
	var autonomy, actions, protIPs, protAgents, planTTL, blockCmds string
	var maxHour, maxAgents int

	fs := flag.NewFlagSet("wazuhmcp serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&c.Addr, "addr", e("WAZUHMCP_ADDR", "127.0.0.1:8090"), "")
	fs.StringVar(&c.TLSCert, "tls-cert", e("WAZUHMCP_TLS_CERT", ""), "")
	fs.StringVar(&c.TLSKey, "tls-key", e("WAZUHMCP_TLS_KEY", ""), "")
	fs.StringVar(&c.Token, "token", e("WAZUHMCP_TOKEN", ""), "")
	fs.StringVar(&c.AdminToken, "admin-token", e("WAZUHMCP_ADMIN_TOKEN", ""), "")
	fs.StringVar(&c.APIURL, "api-url", e("WAZUHMCP_API_URL", "https://localhost:55000"), "")
	fs.StringVar(&c.APIUser, "api-user", e("WAZUHMCP_API_USER", ""), "")
	fs.StringVar(&c.IndexerURL, "indexer-url", e("WAZUHMCP_INDEXER_URL", "https://localhost:9200"), "")
	fs.StringVar(&c.IndexerUser, "indexer-user", e("WAZUHMCP_INDEXER_USER", ""), "")
	fs.StringVar(&c.CAFile, "ca-file", e("WAZUHMCP_CA_FILE", ""), "")
	fs.StringVar(&c.APITLSName, "api-tls-name", e("WAZUHMCP_API_TLS_NAME", ""), "")
	fs.StringVar(&c.IndexerTLSName, "indexer-tls-name", e("WAZUHMCP_INDEXER_TLS_NAME", ""), "")
	fs.BoolVar(&c.Insecure, "insecure-skip-verify", envBool(env("WAZUHMCP_INSECURE")), "")
	fs.StringVar(&autonomy, "autonomy", e("WAZUHMCP_AUTONOMY", "readonly"), "")
	fs.StringVar(&actions, "autonomy-action", e("WAZUHMCP_AUTONOMY_ACTIONS", ""), "")
	fs.StringVar(&protIPs, "protected-ips", e("WAZUHMCP_PROTECTED_IPS", ""), "")
	fs.StringVar(&protAgents, "protected-agents", e("WAZUHMCP_PROTECTED_AGENTS", ""), "")
	fs.IntVar(&maxHour, "max-per-hour", envInt(env("WAZUHMCP_MAX_PER_HOUR"), 10), "")
	fs.IntVar(&maxAgents, "max-agents", envInt(env("WAZUHMCP_MAX_AGENTS"), 5), "")
	fs.StringVar(&planTTL, "plan-ttl", e("WAZUHMCP_PLAN_TTL", "30m"), "")
	fs.StringVar(&c.AuditFile, "audit-file", e("WAZUHMCP_AUDIT_FILE", defaultAudit()), "")
	fs.StringVar(&blockCmds, "block-commands", e("WAZUHMCP_BLOCK_COMMANDS", "300=firewall-drop300,3600=firewall-drop3600"), "")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	var err error
	if c.Autonomy, err = policy.ParseLevel(autonomy); err != nil {
		return nil, err
	}
	if c.AutonomyActions, err = policy.ParseOverrides(actions); err != nil {
		return nil, err
	}
	c.ProtectedIPs = split(protIPs)
	c.ProtectedAgents = split(protAgents)
	if c.BlockCommands, err = ParseBlockCommands(blockCmds); err != nil {
		return nil, err
	}
	c.MaxPerHour, c.MaxAgents = maxHour, maxAgents
	if c.PlanTTL, err = time.ParseDuration(planTTL); err != nil || c.PlanTTL <= 0 {
		return nil, fmt.Errorf("invalid -plan-ttl %q", planTTL)
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	if c.APIUser == "" || c.APIPassword == "" {
		return errors.New("Wazuh API credentials missing: set WAZUHMCP_API_USER (or -api-user) and WAZUHMCP_API_PASSWORD")
	}
	if c.IndexerUser == "" || c.IndexerPassword == "" {
		return errors.New("Wazuh Indexer credentials missing: set WAZUHMCP_INDEXER_USER (or -indexer-user) and WAZUHMCP_INDEXER_PASSWORD")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("-tls-cert and -tls-key must be set together")
	}
	if c.Token != "" && c.Token == c.AdminToken {
		return errors.New("-token and -admin-token must be different: the AI must not hold the admin credential")
	}
	if c.MaxPerHour <= 0 || c.MaxAgents <= 0 {
		return errors.New("-max-per-hour and -max-agents must be positive")
	}
	return nil
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envBool(v string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b
}

func envInt(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func defaultAudit() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".local", "state", "wazuhmcp", "audit.jsonl")
	}
	return "audit.jsonl"
}

var commandNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ParseBlockCommands parses "300=firewall-drop300,3600=firewall-drop3600".
// Names starting with "!" (custom scripts) are refused on purpose: only
// commands defined in the manager's configuration may be run.
func ParseBlockCommands(s string) (map[int]string, error) {
	out := map[int]string{}
	for _, part := range split(s) {
		k, v, ok := strings.Cut(part, "=")
		secs, err := strconv.Atoi(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok || err != nil || secs <= 0 {
			return nil, fmt.Errorf("invalid -block-commands entry %q (want seconds=command)", part)
		}
		if !commandNameRe.MatchString(v) {
			return nil, fmt.Errorf("invalid active-response command name %q", v)
		}
		out[secs] = v
	}
	if len(out) == 0 {
		return nil, errors.New("-block-commands must define at least one duration")
	}
	return out, nil
}
