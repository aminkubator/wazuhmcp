package indexer

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Hard caps so one tool call can never pull an unbounded amount of data.
const (
	MaxLimit     = 50
	DefaultLimit = 20
	maxWindow    = 30 * 24 * 60 // minutes
)

var (
	windowRe = regexp.MustCompile(`^(\d{1,4})([mhd])$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9_\-.:]{1,128}$`)
	cveRe    = regexp.MustCompile(`^(?i)CVE-\d{4}-\d{4,10}$`)
	agentRe  = regexp.MustCompile(`^\d{3,}$`)
	groupRe  = regexp.MustCompile(`^[A-Za-z0-9_\-.]{1,64}$`)
	mitreRe  = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
)

// ParseWindow turns "15m", "6h" or "7d" into an OpenSearch date-math string
// ("now-15m"). The maximum is 30 days.
func ParseWindow(s string) (string, error) {
	m := windowRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", fmt.Errorf("invalid time window %q (use forms like 15m, 6h, 7d)", s)
	}
	n, _ := strconv.Atoi(m[1])
	mins := n
	switch m[2] {
	case "h":
		mins = n * 60
	case "d":
		mins = n * 60 * 24
	}
	if n == 0 || mins > maxWindow {
		return "", fmt.Errorf("time window out of range (1m to 30d)")
	}
	return "now-" + m[1] + m[2], nil
}

// ClampLimit applies the default and the maximum.
func ClampLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	if n > MaxLimit {
		return MaxLimit
	}
	return n
}

// AlertFilter selects alerts. Empty fields are ignored.
type AlertFilter struct {
	Window   string // default "1h"
	MinLevel int    // rule.level >= MinLevel
	AgentID  string
	Group    string // rule.groups, e.g. authentication_failed
	RuleID   string
	SrcIP    string
	MitreID  string // e.g. T1110
	Text     string // simple match on rule.description and full_log
	Limit    int
}

var alertFields = []string{
	"@timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
	"rule.mitre", "agent.id", "agent.name", "agent.ip", "data.srcip", "data.dstip",
	"data.srcuser", "data.dstuser", "location", "decoder.name", "full_log",
}

func (f AlertFilter) filters() ([]any, error) {
	win := f.Window
	if win == "" {
		win = "1h"
	}
	from, err := ParseWindow(win)
	if err != nil {
		return nil, err
	}
	fl := []any{map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": from}}}}
	if f.MinLevel > 0 {
		if f.MinLevel > 15 {
			return nil, fmt.Errorf("min_level must be 1-15")
		}
		fl = append(fl, map[string]any{"range": map[string]any{"rule.level": map[string]any{"gte": f.MinLevel}}})
	}
	if f.AgentID != "" {
		if !agentRe.MatchString(f.AgentID) {
			return nil, fmt.Errorf("invalid agent_id %q", f.AgentID)
		}
		fl = append(fl, term("agent.id", f.AgentID))
	}
	if f.Group != "" {
		if !groupRe.MatchString(f.Group) {
			return nil, fmt.Errorf("invalid group %q", f.Group)
		}
		fl = append(fl, term("rule.groups", f.Group))
	}
	if f.RuleID != "" {
		if !idRe.MatchString(f.RuleID) {
			return nil, fmt.Errorf("invalid rule_id %q", f.RuleID)
		}
		fl = append(fl, term("rule.id", f.RuleID))
	}
	if f.SrcIP != "" {
		if _, err := netip.ParseAddr(f.SrcIP); err != nil {
			return nil, fmt.Errorf("invalid srcip %q", f.SrcIP)
		}
		fl = append(fl, term("data.srcip", f.SrcIP))
	}
	if f.MitreID != "" {
		if !mitreRe.MatchString(f.MitreID) {
			return nil, fmt.Errorf("invalid mitre_id %q (e.g. T1110)", f.MitreID)
		}
		fl = append(fl, term("rule.mitre.id", f.MitreID))
	}
	if f.Text != "" {
		if len(f.Text) > 200 {
			return nil, fmt.Errorf("text too long (max 200 characters)")
		}
		fl = append(fl, map[string]any{"simple_query_string": map[string]any{
			"query":            f.Text,
			"fields":           []string{"rule.description", "full_log"},
			"default_operator": "and",
		}})
	}
	return fl, nil
}

func term(field, value string) map[string]any {
	return map[string]any{"term": map[string]any{field: value}}
}

// AlertsQuery builds a search for the newest alerts matching f.
func AlertsQuery(f AlertFilter) (map[string]any, error) {
	fl, err := f.filters()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"size":    ClampLimit(f.Limit),
		"sort":    []any{map[string]any{"@timestamp": "desc"}},
		"_source": alertFields,
		"query":   map[string]any{"bool": map[string]any{"filter": fl}},
	}, nil
}

// AlertSummaryQuery builds aggregations: top rules, agents, source IPs and an
// activity histogram over the window.
func AlertSummaryQuery(f AlertFilter) (map[string]any, error) {
	fl, err := f.filters()
	if err != nil {
		return nil, err
	}
	topTerms := func(field string, n int) map[string]any {
		return map[string]any{"terms": map[string]any{"field": field, "size": n}}
	}
	return map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": fl}},
		"aggs": map[string]any{
			"top_rules": map[string]any{
				"terms": map[string]any{"field": "rule.id", "size": 10},
				"aggs": map[string]any{
					"description": topTerms("rule.description", 1),
					"max_level":   map[string]any{"max": map[string]any{"field": "rule.level"}},
				},
			},
			"top_agents": topTerms("agent.name", 10),
			"top_srcips": topTerms("data.srcip", 10),
			"top_mitre":  topTerms("rule.mitre.id", 10),
			"by_level":   topTerms("rule.level", 15),
			"over_time":  map[string]any{"auto_date_histogram": map[string]any{"field": "@timestamp", "buckets": 12}},
		},
	}, nil
}

// AlertByIDQuery fetches one alert by document id.
func AlertByIDQuery(id string) (map[string]any, error) {
	if !idRe.MatchString(id) {
		return nil, fmt.Errorf("invalid alert id %q", id)
	}
	return map[string]any{
		"size":  1,
		"query": map[string]any{"ids": map[string]any{"values": []string{id}}},
	}, nil
}

// VulnFilter selects vulnerability findings.
type VulnFilter struct {
	AgentID  string
	Severity string // Critical, High, Medium, Low (case-insensitive)
	CVE      string
	Package  string
	Limit    int
}

var vulnFields = []string{
	"agent.id", "agent.name", "package.name", "package.version", "package.type",
	"vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
	"vulnerability.description", "vulnerability.reference",
	"vulnerability.detected_at", "vulnerability.published_at",
}

func (f VulnFilter) filters() ([]any, error) {
	fl := []any{}
	if f.AgentID != "" {
		if !agentRe.MatchString(f.AgentID) {
			return nil, fmt.Errorf("invalid agent_id %q", f.AgentID)
		}
		fl = append(fl, term("agent.id", f.AgentID))
	}
	if f.Severity != "" {
		sev := strings.ToUpper(f.Severity[:1]) + strings.ToLower(f.Severity[1:])
		switch sev {
		case "Critical", "High", "Medium", "Low":
		default:
			return nil, fmt.Errorf("severity must be Critical, High, Medium or Low")
		}
		fl = append(fl, term("vulnerability.severity", sev))
	}
	if f.CVE != "" {
		if !cveRe.MatchString(f.CVE) {
			return nil, fmt.Errorf("invalid CVE id %q", f.CVE)
		}
		fl = append(fl, term("vulnerability.id", strings.ToUpper(f.CVE)))
	}
	if f.Package != "" {
		if len(f.Package) > 128 {
			return nil, fmt.Errorf("package name too long")
		}
		fl = append(fl, term("package.name", f.Package))
	}
	return fl, nil
}

// VulnQuery builds a search for findings, highest CVSS first.
func VulnQuery(f VulnFilter) (map[string]any, error) {
	fl, err := f.filters()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"size":    ClampLimit(f.Limit),
		"sort":    []any{map[string]any{"vulnerability.score.base": map[string]any{"order": "desc", "unmapped_type": "float"}}},
		"_source": vulnFields,
		"query":   map[string]any{"bool": map[string]any{"filter": fl}},
	}, nil
}

// VulnSummaryQuery counts findings per severity and the most affected agents
// and packages.
func VulnSummaryQuery(f VulnFilter) (map[string]any, error) {
	fl, err := f.filters()
	if err != nil {
		return nil, err
	}
	t := func(field string, n int) map[string]any {
		return map[string]any{"terms": map[string]any{"field": field, "size": n}}
	}
	return map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": fl}},
		"aggs": map[string]any{
			"by_severity":  t("vulnerability.severity", 5),
			"top_agents":   t("agent.name", 10),
			"top_packages": t("package.name", 10),
			"top_cves":     t("vulnerability.id", 10),
		},
	}, nil
}
