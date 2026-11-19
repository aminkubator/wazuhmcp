package indexer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	if _, err := windowMinutes(s); err != nil {
		return "", err
	}
	return "now-" + strings.TrimSpace(s), nil
}

func windowMinutes(s string) (int, error) {
	m := windowRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("invalid time window %q (use forms like 15m, 6h, 7d)", s)
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
		return 0, fmt.Errorf("time window out of range (1m to 30d)")
	}
	return mins, nil
}

// Start is the beginning of the filter's period.
func (f AlertFilter) Start(now time.Time) (time.Time, error) {
	if f.From != "" {
		return ParseTime(f.From)
	}
	win := f.Window
	if win == "" {
		win = "1h"
	}
	mins, err := windowMinutes(win)
	return now.Add(-time.Duration(mins) * time.Minute), err
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
	Window   string // default "1h"; ignored when From is set
	From     string // absolute start, RFC3339 or YYYY-MM-DD (UTC)
	To       string // absolute end, same forms; default now
	MinLevel int    // rule.level >= MinLevel
	AgentID  string
	// ExcludeAgentID drops alerts raised on this agent (only AttackerProfileQuery).
	ExcludeAgentID string
	Group          string // rule.groups, e.g. authentication_failed
	RuleID         string
	SrcIP          string
	MitreID        string // e.g. T1110
	Text           string // simple match on rule.description and full_log
	Limit          int
}

var alertFields = []string{
	"@timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
	"rule.mitre", "agent.id", "agent.name", "agent.ip", "data.srcip", "data.dstip",
	"data.srcuser", "data.dstuser", "location", "decoder.name", "full_log",
}

func (f AlertFilter) filters() ([]any, error) {
	rng, err := f.timeRange()
	if err != nil {
		return nil, err
	}
	fl := []any{map[string]any{"range": map[string]any{"@timestamp": rng}}}
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

// timeRange returns the @timestamp range: absolute (From/To) or relative (Window).
func (f AlertFilter) timeRange() (map[string]any, error) {
	if f.From == "" {
		if f.To != "" {
			return nil, fmt.Errorf("to needs from")
		}
		win := f.Window
		if win == "" {
			win = "1h"
		}
		from, err := ParseWindow(win)
		if err != nil {
			return nil, err
		}
		return map[string]any{"gte": from}, nil
	}
	from, err := ParseTime(f.From)
	if err != nil {
		return nil, err
	}
	rng := map[string]any{"gte": from.Format(time.RFC3339)}
	if f.To != "" {
		to, err := ParseTime(f.To)
		if err != nil {
			return nil, err
		}
		if !to.After(from) {
			return nil, fmt.Errorf("to must be after from")
		}
		rng["lte"] = to.Format(time.RFC3339)
	}
	return rng, nil
}

// ParseTime accepts RFC3339 ("2026-11-01T08:00:00Z", "...+07:00") or a date
// ("2026-11-01", read as 00:00 UTC). The result is in UTC.
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q (use 2026-11-01 or 2026-11-01T08:00:00Z)", s)
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
			"top_srcips": topTerms("data.srcip", 20),
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

// ---------------------------------------------------------------------------
// Investigation queries
// ---------------------------------------------------------------------------

// TimelineMax caps one timeline page; entries are compact (no full_log).
const TimelineMax = 100

var timelineFields = []string{
	"@timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
	"rule.mitre.id", "rule.mitre.tactic", "agent.id", "agent.name", "data.srcip",
	"data.dstip", "data.srcuser", "data.dstuser", "syscheck.path", "syscheck.event",
}

// TimelineQuery returns alerts oldest first. cursor is the value a previous
// page returned (empty for the first page). Sorting on the alert "id" breaks
// ties between alerts of the same millisecond so paging never skips one.
func TimelineQuery(f AlertFilter, cursor string) (map[string]any, error) {
	fl, err := f.filters()
	if err != nil {
		return nil, err
	}
	size := f.Limit
	if size <= 0 {
		size = 50
	}
	if size > TimelineMax {
		size = TimelineMax
	}
	q := map[string]any{
		"size": size,
		"sort": []any{
			map[string]any{"@timestamp": "asc"},
			map[string]any{"id": map[string]any{"order": "asc", "unmapped_type": "keyword"}},
		},
		"_source": timelineFields,
		"query":   map[string]any{"bool": map[string]any{"filter": fl}},
	}
	if cursor != "" {
		after, err := DecodeCursor(cursor)
		if err != nil {
			return nil, err
		}
		q["search_after"] = after
	}
	return q, nil
}

// EncodeCursor turns the sort values of the last hit into an opaque cursor.
func EncodeCursor(sort []any) string {
	if len(sort) != 2 {
		return ""
	}
	b, _ := json.Marshal(sort)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor validates a cursor: exactly [epoch-millis number, id string].
func DecodeCursor(c string) ([]any, error) {
	bad := fmt.Errorf("invalid cursor (pass next_cursor from the previous page unchanged)")
	if len(c) > 256 {
		return nil, bad
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, bad
	}
	var v []any
	if json.Unmarshal(b, &v) != nil || len(v) != 2 {
		return nil, bad
	}
	if _, ok := v[0].(float64); !ok {
		return nil, bad
	}
	if id, ok := v[1].(string); !ok || (id != "" && !idRe.MatchString(id)) {
		return nil, bad
	}
	return v, nil
}

func termsAgg(field string, n int) map[string]any {
	return map[string]any{"terms": map[string]any{"field": field, "size": n}}
}

// firstLast adds first_seen / last_seen to an aggregation.
func firstLast(agg map[string]any, extra map[string]any) map[string]any {
	sub := map[string]any{
		"first_seen": map[string]any{"min": map[string]any{"field": "@timestamp"}},
		"last_seen":  map[string]any{"max": map[string]any{"field": "@timestamp"}},
	}
	for k, v := range extra {
		sub[k] = v
	}
	agg["aggs"] = sub
	return agg
}

func groupFilter(groups ...string) map[string]any {
	return map[string]any{"terms": map[string]any{"rule.groups": groups}}
}

// loginSuccess matches successful logins. A login that follows a brute force
// is raised as rule 40112 (groups syslog, attacks) INSTEAD of the normal
// authentication_success rule, so that rule id must be included explicitly.
var loginSuccess = map[string]any{"bool": map[string]any{
	"should":               []any{groupFilter("authentication_success"), term("rule.id", "40112")},
	"minimum_should_match": 1,
}}

// AttackerProfileQuery summarises everything one source IP did: when, which
// agents, which MITRE techniques, which users, and whether a login succeeded.
// f.SrcIP is required.
func AttackerProfileQuery(f AlertFilter) (map[string]any, error) {
	if f.SrcIP == "" {
		return nil, fmt.Errorf("srcip is required")
	}
	fl, err := f.filters()
	if err != nil {
		return nil, err
	}
	query := map[string]any{"filter": fl}
	if f.ExcludeAgentID != "" {
		if !agentRe.MatchString(f.ExcludeAgentID) {
			return nil, fmt.Errorf("invalid agent id %q", f.ExcludeAgentID)
		}
		query["must_not"] = []any{term("agent.id", f.ExcludeAgentID)}
	}
	return map[string]any{
		"size":  0,
		"query": map[string]any{"bool": query},
		"aggs": map[string]any{
			"first_seen": map[string]any{"min": map[string]any{"field": "@timestamp"}},
			"last_seen":  map[string]any{"max": map[string]any{"field": "@timestamp"}},
			"agents_targeted": firstLast(termsAgg("agent.id", 50), map[string]any{
				"name":      termsAgg("agent.name", 1),
				"max_level": map[string]any{"max": map[string]any{"field": "rule.level"}},
			}),
			"techniques": firstLast(termsAgg("rule.mitre.id", 30), map[string]any{
				"tactic": termsAgg("rule.mitre.tactic", 3),
			}),
			"rule_groups":  termsAgg("rule.groups", 20),
			"target_users": termsAgg("data.dstuser", 20),
			"source_users": termsAgg("data.srcuser", 20),
			"top_rules": firstLast(termsAgg("rule.id", 15), map[string]any{
				"description": termsAgg("rule.description", 1),
				"max_level":   map[string]any{"max": map[string]any{"field": "rule.level"}},
			}),
			"successful_logins": map[string]any{
				"filter": loginSuccess,
				"aggs": map[string]any{
					"agents": firstLast(termsAgg("agent.name", 20), map[string]any{
						"users": termsAgg("data.dstuser", 5),
					}),
				},
			},
			"by_level": termsAgg("rule.level", 15),
		},
	}, nil
}

// interestingGroups are rule groups that point at a compromise on a host.
var interestingGroups = []string{
	"authentication_success", "authentication_failed", "invalid_login", "adduser",
	"addgroup", "sudo", "su", "syscheck", "rootcheck", "attack", "exploit_attempt",
	"web", "sql_injection", "virus", "malware", "audit_command", "firewall_drop",
}

// HostActivityQuery summarises the alerts of one agent: notable groups, file
// changes, logins (and from where) and rootcheck findings. f.AgentID is required.
func HostActivityQuery(f AlertFilter) (map[string]any, error) {
	if f.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	fl, err := f.filters()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": fl}},
		"aggs": map[string]any{
			"by_level": termsAgg("rule.level", 15),
			"notable_groups": firstLast(map[string]any{"terms": map[string]any{
				"field": "rule.groups", "size": len(interestingGroups), "include": interestingGroups,
			}}, nil),
			"top_rules": firstLast(termsAgg("rule.id", 15), map[string]any{
				"description": termsAgg("rule.description", 1),
				"max_level":   map[string]any{"max": map[string]any{"field": "rule.level"}},
			}),
			"logins": map[string]any{
				"filter": loginSuccess,
				"aggs": map[string]any{
					"from_ip": firstLast(termsAgg("data.srcip", 20), map[string]any{"users": termsAgg("data.dstuser", 5)}),
				},
			},
			"failed_logins": map[string]any{
				"filter": groupFilter("authentication_failed", "invalid_login"),
				"aggs":   map[string]any{"from_ip": termsAgg("data.srcip", 10)},
			},
			"file_changes": map[string]any{
				"filter": groupFilter("syscheck"),
				"aggs": map[string]any{
					"paths": firstLast(termsAgg("syscheck.path", 25), map[string]any{"event": termsAgg("syscheck.event", 3)}),
				},
			},
			"rootcheck": map[string]any{
				"filter": groupFilter("rootcheck"),
				"aggs":   map[string]any{"findings": termsAgg("rule.description", 10)},
			},
		},
	}, nil
}
