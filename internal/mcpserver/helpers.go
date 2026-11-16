package mcpserver

import (
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func boolPtr(b bool) *bool { return &b }

// readOnly marks a tool that never changes anything in Wazuh or on disk.
func readOnly() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}
}

// additive marks a tool that only records something (a plan), without
// touching Wazuh agents.
func additive() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)}
}

// impactful marks a tool that changes the monitored environment.
func impactful() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)}
}

// Limits for text that comes from monitored systems.
const (
	maxFieldLen   = 600  // normal fields
	maxFullLogLen = 1500 // full_log
)

// sanitize makes data from logs safer to hand to a model: it strips control
// characters (including ANSI escapes) and clips long strings, recursively.
// Log content is attacker-controlled; it can still contain text that looks
// like instructions, which is why the server instructions tell the client to
// treat every field as data. Sanitizing only limits size and hides escapes.
func sanitize(v any) any {
	return sanitizeKey("", v)
}

func sanitizeKey(key string, v any) any {
	switch t := v.(type) {
	case string:
		limit := maxFieldLen
		if key == "full_log" {
			limit = maxFullLogLen
		}
		return clip(cleanText(t), limit)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = sanitizeKey(k, val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = sanitizeKey(key, val)
		}
		return out
	default:
		return v
	}
}

func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…[truncated]"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
