// Package audit writes an append-only JSON-lines log of every response
// action: who proposed, approved, executed, and what Wazuh answered.
//
// Secrets (tokens, passwords) are never passed to this package. Entries carry
// only plan metadata.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one audit record.
type Entry struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"` // "mcp" or "admin"
	Event   string    `json:"event"` // propose, approve, reject, execute, expire, ...
	PlanID  string    `json:"plan_id,omitempty"`
	Action  string    `json:"action,omitempty"`
	Level   string    `json:"level,omitempty"` // effective autonomy level at the time
	Params  any       `json:"params,omitempty"`
	OK      bool      `json:"ok"`
	Message string    `json:"message,omitempty"`
}

// Logger appends entries to a file. A nil *Logger discards everything.
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// Open opens (creating if needed) an append-only audit file with mode 0600.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{f: f}, nil
}

// Log writes one entry. Errors are returned so callers can refuse to act
// when the audit trail cannot be written.
func (l *Logger) Log(e Entry) error {
	if l == nil {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(append(b, '\n'))
	return err
}

// Close closes the file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	return l.f.Close()
}
