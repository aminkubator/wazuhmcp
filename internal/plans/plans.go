// Package plans stores response plans and their lifecycle.
//
// A plan is a concrete, validated action (action + parameters + reason)
// created by the AI or a human. Plans are what a human approves and what the
// executor runs. The store is in memory: pending plans do not survive a
// restart, which is deliberate (a stale plan should not run after a reboot).
// Every state change is recorded in the audit log, which is persistent.
package plans

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"wazuhmcp/internal/policy"
)

// Status is where a plan is in its lifecycle.
type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Rejected Status = "rejected"
	Executed Status = "executed"
	Failed   Status = "failed"
)

// Plan is one proposed response action.
type Plan struct {
	ID        string        `json:"id"`
	Action    policy.Action `json:"action"`
	Params    policy.Params `json:"params"`
	Reason    string        `json:"reason"`
	Source    string        `json:"source,omitempty"` // alert id or CVE that motivated it
	Risk      policy.Risk   `json:"risk"`
	Status    Status        `json:"status"`
	CreatedBy string        `json:"created_by"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	DecidedBy string        `json:"decided_by,omitempty"`
	DecidedAt *time.Time    `json:"decided_at,omitempty"`
	Result    string        `json:"result,omitempty"`
}

// Errors returned by the store.
var (
	ErrNotFound = errors.New("plan not found")
	ErrExpired  = errors.New("plan expired")
)

// Store keeps plans in memory.
type Store struct {
	mu    sync.Mutex
	plans map[string]*Plan
	ttl   time.Duration
	now   func() time.Time
}

// NewStore creates a store whose plans expire after ttl (default 30 minutes).
func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Store{plans: map[string]*Plan{}, ttl: ttl, now: time.Now}
}

// Create adds a new pending plan.
func (s *Store) Create(p Plan) (Plan, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Plan{}, err
	}
	now := s.now()
	p.ID = "plan-" + hex.EncodeToString(b[:])
	p.Status = Pending
	p.CreatedAt = now
	p.ExpiresAt = now.Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	s.plans[p.ID] = &p
	return p, nil
}

// Get returns a copy of a plan.
func (s *Store) Get(id string) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok {
		return Plan{}, ErrNotFound
	}
	return *p, nil
}

// List returns plans newest first, optionally filtered by status.
func (s *Store) List(status Status) []Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(s.now())
	var out []Plan
	for _, p := range s.plans {
		if status == "" || p.Status == status {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Decide moves a pending plan to approved or rejected.
func (s *Store) Decide(id, by string, approve bool) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok {
		return Plan{}, ErrNotFound
	}
	now := s.now()
	if now.After(p.ExpiresAt) {
		return *p, ErrExpired
	}
	if p.Status != Pending {
		return *p, fmt.Errorf("plan is %s, only pending plans can be decided", p.Status)
	}
	if approve {
		p.Status = Approved
	} else {
		p.Status = Rejected
	}
	p.DecidedBy, p.DecidedAt = by, &now
	return *p, nil
}

// Claim atomically marks a plan as being executed so the same plan can never
// run twice, even with concurrent calls. needApproved requires the Approved
// status; otherwise Pending or Approved is accepted. On success the plan is
// returned still marked Approved/Pending removed: its status becomes Executed
// only through Finish.
func (s *Store) Claim(id string, needApproved bool) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok {
		return Plan{}, ErrNotFound
	}
	if s.now().After(p.ExpiresAt) {
		return *p, ErrExpired
	}
	switch {
	case p.Status == Approved:
	case p.Status == Pending && !needApproved:
	case p.Status == Pending:
		return *p, fmt.Errorf("plan %s is pending: a human must approve it first", id)
	default:
		return *p, fmt.Errorf("plan is %s and cannot be executed", p.Status)
	}
	// Mark as executed immediately; Finish may turn it into Failed.
	p.Status = Executed
	return *p, nil
}

// Finish records the outcome of an executed plan.
func (s *Store) Finish(id string, err error, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok {
		return
	}
	if err != nil {
		p.Status = Failed
		p.Result = err.Error()
		return
	}
	p.Status = Executed
	p.Result = result
}

// prune drops finished plans a day after they expired. Caller holds s.mu.
func (s *Store) prune(now time.Time) {
	for id, p := range s.plans {
		if now.After(p.ExpiresAt.Add(24 * time.Hour)) {
			delete(s.plans, id)
		}
	}
}
