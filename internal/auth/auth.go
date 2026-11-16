// Package auth implements shared-secret token authentication
// (Authorization: Bearer or X-API-Key). The server uses two independent
// instances: one for MCP clients (the AI) and one for the admin API (humans),
// so the AI's token can never approve a plan.
package auth

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

// Authenticator validates one shared secret.
type Authenticator struct {
	token string
	realm string
}

// New returns an Authenticator for token.
func New(token, realm string) *Authenticator { return &Authenticator{token: token, realm: realm} }

// Check reports whether the request carries the right credential.
func (a *Authenticator) Check(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		if a.equal(strings.TrimSpace(h[7:])) {
			return true
		}
	}
	return a.equal(r.Header.Get("X-API-Key"))
}

func (a *Authenticator) equal(got string) bool {
	if got == "" || a.token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}

// Protect rejects requests without a valid credential with a JSON 401.
func (a *Authenticator) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Check(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+a.realm+`"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	})
}
