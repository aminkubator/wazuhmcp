// Package app wires clients, policy, response service, MCP server and the
// admin REST API into one HTTP server.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"wazuhmcp/internal/audit"
	"wazuhmcp/internal/auth"
	"wazuhmcp/internal/config"
	"wazuhmcp/internal/mcpserver"
	"wazuhmcp/internal/plans"
	"wazuhmcp/internal/policy"
	"wazuhmcp/internal/response"
	"wazuhmcp/internal/wazuh/api"
	"wazuhmcp/internal/wazuh/indexer"
)

// Server is a configured HTTP server.
type Server struct {
	cfg        *config.Config
	log        *slog.Logger
	svc        *response.Service
	aud        *audit.Logger
	http       *http.Server
	ln         net.Listener
	Token      string
	AdminToken string
	TokensNew  [2]bool // generated: [mcp, admin]
	stopReaper context.CancelFunc
}

// New builds a Server from cfg without starting it.
func New(cfg *config.Config, version string, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{cfg: cfg, log: logger, Token: cfg.Token, AdminToken: cfg.AdminToken}
	var err error
	if s.Token == "" {
		if s.Token, err = randomToken(); err != nil {
			return nil, err
		}
		s.TokensNew[0] = true
	}
	if s.AdminToken == "" {
		if s.AdminToken, err = randomToken(); err != nil {
			return nil, err
		}
		s.TokensNew[1] = true
	}

	mgr, err := api.New(api.Options{BaseURL: cfg.APIURL, User: cfg.APIUser, Password: cfg.APIPassword,
		CAFile: cfg.CAFile, InsecureSkipVerify: cfg.Insecure, TLSServerName: cfg.APITLSName})
	if err != nil {
		return nil, err
	}
	idx, err := indexer.New(indexer.Options{BaseURL: cfg.IndexerURL, User: cfg.IndexerUser, Password: cfg.IndexerPassword,
		CAFile: cfg.CAFile, InsecureSkipVerify: cfg.Insecure, TLSServerName: cfg.IndexerTLSName})
	if err != nil {
		return nil, err
	}
	if cfg.Insecure {
		logger.Warn("TLS verification is disabled (-insecure-skip-verify); prefer -ca-file")
	}

	cmds := response.Commands{Block: cfg.BlockCommands}
	pol, err := policy.New(policy.Config{
		AllowedTTLs: cmds.TTLs(),
		Default:     cfg.Autonomy, Overrides: cfg.AutonomyActions,
		ProtectedIPs: cfg.ProtectedIPs, ProtectedAgents: cfg.ProtectedAgents,
		MaxPerHour: cfg.MaxPerHour, MaxAgents: cfg.MaxAgents,
	})
	if err != nil {
		return nil, err
	}
	warnRisky(logger, pol)

	if pol.MaxLevel() > policy.ReadOnly {
		if s.aud, err = audit.Open(cfg.AuditFile); err != nil {
			return nil, err
		}
	}
	s.svc = response.New(pol, plans.NewStore(cfg.PlanTTL), s.aud, mgr, cmds, logger)

	mcpSrv := mcpserver.New(mcpserver.Deps{Manager: mgr, Indexer: idx, Response: s.svc, Logger: logger}, version)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv },
		&mcp.StreamableHTTPOptions{Logger: logger})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.Handle("/mcp", auth.New(s.Token, "wazuhmcp").Protect(mcpHandler))
	mux.Handle("/admin/", auth.New(s.AdminToken, "wazuhmcp-admin").Protect(http.StripPrefix("/admin", s.adminAPI())))

	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return s, nil
}

func warnRisky(l *slog.Logger, p *policy.Policy) {
	for _, a := range policy.Actions() {
		lvl := p.LevelFor(a.Action)
		if lvl == policy.Auto && a.Risk != policy.RiskLow {
			l.Warn("autonomy auto on a non-low-risk action", "action", a.Action, "risk", a.Risk)
		}
	}
}

// Start listens and serves in the background.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	if host, _, _ := net.SplitHostPort(s.cfg.Addr); !isLoopback(host) {
		s.log.Warn("listening on a non-loopback address; tokens travel in plain HTTP, put a TLS reverse proxy in front", "addr", s.cfg.Addr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stopReaper = cancel
	go s.reapLoop(ctx)
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("http server stopped", "err", err)
		}
	}()
	return nil
}

func (s *Server) reapLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.svc.Reap(ctx)
		}
	}
}

// Shutdown stops the server and closes the audit log.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.stopReaper != nil {
		s.stopReaper()
	}
	err := s.http.Shutdown(ctx)
	_ = s.aud.Close()
	return err
}

// Addr is the actual listen address.
func (s *Server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.cfg.Addr
}

// Service exposes the response service (used by tests).
func (s *Server) Service() *response.Service { return s.svc }

// Handler exposes the HTTP handler (used by tests).
func (s *Server) Handler() http.Handler { return s.http.Handler }

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func randomToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ---------------------------------------------------------------------------
// Admin REST API (humans): list, approve, reject and execute plans.
// ---------------------------------------------------------------------------

func (s *Server) adminAPI() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /plans", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"plans": s.svc.Plans(plans.Status(r.URL.Query().Get("status")))})
	})
	mux.HandleFunc("GET /plans/{id}", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.svc.Plan(r.PathValue("id"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	mux.HandleFunc("POST /plans/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.svc.Decide(response.ActorAdmin, r.PathValue("id"), true)
		reply(w, p, err)
	})
	mux.HandleFunc("POST /plans/{id}/reject", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.svc.Decide(response.ActorAdmin, r.PathValue("id"), false)
		reply(w, p, err)
	})
	mux.HandleFunc("POST /plans/{id}/execute", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.svc.Execute(r.Context(), response.ActorAdmin, r.PathValue("id"))
		reply(w, p, err)
	})
	mux.HandleFunc("GET /blocks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"blocks": s.svc.ActiveBlocks()})
	})
	return mux
}

func reply(w http.ResponseWriter, p plans.Plan, err error) {
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusConflict
	switch {
	case errors.Is(err, plans.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, plans.ErrExpired):
		code = http.StatusGone
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
