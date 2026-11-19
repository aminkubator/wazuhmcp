// Command wazuhmcp is an MCP server to read what Wazuh sees (attacks,
// vulnerabilities) and to respond, with a configurable level of AI autonomy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wazuhmcp/internal/app"
	"wazuhmcp/internal/config"
)

// version is set at build time: -ldflags "-X main.version=..."
var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		if err := serve(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Print(config.Usage)
				return
			}
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "version", "--version":
		fmt.Println("wazuhmcp", version)
	case "help", "-h", "--help":
		fmt.Print(config.Usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, config.Usage)
		os.Exit(2)
	}
}

func serve(args []string) error {
	cfg, err := config.Parse(args, os.Getenv, os.Stderr)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	srv, err := app.New(cfg, version, logger)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	banner(srv, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func banner(s *app.Server, cfg *config.Config) {
	e := os.Stderr
	fmt.Fprintf(e, "\nWazuhMCP %s\n", version)
	scheme := "http"
	if cfg.TLSCert != "" {
		scheme = "https"
	}
	fmt.Fprintf(e, "  MCP:        %s://%s/mcp\n", scheme, s.Addr())
	fmt.Fprintf(e, "  admin API:  %s://%s/admin/plans\n", scheme, s.Addr())
	fmt.Fprintf(e, "  autonomy:   %s", cfg.Autonomy)
	for a, l := range cfg.AutonomyActions {
		fmt.Fprintf(e, "  %s=%s", a, l)
	}
	fmt.Fprintln(e)
	if s.TokensNew[0] {
		fmt.Fprintf(e, "  mcp token:  %s  (generated for this run)\n", s.Token)
	}
	if s.TokensNew[1] {
		fmt.Fprintf(e, "  admin token: %s  (generated for this run; keep it away from the AI client)\n", s.AdminToken)
	}
	fmt.Fprintln(e)
}
