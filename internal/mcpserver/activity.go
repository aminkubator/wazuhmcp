package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// activityMiddleware logs one line per tool call: name, outcome, duration.
// Arguments and results are never logged (they can hold IPs, hostnames and log
// excerpts); the audit log holds the details of response actions.
func activityMiddleware(logger *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			started := time.Now()
			res, err := next(ctx, method, req)
			name := "unknown"
			if r, ok := req.(*mcp.CallToolRequest); ok && r.Params != nil {
				name = r.Params.Name
			}
			failed := err != nil
			if r, ok := res.(*mcp.CallToolResult); ok && r != nil && r.IsError {
				failed = true
			}
			mark := "✓"
			if failed {
				mark = "✗"
			}
			msg := fmt.Sprintf("tool: %s %s %s", name, mark, time.Since(started).Round(time.Millisecond))
			if failed {
				logger.Warn(msg)
			} else {
				logger.Info(msg)
			}
			return res, err
		}
	}
}
