package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	mcpadapter "github.com/primetz/mcpsg/internal/adapter/primary/mcp"
	"github.com/primetz/mcpsg/internal/adapter/secondary/mcpproxy"
	"github.com/primetz/mcpsg/internal/adapter/secondary/policy"
	"github.com/primetz/mcpsg/internal/core/service"
	"github.com/primetz/mcpsg/pkg/domain"
	"github.com/primetz/mcpsg/pkg/port"
)

// simpleStderrLogger is a minimal outgoing audit adapter (writes strictly to stderr to avoid breaking stdio).
type simpleStderrLogger struct {
	logger *log.Logger // Underlying logger instance
}

func (l *simpleStderrLogger) Log(_ context.Context, e domain.SecurityEvent) {
	l.logger.Printf("[AUDIT] phase=%s tool=%s action=%s reason=%q\n", e.Phase, e.ToolName, e.Action, e.Reason)
}

// main assembles the dependency graph and starts the MCP Security Gateway.
func main() {
	// Route all technical output strictly to os.Stderr
	stderrLog := log.New(os.Stderr, "[mcpsg] ", log.LstdFlags)

	policyPath := flag.String("policy", "policy.yaml", "Path to security policy YAML file")
	modeFlag := flag.String("mode", "enforce", "Gateway mode: enforce or audit")
	flag.Parse()

	// Extract target MCP server command and arguments following flags
	upstreamArgs := flag.Args()
	if len(upstreamArgs) == 0 {
		stderrLog.Fatalln("Usage: mcpsg --policy policy.yaml [--mode enforce|audit] -- <command> [args...]")
	}

	// Create context with signal handling for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 1. Initialize outgoing policy adapter (YAML + CEL)
	var policyEval port.PolicyEvaluator
	if *policyPath != "" {
		eval, err := policy.NewCELEvaluatorFromFile(*policyPath)
		if err != nil {
			stderrLog.Fatalf("Failed to load policy: %v\n", err)
		}
		policyEval = eval
	}

	// 2. Initialize outgoing target MCP server adapter (child process)
	upstreamCmd := upstreamArgs[0]
	var upstreamCmdArgs []string
	if len(upstreamArgs) > 1 {
		upstreamCmdArgs = upstreamArgs[1:]
	}

	proxyExecutor, err := mcpproxy.NewStdioProxy(ctx, upstreamCmd, os.Environ(), upstreamCmdArgs...)
	if err != nil {
		stderrLog.Fatalf("Failed to start upstream MCP server: %v\n", err)
	}
	defer func() {
		stderrLog.Println("Shutting down upstream MCP server...")
		_ = proxyExecutor.Close()
	}()

	// 3. Assemble the Security Core
	auditLogger := &simpleStderrLogger{logger: stderrLog}
	gatewayCore := service.NewSecurityGateway(
		service.Config{Mode: service.Mode(*modeFlag)},
		proxyExecutor,
		policyEval,
		nil, // Placeholder for future DLPScanner integration
		nil, // Placeholder for future PinStore integration (Rug Pull protection)
		auditLogger,
	)

	// 4. Start the incoming adapter (MCP Stdio Server)
	stdioSrv := mcpadapter.NewStdioServer("mcp-security-gateway", "0.1.0", gatewayCore)
	stderrLog.Printf("Starting MCP Security Gateway in %q mode...\n", *modeFlag)

	if err := stdioSrv.SyncAndServe(ctx); err != nil {
		stderrLog.Fatalf("Gateway stopped with error: %v\n", err)
	}
}
