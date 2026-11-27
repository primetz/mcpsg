package port

import (
	"context"

	"github.com/primetz/mcpsg/pkg/domain"
)

// ToolExecutor abstracts the tool source (external process, remote MCP, or Go functions).
type ToolExecutor interface {
	// ListTools fetches the available tools from the underlying source.
	ListTools(ctx context.Context) ([]domain.ToolDefinition, error)

	// Execute invokes the tool with the given call payload and returns the result.
	Execute(ctx context.Context, call domain.ToolCall) (domain.ToolResult, error)

	// Close gracefully terminates the underlying connection or process and releases associated resources.
	Close() error
}

// PolicyEvaluator evaluates access rules and validates arguments (powered by CEL + YAML).
type PolicyEvaluator interface {
	// IsToolVisible checks if a tool should be exposed in the tools/list response.
	IsToolVisible(ctx context.Context, secCtx domain.SecurityContext, toolName string) bool

	// EvaluateCall assesses a specific tool invocation with arguments before execution.
	EvaluateCall(ctx context.Context, secCtx domain.SecurityContext, call domain.ToolCall) (domain.Action, string, error)
}

// DLPScanner scans and sanitizes outbound content for secrets and injections.
type DLPScanner interface {
	// ScanAndSanitize inspects the tool result, masks sensitive data if needed, and reports findings.
	ScanAndSanitize(ctx context.Context, result domain.ToolResult) (sanitized domain.ToolResult, triggered bool, findings []string, err error)
}

// PinStore manages tool definition hash storage and verification (defense against Rug Pulls).
type PinStore interface {
	// VerifyOrPin checks if the tool definition matches a stored hash, or registers it if new.
	VerifyOrPin(ctx context.Context, tool domain.ToolDefinition) error
}

// AuditLogger records security events for compliance and debugging.
type AuditLogger interface {
	// Log persists a security event to the configured storage backend.
	Log(ctx context.Context, event domain.SecurityEvent)
}
