package port

import (
	"context"

	"github.com/primetz/mcpsg/pkg/domain"
)

// SecurityGateway defines the entry point to the security core.
type SecurityGateway interface {
	// ListTools returns a filtered list of available tools (respecting schema pinning and policy rules).
	ListTools(ctx context.Context, secCtx domain.SecurityContext) ([]domain.ToolDefinition, error)

	// CallTool performs pre-flight validation, invokes the tool, and sanitizes the response (post-flight).
	CallTool(ctx context.Context, secCtx domain.SecurityContext, call domain.ToolCall) (domain.ToolResult, error)
}
