package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/primetz/mcpsg/pkg/domain"
	"github.com/primetz/mcpsg/pkg/port"
)

// StdioServer wraps the MCP server and delegates all logic to the core incoming port (SecurityGateway).
type StdioServer struct {
	mcpServer *server.MCPServer    // Underlying MCP server instance
	gateway   port.SecurityGateway // Security gateway core
}

// NewStdioServer creates an incoming adapter over the security core.
func NewStdioServer(name, version string, gateway port.SecurityGateway) *StdioServer {
	s := server.NewMCPServer(
		name,
		version,
		server.WithToolCapabilities(true),
	)

	return &StdioServer{
		mcpServer: s,
		gateway:   gateway,
	}
}

// SyncAndServe fetches allowed tools from the core, registers them, and starts the stdio loop.
func (s *StdioServer) SyncAndServe(ctx context.Context) error {
	// Initialize base session context (local user for stdio)
	secCtx := domain.SecurityContext{
		SessionID: "local-stdio",
		Subject:   "local-user",
	}

	// 1. Fetch filtered and verified (Pinning) tool list from core
	tools, err := s.gateway.ListTools(ctx, secCtx)
	if err != nil {
		return fmt.Errorf("failed to list tools from gateway: %w", err)
	}

	// 2. Register each allowed tool in the MCP server
	for _, t := range tools {
		mcpTool := mcp.Tool{
			Name:        t.Name,
			Description: t.Description,
		}
		if len(t.InputSchema) > 0 {
			_ = json.Unmarshal(t.InputSchema, &mcpTool.InputSchema)
		}

		// Capture tool name for closure
		toolName := t.Name
		s.mcpServer.AddTool(mcpTool, func(callCtx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return s.handleToolCall(callCtx, secCtx, toolName, req)
		})
	}

	// 3. Start stdin/stdout listener (blocking call)
	return server.ServeStdio(s.mcpServer)
}

// handleToolCall translates MCP requests to core invocations and maps results/errors back.
func (s *StdioServer) handleToolCall(
	ctx context.Context,
	secCtx domain.SecurityContext,
	toolName string,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)

	call := domain.ToolCall{
		Name:      toolName,
		Arguments: args,
	}

	// Invoke security core (Pre-flight -> Execute -> Post-flight DLP)
	res, err := s.gateway.CallTool(ctx, secCtx, call)
	if err != nil {
		// If security policy blocks, return soft error for LLM (IsError: true)
		if policyErr, ok := errors.AsType[*domain.PolicyViolationError](err); ok {
			return mcp.NewToolResultError(fmt.Sprintf("[SECURITY BLOCK] %s", policyErr.Message)), nil
		}
		// If upstream server fails, return protocol error
		return nil, err
	}

	// Convert domain.ToolResult back to mcp-go format
	mcpContent := make([]mcp.Content, 0, len(res.Content))
	for _, block := range res.Content {
		switch block.Type {
		case "text":
			mcpContent = append(mcpContent, mcp.NewTextContent(block.Text))
		case "image":
			mcpContent = append(mcpContent, mcp.NewImageContent(block.Data, block.MimeType))
		}
	}

	return &mcp.CallToolResult{
		Content: mcpContent,
		IsError: res.IsError,
	}, nil
}
