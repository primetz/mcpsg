package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/primetz/mcpsg/pkg/domain"
	"github.com/primetz/mcpsg/pkg/port"
)

// stdioProxy implements port.ToolExecutor by proxying calls to a child MCP process.
type stdioProxy struct {
	mcpClient *client.Client // Underlying MCP client for stdio communication
}

// NewStdioProxy spawns the target command and performs MCP initialization.
func NewStdioProxy(ctx context.Context, command string, env []string, args ...string) (port.ToolExecutor, error) {
	c, err := client.NewStdioMCPClient(command, env, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to start upstream process: %w", err)
	}

	// Perform mandatory MCP handshake with child server
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "mcp-security-gateway",
		Version: "0.1.0",
	}

	if _, err := c.Initialize(ctx, initReq); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("upstream mcp initialize failed: %w", err)
	}

	return &stdioProxy{mcpClient: c}, nil
}

// ListTools fetches the tool list from the child server and converts it to domain.ToolDefinition.
func (p *stdioProxy) ListTools(ctx context.Context) ([]domain.ToolDefinition, error) {
	resp, err := p.mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return nil, err
	}

	result := make([]domain.ToolDefinition, 0, len(resp.Tools))
	for _, t := range resp.Tools {
		schemaBytes, err := json.Marshal(t.InputSchema) // Serialize input schema to raw JSON bytes
		if err != nil {
			return nil, fmt.Errorf("marshal tool %q schema: %w", t.Name, err)
		}

		result = append(result, domain.ToolDefinition{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schemaBytes,
		})
	}

	return result, nil
}

// Execute forwards the approved tool invocation to the child server.
func (p *stdioProxy) Execute(ctx context.Context, call domain.ToolCall) (domain.ToolResult, error) {
	req := mcp.CallToolRequest{} // Construct MCP call request
	req.Params.Name = call.Name
	req.Params.Arguments = call.Arguments

	resp, err := p.mcpClient.CallTool(ctx, req) // Execute tool call via MCP client
	if err != nil {
		return domain.ToolResult{}, err
	}

	blocks := make([]domain.ContentBlock, 0, len(resp.Content)) // Initialize result content slice
	for _, item := range resp.Content {
		switch v := item.(type) {
		case mcp.TextContent:
			blocks = append(blocks, domain.ContentBlock{
				Type: "text",
				Text: v.Text,
			})
		case mcp.ImageContent:
			blocks = append(blocks, domain.ContentBlock{
				Type:     "image",
				MimeType: v.MIMEType,
				Data:     v.Data,
			})
		}
	}

	return domain.ToolResult{
		Content: blocks,
		IsError: resp.IsError,
	}, nil
}

// Close cleanly terminates the child process upon gateway shutdown.
func (p *stdioProxy) Close() error {
	if p.mcpClient != nil {
		return p.mcpClient.Close()
	}
	return nil
}
