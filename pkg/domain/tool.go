package domain

import "encoding/json"

// ToolDefinition represents a tool as returned by the tools/list method.
type ToolDefinition struct {
	Name        string          `json:"name"`                  // Unique name identifying the tool
	Description string          `json:"description,omitempty"` // Human-readable description of what the tool does
	InputSchema json.RawMessage `json:"inputSchema"`           // Raw JSON Schema. Preserved as RawMessage for exact formatting & schema pinning
}

// ToolCall represents an invocation request for the tools/call method.
type ToolCall struct {
	ID        string         // toolCallId (from the tools/call request)
	Name      string         // Name of the tool to invoke
	Arguments map[string]any // Parsed arguments, ready for direct evaluation in CEL
}

// ContentBlock represents a single content unit in a tool response (text, image, or resource).
type ContentBlock struct {
	Type     string // "text", "image", or "resource"
	Text     string // Main text payload (subject to DLP scanning)
	MimeType string // MIME type for binary data or resources
	Data     string // Base64-encoded payload or URI
}

// ToolResult represents the response returned after a tool execution.
type ToolResult struct {
	Content []ContentBlock // Array of content blocks returned by the tool
	IsError bool           // Indicates whether the tool execution failed
}

// TextResult is a convenience helper to quickly construct a text-based ToolResult.
func TextResult(text string) ToolResult {
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
		IsError: false,
	}
}
