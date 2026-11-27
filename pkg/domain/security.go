package domain

import "time"

// Action defines the decision made by the policy engine.
type Action string

const (
	ActionAllow  Action = "allow"  // Permits the requested action
	ActionDeny   Action = "deny"   // Blocks the requested action
	ActionWarn   Action = "warn"   // Used in audit mode (dry-run)
	ActionRedact Action = "redact" // Used for DLP masking
)

// SecurityContext carries metadata about the current session/agent (prepared for RBAC and multi-agent support).
type SecurityContext struct {
	SessionID string            // Unique session identifier
	Subject   string            // User or agent identifier
	Roles     []string          // Roles for future ABAC/RBAC evaluations
	Metadata  map[string]string // Additional headers or tags
}

// SecurityEvent describes a security event for transmission to the AuditLogger.
type SecurityEvent struct {
	Timestamp time.Time      // Event timestamp
	TraceID   string         // Distributed tracing identifier
	Phase     string         // "tools/list", "pre_call", "post_call"
	ToolName  string         // Name of the invoked tool
	RuleName  string         // Name of the matched policy rule
	Action    Action         // Decision taken by the policy engine
	Reason    string         // Human-readable explanation for the action
	Metadata  map[string]any // Additional event context or custom fields
}
