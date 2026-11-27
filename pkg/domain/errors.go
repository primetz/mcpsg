package domain

import "errors"

var (
	// ErrAccessDenied is returned when a tool invocation is blocked by a rule or default policy.
	ErrAccessDenied = errors.New("tool execution denied by security policy")

	// ErrToolNotFound is returned when a tool is not found or restricted by policy.
	ErrToolNotFound = errors.New("tool not found or restricted")

	// ErrSchemaMismatch is returned when a tool definition hash mismatch is detected (potential rug pull).
	ErrSchemaMismatch = errors.New("tool definition hash mismatch (potential rug pull)")

	// ErrDLPBlocked is returned when a tool response contains secrets and block mode is enabled.
	ErrDLPBlocked = errors.New("tool response blocked due to sensitive data leak")
)

// PolicyViolationError wraps a domain error with a clear message for the LLM.
type PolicyViolationError struct {
	Err     error  // Underlying domain error
	Rule    string // Name of the triggered policy rule
	Message string // User-facing message shown to the LLM explaining the denial
}

// Error implements the error interface. Returns the user-facing message.
func (e *PolicyViolationError) Error() string {
	return e.Message
}

// Unwrap implements error unwrapping to preserve the underlying error chain.
func (e *PolicyViolationError) Unwrap() error {
	return e.Err
}
