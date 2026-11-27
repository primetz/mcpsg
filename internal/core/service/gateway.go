package service

import (
	"context"
	"fmt"
	"time"

	"github.com/primetz/mcpsg/pkg/domain"
	"github.com/primetz/mcpsg/pkg/port"
)

// Mode defines the gateway operation mode: enforcement or audit-only.
type Mode string

const (
	ModeEnforce Mode = "enforce" // Enforces policies and blocks violations
	ModeAudit   Mode = "audit"   // Logs violations but allows execution (dry-run)
)

// Config holds the core behavior settings.
type Config struct {
	Mode Mode
}

// securityGateway implements the port.SecurityGateway interface.
type securityGateway struct {
	cfg      Config               // Gateway configuration
	executor port.ToolExecutor    // Tool execution adapter
	policy   port.PolicyEvaluator // Policy evaluation engine (CEL/YAML)
	dlp      port.DLPScanner      // Data loss prevention scanner
	pinStore port.PinStore        // Tool definition hash verifier
	audit    port.AuditLogger     // Security event logger
}

// NewSecurityGateway assembles the core from provided outgoing port implementations.
func NewSecurityGateway(
	cfg Config,
	executor port.ToolExecutor,
	policy port.PolicyEvaluator,
	dlp port.DLPScanner,
	pinStore port.PinStore,
	audit port.AuditLogger,
) port.SecurityGateway {
	if cfg.Mode == "" {
		cfg.Mode = ModeEnforce
	}
	return &securityGateway{
		cfg:      cfg,
		executor: executor,
		policy:   policy,
		dlp:      dlp,
		pinStore: pinStore,
		audit:    audit,
	}
}

// ListTools fetches tools from the executor, filters by policy, and verifies hashes (Pinning).
func (g *securityGateway) ListTools(ctx context.Context, secCtx domain.SecurityContext) ([]domain.ToolDefinition, error) {
	rawTools, err := g.executor.ListTools(ctx) // Fetch raw tool list from upstream
	if err != nil {
		return nil, fmt.Errorf("upstream list tools failed: %w", err)
	}

	allowedTools := make([]domain.ToolDefinition, 0, len(rawTools)) // Initialize filtered results slice

	for _, tool := range rawTools {
		// 1. Check tool visibility against policy rules
		if g.policy != nil && !g.policy.IsToolVisible(ctx, secCtx, tool.Name) {
			g.logEvent(ctx, "tools/list", tool.Name, domain.ActionDeny, "hidden by policy", nil)
			continue
		}

		// 2. Verify schema and description integrity (Rug Pull protection)
		if g.pinStore != nil {
			if err := g.pinStore.VerifyOrPin(ctx, tool); err != nil {
				g.logEvent(ctx, "tools/list", tool.Name, domain.ActionDeny, err.Error(), nil)
				if g.cfg.Mode == ModeEnforce {
					// In enforce mode, hide compromised tools from the LLM
					continue
				}
			}
		}

		allowedTools = append(allowedTools, tool)
	}

	return allowedTools, nil
}

// CallTool executes the full verification cycle: Pre-flight -> Execution -> Post-flight (DLP).
func (g *securityGateway) CallTool(ctx context.Context, secCtx domain.SecurityContext, call domain.ToolCall) (domain.ToolResult, error) {
	// STAGE 1: Pre-flight policy and argument validation (CEL)
	if g.policy != nil {
		action, reason, err := g.policy.EvaluateCall(ctx, secCtx, call)
		if err != nil {
			return domain.ToolResult{}, fmt.Errorf("policy evaluation error: %w", err)
		}

		if action == domain.ActionDeny {
			g.logEvent(ctx, "pre_call", call.Name, domain.ActionDeny, reason, map[string]any{
				"call_id": call.ID,
				"mode":    g.cfg.Mode,
			})

			if g.cfg.Mode == ModeEnforce {
				return domain.ToolResult{}, &domain.PolicyViolationError{
					Err:     domain.ErrAccessDenied,
					Message: reason,
				}
			}
			// In audit mode, log the violation and allow execution to proceed
		} else {
			g.logEvent(ctx, "pre_call", call.Name, domain.ActionAllow, "passed policy checks", map[string]any{
				"call_id": call.ID,
			})
		}
	}

	// STAGE 2: Tool execution via outgoing adapter
	result, err := g.executor.Execute(ctx, call)
	if err != nil {
		return domain.ToolResult{}, err
	}

	// STAGE 3: Post-flight response scanning (DLP / secret masking)
	if g.dlp != nil {
		sanitized, triggered, findings, err := g.dlp.ScanAndSanitize(ctx, result)
		if err != nil {
			if g.cfg.Mode == ModeEnforce {
				return domain.ToolResult{}, &domain.PolicyViolationError{
					Err:     domain.ErrDLPBlocked,
					Message: "Tool response blocked by DLP policy due to sensitive content",
				}
			}
		}

		if triggered {
			g.logEvent(ctx, "post_call", call.Name, domain.ActionRedact, "sensitive data detected in output", map[string]any{
				"call_id":  call.ID,
				"findings": findings,
				"mode":     g.cfg.Mode,
			})

			if g.cfg.Mode == ModeEnforce {
				result = sanitized // Mask sensitive data in enforce mode
			}
		}
	}

	return result, nil
}

// logEvent safely sends a security event to the AuditLogger if connected.
func (g *securityGateway) logEvent(ctx context.Context, phase, toolName string, action domain.Action, reason string, meta map[string]any) {
	if g.audit == nil {
		return
	}
	g.audit.Log(ctx, domain.SecurityEvent{
		Timestamp: time.Now().UTC(),
		Phase:     phase,
		ToolName:  toolName,
		Action:    action,
		Reason:    reason,
		Metadata:  meta,
	})
}
