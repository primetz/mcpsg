package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cel.dev/cel-go/cel"
	"github.com/primetz/mcpsg/pkg/domain"
	"github.com/primetz/mcpsg/pkg/port"
	"gopkg.in/yaml.v3"
)

// YAML DTOs for configuration parsing.
type yamlConfig struct {
	Settings struct {
		DefaultAction string `yaml:"default_action"` // Global fallback action
	} `yaml:"settings"`
	Rules []yamlRule `yaml:"rules"` // List of policy rules
}

type yamlRule struct {
	Name       string   `yaml:"name"`    // Rule identifier
	Tools      []string `yaml:"tools"`   // Tool name patterns (supports glob matching)
	Action     string   `yaml:"action"`  // Default action when conditions are not met
	Message    string   `yaml:"message"` // Denial message shown to LLM
	Conditions []struct {
		Expr    string `yaml:"expr"`    // CEL expression to evaluate
		Message string `yaml:"message"` // Error message if condition fails
	} `yaml:"conditions"`
}

// Compiled rule for fast execution at runtime.
type compiledRule struct {
	name       string              // Rule name
	patterns   []string            // Glob patterns for tool matching
	action     domain.Action       // Action to take when conditions pass
	message    string              // Custom denial message
	conditions []compiledCondition // Pre-compiled CEL programs
}

type compiledCondition struct {
	program cel.Program // Compiled CEL program
	message string      // Condition failure message
}

// celEvaluator implements the port.PolicyEvaluator interface.
type celEvaluator struct {
	defaultAction domain.Action  // Fallback action when no rule matches
	rules         []compiledRule // Ordered list of compiled policy rules
}

// NewCELEvaluatorFromFile reads YAML config and pre-compiles all CEL expressions.
func NewCELEvaluatorFromFile(path string) (port.PolicyEvaluator, error) {
	data, err := os.ReadFile(path) // Read policy configuration file
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var cfg yamlConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}

	// Create CEL environment with available variables (args and subject)
	env, err := cel.NewEnv(
		cel.Variable("args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("subject", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("create cel env: %w", err)
	}

	defAction := domain.ActionDeny
	if cfg.Settings.DefaultAction == "allow" {
		defAction = domain.ActionAllow
	}

	eval := &celEvaluator{
		defaultAction: defAction,
		rules:         make([]compiledRule, 0, len(cfg.Rules)),
	}

	for _, r := range cfg.Rules {
		cr := compiledRule{
			name:     r.Name,
			patterns: r.Tools,
			action:   domain.Action(r.Action),
			message:  r.Message,
		}

		for _, c := range r.Conditions {
			ast, issues := env.Compile(c.Expr)
			if issues != nil && issues.Err() != nil {
				return nil, fmt.Errorf("rule %q CEL compile error (%s): %w", r.Name, c.Expr, issues.Err())
			}
			prog, err := env.Program(ast)
			if err != nil {
				return nil, fmt.Errorf("rule %q CEL program error: %w", r.Name, err)
			}
			cr.conditions = append(cr.conditions, compiledCondition{
				program: prog,
				message: c.Message,
			})
		}
		eval.rules = append(eval.rules, cr)
	}

	return eval, nil
}

// IsToolVisible determines whether a tool should be exposed in tools/list.
func (e *celEvaluator) IsToolVisible(_ context.Context, _ domain.SecurityContext, toolName string) bool {
	rule := e.matchRule(toolName)
	if rule == nil {
		return e.defaultAction == domain.ActionAllow
	}

	// If rule explicitly denies tool without conditions, hide from list
	if rule.action == domain.ActionDeny && len(rule.conditions) == 0 {
		return false
	}

	return true
}

// EvaluateCall checks tool invocation and arguments via CEL.
func (e *celEvaluator) EvaluateCall(_ context.Context, secCtx domain.SecurityContext, call domain.ToolCall) (domain.Action, string, error) {
	rule := e.matchRule(call.Name)
	if rule == nil {
		if e.defaultAction == domain.ActionAllow {
			return domain.ActionAllow, "", nil
		}
		return domain.ActionDeny, fmt.Sprintf("tool %q is not allowed by default policy", call.Name), nil
	}

	if rule.action == domain.ActionDeny && len(rule.conditions) == 0 {
		msg := rule.message
		if msg == "" {
			msg = fmt.Sprintf("tool %q is explicitly denied by rule %q", call.Name, rule.name)
		}
		return domain.ActionDeny, msg, nil
	}

	// Safely initialize args if LLM passed null/empty arguments
	args := call.Arguments
	if args == nil {
		args = map[string]any{}
	}

	// Evaluate all CEL conditions for the rule
	for _, cond := range rule.conditions {
		out, _, err := cond.program.Eval(map[string]any{
			"args":    args,
			"subject": secCtx.Subject,
		})
		if err != nil {
			// Evaluation error (e.g., accessing non-existent field) is treated as denial (Fail-Closed)
			return domain.ActionDeny, fmt.Sprintf("policy condition failed: %v", err), nil
		}

		allowed, ok := out.Value().(bool)
		if !ok || !allowed {
			msg := cond.message
			if msg == "" {
				msg = fmt.Sprintf("arguments violated policy rule %q", rule.name)
			}
			return domain.ActionDeny, msg, nil
		}
	}

	return domain.ActionAllow, "", nil
}

// matchRule finds the first matching rule for a given tool name.
func (e *celEvaluator) matchRule(toolName string) *compiledRule {
	for i := range e.rules {
		for _, pattern := range e.rules[i].patterns {
			if matched, _ := filepath.Match(pattern, toolName); matched {
				return &e.rules[i]
			}
		}
	}
	return nil
}
