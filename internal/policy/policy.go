// Package policy defines the declarative control schema and validation.
package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Operator is a supported assertion operator.
type Operator string

// Supported assertion operators.
const (
	OpExists             Operator = "exists"
	OpNotExists          Operator = "not_exists"
	OpEquals             Operator = "equals"
	OpNotEquals          Operator = "not_equals"
	OpIsTrue             Operator = "is_true"
	OpIsFalse            Operator = "is_false"
	OpGreaterThan        Operator = "greater_than"
	OpGreaterThanOrEqual Operator = "greater_than_or_equal"
	OpLessThan           Operator = "less_than"
	OpLessThanOrEqual    Operator = "less_than_or_equal"
	OpContains           Operator = "contains"
	OpNotContains        Operator = "not_contains"
	OpMatchRegex         Operator = "match_regex"
	OpNotMatchRegex      Operator = "not_match_regex"
	OpAny                Operator = "any"
	OpAll                Operator = "all"
)

var validOperators = map[Operator]bool{
	OpExists: true, OpNotExists: true,
	OpEquals: true, OpNotEquals: true,
	OpIsTrue: true, OpIsFalse: true,
	OpGreaterThan: true, OpGreaterThanOrEqual: true,
	OpLessThan: true, OpLessThanOrEqual: true,
	OpContains: true, OpNotContains: true,
	OpMatchRegex: true, OpNotMatchRegex: true,
	OpAny: true, OpAll: true,
}

// Assertion is a single declarative field check. For `any`/`all` operators,
// nested assertions are evaluated against each element of the list at `path`.
type Assertion struct {
	Path       string      `yaml:"path" json:"path"`
	Operator   Operator    `yaml:"operator" json:"operator"`
	Value      interface{} `yaml:"value,omitempty" json:"value,omitempty"`
	Assertions []Assertion `yaml:"assertions,omitempty" json:"assertions,omitempty"`
	// Message optionally overrides the failure message for this assertion.
	Message string `yaml:"message,omitempty" json:"message,omitempty"`
}

// ResourceRef describes the cloud resource a control targets.
type ResourceRef struct {
	Provider string `yaml:"provider" json:"provider"`
	Service  string `yaml:"service" json:"service"`
	Type     string `yaml:"type" json:"type"`
}

// Match selects which Kubernetes resources a control applies to.
type Match struct {
	APIGroups []string `yaml:"apiGroups" json:"apiGroups"`
	Kinds     []string `yaml:"kinds" json:"kinds"`
	// ProductionOnly restricts the control to resources marked as production
	// via labels (environment: prod|production, env: prod|production) or the
	// annotation ackrocheck.dev/environment: production.
	ProductionOnly bool `yaml:"productionOnly,omitempty" json:"productionOnly,omitempty"`
}

// Remediation describes how to fix a failed control.
type Remediation struct {
	Message string                 `yaml:"message" json:"message"`
	Patch   map[string]interface{} `yaml:"patch,omitempty" json:"patch,omitempty"`
}

// Reference points to an external standard or rule.
type Reference struct {
	Type string `yaml:"type" json:"type"`
	ID   string `yaml:"id" json:"id"`
}

// Compatibility tracks control lifecycle metadata.
type Compatibility struct {
	Status       string `yaml:"status" json:"status"`
	IntroducedIn string `yaml:"introducedIn" json:"introducedIn"`
}

// Policy is a single declarative security control.
type Policy struct {
	ID            string        `yaml:"id" json:"id"`
	Title         string        `yaml:"title" json:"title"`
	Description   string        `yaml:"description" json:"description"`
	Severity      Severity      `yaml:"severity" json:"severity"`
	Category      string        `yaml:"category" json:"category"`
	Resource      ResourceRef   `yaml:"resource" json:"resource"`
	Match         Match         `yaml:"match" json:"match"`
	Assertions    []Assertion   `yaml:"assertions" json:"assertions"`
	Remediation   Remediation   `yaml:"remediation" json:"remediation"`
	References    []Reference   `yaml:"references,omitempty" json:"references,omitempty"`
	Compatibility Compatibility `yaml:"compatibility,omitempty" json:"compatibility,omitempty"`
	// Notes documents assumptions and limitations of the control.
	Notes string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

var policyIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

// Validate checks the policy for structural problems. It normalizes the
// severity in place.
func (p *Policy) Validate() error {
	var errs []error
	if p.ID == "" {
		errs = append(errs, errors.New("missing id"))
	} else if !policyIDPattern.MatchString(p.ID) {
		errs = append(errs, fmt.Errorf("invalid id %q: must match %s", p.ID, policyIDPattern))
	}
	if p.Title == "" {
		errs = append(errs, errors.New("missing title"))
	}
	sev, err := ParseSeverity(string(p.Severity))
	if err != nil {
		errs = append(errs, err)
	} else {
		p.Severity = sev
	}
	if len(p.Match.APIGroups) == 0 {
		errs = append(errs, errors.New("match.apiGroups must not be empty"))
	}
	if len(p.Match.Kinds) == 0 {
		errs = append(errs, errors.New("match.kinds must not be empty"))
	}
	if len(p.Assertions) == 0 {
		errs = append(errs, errors.New("assertions must not be empty"))
	}
	for i := range p.Assertions {
		if err := validateAssertion(&p.Assertions[i]); err != nil {
			errs = append(errs, fmt.Errorf("assertion %d: %w", i, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("policy %s: %w", orUnknown(p.ID), errors.Join(errs...))
	}
	return nil
}

func validateAssertion(a *Assertion) error {
	if a.Path == "" {
		return errors.New("missing path")
	}
	if !validOperators[a.Operator] {
		return fmt.Errorf("unknown operator %q", a.Operator)
	}
	switch a.Operator {
	case OpAny, OpAll:
		if len(a.Assertions) == 0 {
			return fmt.Errorf("operator %q requires nested assertions", a.Operator)
		}
		for i := range a.Assertions {
			if err := validateAssertion(&a.Assertions[i]); err != nil {
				return fmt.Errorf("nested assertion %d: %w", i, err)
			}
		}
	case OpMatchRegex, OpNotMatchRegex:
		s, ok := a.Value.(string)
		if !ok {
			return fmt.Errorf("operator %q requires a string value", a.Operator)
		}
		if _, err := regexp.Compile(s); err != nil {
			return fmt.Errorf("operator %q has invalid regex: %w", a.Operator, err)
		}
	case OpGreaterThan, OpGreaterThanOrEqual, OpLessThan, OpLessThanOrEqual:
		if a.Value == nil {
			return fmt.Errorf("operator %q requires a numeric value", a.Operator)
		}
	case OpEquals, OpNotEquals, OpContains, OpNotContains:
		if a.Value == nil {
			return fmt.Errorf("operator %q requires a value", a.Operator)
		}
	}
	return nil
}

// Matches reports whether the policy applies to a resource with the given
// API group and kind.
func (p *Policy) Matches(apiGroup, kind string) bool {
	groupOK := false
	for _, g := range p.Match.APIGroups {
		if strings.EqualFold(g, apiGroup) {
			groupOK = true
			break
		}
	}
	if !groupOK {
		return false
	}
	for _, k := range p.Match.Kinds {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "<unknown>"
	}
	return s
}
