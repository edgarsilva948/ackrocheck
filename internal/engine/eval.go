// Package engine evaluates declarative policy assertions against parsed
// resource documents. It never executes user-provided code.
package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

// Result is the three-valued outcome of an assertion or policy evaluation.
// Unknown means the value is templated (e.g. a KRO "${...}" expression) and
// cannot be statically verified.
type Result int

// Evaluation results.
const (
	Pass Result = iota
	Fail
	Unknown
)

// Outcome is the result of evaluating a full policy against a resource.
type Outcome struct {
	Result   Result
	Messages []string
}

// Evaluate runs all policy assertions (logical AND) against a resource
// document. The document is treated as untrusted data.
func Evaluate(p *policy.Policy, doc map[string]interface{}) Outcome {
	results := make([]Result, 0, len(p.Assertions))
	var messages []string
	for i := range p.Assertions {
		r, msg := evalAssertion(&p.Assertions[i], doc)
		results = append(results, r)
		if r != Pass && msg != "" {
			messages = append(messages, msg)
		}
	}
	return Outcome{Result: combineAnd(results), Messages: messages}
}

// combineAnd: any Fail -> Fail, else any Unknown -> Unknown, else Pass.
func combineAnd(results []Result) Result {
	out := Pass
	for _, r := range results {
		if r == Fail {
			return Fail
		}
		if r == Unknown {
			out = Unknown
		}
	}
	return out
}

// combineOr: any Pass -> Pass, else any Unknown -> Unknown, else Fail.
func combineOr(results []Result) Result {
	out := Fail
	for _, r := range results {
		if r == Pass {
			return Pass
		}
		if r == Unknown {
			out = Unknown
		}
	}
	return out
}

func evalAssertion(a *policy.Assertion, doc interface{}) (Result, string) {
	r, msg := evalOperator(a, doc)
	if r != Pass && a.Message != "" {
		msg = a.Message
	}
	return r, msg
}

func evalOperator(a *policy.Assertion, doc interface{}) (Result, string) {
	value, found := resolvePath(doc, a.Path)

	switch a.Operator {
	case policy.OpExists:
		if found {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s is not set", a.Path)
	case policy.OpNotExists:
		if !found {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s is set but should not be", a.Path)
	case policy.OpAny, policy.OpAll:
		return evalCombinator(a, value, found)
	}

	// Value-comparing operators below. Missing fields fail "positive"
	// operators and pass "negative" ones.
	if !found {
		switch a.Operator {
		case policy.OpNotEquals, policy.OpNotContains, policy.OpNotMatchRegex:
			return Pass, ""
		default:
			return Fail, fmt.Sprintf("%s is not set (expected %s %v)", a.Path, a.Operator, a.Value)
		}
	}
	if IsDynamicValue(value) {
		return Unknown, fmt.Sprintf("%s is the templated expression %q and cannot be statically verified", a.Path, value)
	}

	switch a.Operator {
	case policy.OpEquals:
		if looseEquals(value, a.Value) {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s is %v (expected %v)", a.Path, display(value), display(a.Value))
	case policy.OpNotEquals:
		if !looseEquals(value, a.Value) {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s must not be %v", a.Path, display(a.Value))
	case policy.OpIsTrue:
		if value == true {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s is %v (expected true)", a.Path, display(value))
	case policy.OpIsFalse:
		if value == false {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s is %v (expected false)", a.Path, display(value))
	case policy.OpGreaterThan, policy.OpGreaterThanOrEqual, policy.OpLessThan, policy.OpLessThanOrEqual:
		return evalNumeric(a, value)
	case policy.OpContains:
		if containsValue(value, a.Value) {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s does not contain %v", a.Path, display(a.Value))
	case policy.OpNotContains:
		if !containsValue(value, a.Value) {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s must not contain %v", a.Path, display(a.Value))
	case policy.OpMatchRegex, policy.OpNotMatchRegex:
		return evalRegex(a, value)
	}
	return Fail, fmt.Sprintf("unsupported operator %q", a.Operator)
}

// evalCombinator handles `any` and `all`.
//
// When the value at path is a list, they act as quantifiers: an element
// matches when ALL nested assertions pass against it; `any` passes when at
// least one element matches, `all` passes when every element matches (an
// empty or missing list passes `all` and fails `any`).
//
// When the value is not a list (a map, a scalar, or the document itself via
// path "."), they act as logical combinators over the nested assertions:
// `any` is OR, `all` is AND.
func evalCombinator(a *policy.Assertion, value interface{}, found bool) (Result, string) {
	if !found {
		if a.Operator == policy.OpAll {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s is not set", a.Path)
	}

	if list, ok := value.([]interface{}); ok {
		results := make([]Result, 0, len(list))
		var firstDetail string
		for i, el := range list {
			elResults := make([]Result, 0, len(a.Assertions))
			var elMsgs []string
			for j := range a.Assertions {
				r, msg := evalAssertion(&a.Assertions[j], el)
				elResults = append(elResults, r)
				if r != Pass && msg != "" {
					elMsgs = append(elMsgs, msg)
				}
			}
			er := combineAnd(elResults)
			results = append(results, er)
			if er != Pass && firstDetail == "" && len(elMsgs) > 0 {
				firstDetail = fmt.Sprintf("%s[%d]: %s", a.Path, i, strings.Join(elMsgs, "; "))
			}
		}
		if a.Operator == policy.OpAny {
			r := combineOr(results)
			if r == Fail {
				return Fail, fmt.Sprintf("no element of %s matches the expected conditions", a.Path)
			}
			return r, ""
		}
		r := combineAnd(results)
		if r != Pass {
			return r, firstDetail
		}
		return Pass, ""
	}

	// Non-list: logical combinator over nested assertions.
	results := make([]Result, 0, len(a.Assertions))
	var msgs []string
	for i := range a.Assertions {
		r, msg := evalAssertion(&a.Assertions[i], value)
		results = append(results, r)
		if r != Pass && msg != "" {
			msgs = append(msgs, msg)
		}
	}
	if a.Operator == policy.OpAny {
		r := combineOr(results)
		if r == Fail {
			return Fail, fmt.Sprintf("none of the alternatives passed: %s", strings.Join(msgs, "; "))
		}
		return r, ""
	}
	r := combineAnd(results)
	if r != Pass && len(msgs) > 0 {
		return r, strings.Join(msgs, "; ")
	}
	return r, ""
}

func evalNumeric(a *policy.Assertion, value interface{}) (Result, string) {
	got, ok1 := toFloat(value)
	want, ok2 := toFloat(a.Value)
	if !ok1 || !ok2 {
		return Fail, fmt.Sprintf("%s is %v, which is not comparable to %v", a.Path, display(value), display(a.Value))
	}
	var pass bool
	switch a.Operator {
	case policy.OpGreaterThan:
		pass = got > want
	case policy.OpGreaterThanOrEqual:
		pass = got >= want
	case policy.OpLessThan:
		pass = got < want
	case policy.OpLessThanOrEqual:
		pass = got <= want
	}
	if pass {
		return Pass, ""
	}
	return Fail, fmt.Sprintf("%s is %v (expected %s %v)", a.Path, display(value), strings.ReplaceAll(string(a.Operator), "_", " "), display(a.Value))
}

func evalRegex(a *policy.Assertion, value interface{}) (Result, string) {
	pattern, _ := a.Value.(string)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Fail, fmt.Sprintf("invalid regex %q: %v", pattern, err)
	}
	s := stringify(value)
	matched := re.MatchString(s)
	if a.Operator == policy.OpMatchRegex {
		if matched {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("%s value %q does not match %q", a.Path, s, pattern)
	}
	if !matched {
		return Pass, ""
	}
	return Fail, fmt.Sprintf("%s value %q must not match %q", a.Path, s, pattern)
}

// resolvePath resolves a path against doc. The path "." refers to the
// current document/element itself.
func resolvePath(doc interface{}, path string) (interface{}, bool) {
	if path == "." {
		return doc, true
	}
	return Resolve(doc, path)
}

func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// looseEquals compares two values with YAML-friendly coercions: numbers are
// compared numerically across int/float/string forms, and the strings
// "true"/"false" compare equal to booleans.
func looseEquals(a, b interface{}) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a == b {
		return true
	}
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if aok && bok {
		return af == bf
	}
	if ab, ok := a.(bool); ok {
		if s, ok := b.(string); ok {
			return strings.EqualFold(s, strconv.FormatBool(ab))
		}
	}
	if bb, ok := b.(bool); ok {
		if s, ok := a.(string); ok {
			return strings.EqualFold(s, strconv.FormatBool(bb))
		}
	}
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	return false
}

// containsValue implements the `contains` operator: substring for strings,
// membership for lists, key presence for maps.
func containsValue(container, val interface{}) bool {
	switch c := container.(type) {
	case string:
		return strings.Contains(c, stringify(val))
	case []interface{}:
		for _, el := range c {
			if looseEquals(el, val) {
				return true
			}
		}
		return false
	case map[string]interface{}:
		key, ok := val.(string)
		if !ok {
			return false
		}
		_, present := c[key]
		return present
	default:
		return false
	}
}

func stringify(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func display(v interface{}) string {
	if s, ok := v.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%v", v)
}
