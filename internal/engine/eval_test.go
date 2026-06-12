package engine

import (
	"testing"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

func doc(spec map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"spec": spec}
}

func evalOne(t *testing.T, a policy.Assertion, d map[string]interface{}) Result {
	t.Helper()
	p := &policy.Policy{Assertions: []policy.Assertion{a}}
	return Evaluate(p, d).Result
}

func TestOperators(t *testing.T) {
	tests := []struct {
		name      string
		assertion policy.Assertion
		doc       map[string]interface{}
		want      Result
	}{
		// exists / not_exists
		{"exists present", policy.Assertion{Path: "spec.key", Operator: policy.OpExists},
			doc(map[string]interface{}{"key": "v"}), Pass},
		{"exists missing", policy.Assertion{Path: "spec.key", Operator: policy.OpExists},
			doc(map[string]interface{}{}), Fail},
		{"exists nil value still exists", policy.Assertion{Path: "spec.key", Operator: policy.OpExists},
			doc(map[string]interface{}{"key": nil}), Pass},
		{"not_exists missing", policy.Assertion{Path: "spec.key", Operator: policy.OpNotExists},
			doc(map[string]interface{}{}), Pass},
		{"not_exists present", policy.Assertion{Path: "spec.key", Operator: policy.OpNotExists},
			doc(map[string]interface{}{"key": 1}), Fail},

		// equals / not_equals
		{"equals match", policy.Assertion{Path: "spec.v", Operator: policy.OpEquals, Value: "x"},
			doc(map[string]interface{}{"v": "x"}), Pass},
		{"equals mismatch", policy.Assertion{Path: "spec.v", Operator: policy.OpEquals, Value: "x"},
			doc(map[string]interface{}{"v": "y"}), Fail},
		{"equals missing fails", policy.Assertion{Path: "spec.v", Operator: policy.OpEquals, Value: "x"},
			doc(map[string]interface{}{}), Fail},
		{"equals numeric int float", policy.Assertion{Path: "spec.v", Operator: policy.OpEquals, Value: 7},
			doc(map[string]interface{}{"v": 7.0}), Pass},
		{"equals bool string", policy.Assertion{Path: "spec.v", Operator: policy.OpEquals, Value: true},
			doc(map[string]interface{}{"v": "true"}), Pass},
		{"not_equals mismatch", policy.Assertion{Path: "spec.v", Operator: policy.OpNotEquals, Value: true},
			doc(map[string]interface{}{"v": false}), Pass},
		{"not_equals match", policy.Assertion{Path: "spec.v", Operator: policy.OpNotEquals, Value: true},
			doc(map[string]interface{}{"v": true}), Fail},
		{"not_equals missing passes", policy.Assertion{Path: "spec.v", Operator: policy.OpNotEquals, Value: true},
			doc(map[string]interface{}{}), Pass},

		// is_true / is_false
		{"is_true true", policy.Assertion{Path: "spec.v", Operator: policy.OpIsTrue},
			doc(map[string]interface{}{"v": true}), Pass},
		{"is_true false", policy.Assertion{Path: "spec.v", Operator: policy.OpIsTrue},
			doc(map[string]interface{}{"v": false}), Fail},
		{"is_true missing fails", policy.Assertion{Path: "spec.v", Operator: policy.OpIsTrue},
			doc(map[string]interface{}{}), Fail},
		{"is_true string true fails", policy.Assertion{Path: "spec.v", Operator: policy.OpIsTrue},
			doc(map[string]interface{}{"v": "true"}), Fail},
		{"is_false false", policy.Assertion{Path: "spec.v", Operator: policy.OpIsFalse},
			doc(map[string]interface{}{"v": false}), Pass},
		{"is_false true", policy.Assertion{Path: "spec.v", Operator: policy.OpIsFalse},
			doc(map[string]interface{}{"v": true}), Fail},
		{"is_false missing fails", policy.Assertion{Path: "spec.v", Operator: policy.OpIsFalse},
			doc(map[string]interface{}{}), Fail},

		// numeric comparisons
		{"gt pass", policy.Assertion{Path: "spec.n", Operator: policy.OpGreaterThan, Value: 5},
			doc(map[string]interface{}{"n": 6}), Pass},
		{"gt fail equal", policy.Assertion{Path: "spec.n", Operator: policy.OpGreaterThan, Value: 5},
			doc(map[string]interface{}{"n": 5}), Fail},
		{"gte pass equal", policy.Assertion{Path: "spec.n", Operator: policy.OpGreaterThanOrEqual, Value: 7},
			doc(map[string]interface{}{"n": 7}), Pass},
		{"gte fail below", policy.Assertion{Path: "spec.n", Operator: policy.OpGreaterThanOrEqual, Value: 7},
			doc(map[string]interface{}{"n": 6}), Fail},
		{"gte missing fails", policy.Assertion{Path: "spec.n", Operator: policy.OpGreaterThanOrEqual, Value: 7},
			doc(map[string]interface{}{}), Fail},
		{"lt pass", policy.Assertion{Path: "spec.n", Operator: policy.OpLessThan, Value: 5},
			doc(map[string]interface{}{"n": 4}), Pass},
		{"lt fail", policy.Assertion{Path: "spec.n", Operator: policy.OpLessThan, Value: 5},
			doc(map[string]interface{}{"n": 5}), Fail},
		{"lte pass equal", policy.Assertion{Path: "spec.n", Operator: policy.OpLessThanOrEqual, Value: 5},
			doc(map[string]interface{}{"n": 5}), Pass},
		{"lte fail above", policy.Assertion{Path: "spec.n", Operator: policy.OpLessThanOrEqual, Value: 5},
			doc(map[string]interface{}{"n": 6}), Fail},
		{"numeric string coerced", policy.Assertion{Path: "spec.n", Operator: policy.OpGreaterThanOrEqual, Value: 7},
			doc(map[string]interface{}{"n": "14"}), Pass},
		{"non-numeric fails comparison", policy.Assertion{Path: "spec.n", Operator: policy.OpGreaterThan, Value: 5},
			doc(map[string]interface{}{"n": "abc"}), Fail},

		// contains / not_contains
		{"contains substring", policy.Assertion{Path: "spec.s", Operator: policy.OpContains, Value: "bc"},
			doc(map[string]interface{}{"s": "abcd"}), Pass},
		{"contains substring missing", policy.Assertion{Path: "spec.s", Operator: policy.OpContains, Value: "zz"},
			doc(map[string]interface{}{"s": "abcd"}), Fail},
		{"contains list member", policy.Assertion{Path: "spec.l", Operator: policy.OpContains, Value: "*"},
			doc(map[string]interface{}{"l": []interface{}{"a", "*"}}), Pass},
		{"contains list no member", policy.Assertion{Path: "spec.l", Operator: policy.OpContains, Value: "*"},
			doc(map[string]interface{}{"l": []interface{}{"a", "b"}}), Fail},
		{"contains map key", policy.Assertion{Path: "spec.m", Operator: policy.OpContains, Value: "k"},
			doc(map[string]interface{}{"m": map[string]interface{}{"k": 1}}), Pass},
		{"contains on int fails", policy.Assertion{Path: "spec.n", Operator: policy.OpContains, Value: "1"},
			doc(map[string]interface{}{"n": 12}), Fail},
		{"not_contains pass", policy.Assertion{Path: "spec.l", Operator: policy.OpNotContains, Value: "*"},
			doc(map[string]interface{}{"l": []interface{}{"a"}}), Pass},
		{"not_contains fail", policy.Assertion{Path: "spec.l", Operator: policy.OpNotContains, Value: "*"},
			doc(map[string]interface{}{"l": []interface{}{"*"}}), Fail},
		{"not_contains missing passes", policy.Assertion{Path: "spec.l", Operator: policy.OpNotContains, Value: "*"},
			doc(map[string]interface{}{}), Pass},

		// regex
		{"match_regex pass", policy.Assertion{Path: "spec.s", Operator: policy.OpMatchRegex, Value: "^ab"},
			doc(map[string]interface{}{"s": "abcd"}), Pass},
		{"match_regex fail", policy.Assertion{Path: "spec.s", Operator: policy.OpMatchRegex, Value: "^zz"},
			doc(map[string]interface{}{"s": "abcd"}), Fail},
		{"match_regex missing fails", policy.Assertion{Path: "spec.s", Operator: policy.OpMatchRegex, Value: "^ab"},
			doc(map[string]interface{}{}), Fail},
		{"not_match_regex pass", policy.Assertion{Path: "spec.s", Operator: policy.OpNotMatchRegex, Value: "^zz"},
			doc(map[string]interface{}{"s": "abcd"}), Pass},
		{"not_match_regex fail", policy.Assertion{Path: "spec.s", Operator: policy.OpNotMatchRegex, Value: "^ab"},
			doc(map[string]interface{}{"s": "abcd"}), Fail},
		{"not_match_regex missing passes", policy.Assertion{Path: "spec.s", Operator: policy.OpNotMatchRegex, Value: "^ab"},
			doc(map[string]interface{}{}), Pass},
		{"regex non-string stringified", policy.Assertion{Path: "spec.n", Operator: policy.OpMatchRegex, Value: "^42$"},
			doc(map[string]interface{}{"n": 42}), Pass},

		// dynamic (templated) values -> Unknown
		{"dynamic value unknown", policy.Assertion{Path: "spec.v", Operator: policy.OpIsTrue},
			doc(map[string]interface{}{"v": "${schema.spec.encrypted}"}), Unknown},
		{"dynamic exists still passes", policy.Assertion{Path: "spec.v", Operator: policy.OpExists},
			doc(map[string]interface{}{"v": "${schema.spec.key}"}), Pass},

		// list indexing in paths
		{"numeric path index", policy.Assertion{Path: "spec.rules.0.port", Operator: policy.OpEquals, Value: 443},
			doc(map[string]interface{}{"rules": []interface{}{map[string]interface{}{"port": 443}}}), Pass},
		{"numeric path index out of range", policy.Assertion{Path: "spec.rules.5.port", Operator: policy.OpEquals, Value: 443},
			doc(map[string]interface{}{"rules": []interface{}{}}), Fail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, tt.assertion, tt.doc)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnyAllQuantifiers(t *testing.T) {
	portIs22 := policy.Assertion{Path: "port", Operator: policy.OpEquals, Value: 22}
	listDoc := func(ports ...int) map[string]interface{} {
		var l []interface{}
		for _, p := range ports {
			l = append(l, map[string]interface{}{"port": p})
		}
		return doc(map[string]interface{}{"rules": l})
	}

	tests := []struct {
		name      string
		assertion policy.Assertion
		doc       map[string]interface{}
		want      Result
	}{
		{"any one matches",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAny, Assertions: []policy.Assertion{portIs22}},
			listDoc(80, 22), Pass},
		{"any none matches",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAny, Assertions: []policy.Assertion{portIs22}},
			listDoc(80, 443), Fail},
		{"any empty list fails",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAny, Assertions: []policy.Assertion{portIs22}},
			listDoc(), Fail},
		{"any missing list fails",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAny, Assertions: []policy.Assertion{portIs22}},
			doc(map[string]interface{}{}), Fail},
		{"all every matches",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAll, Assertions: []policy.Assertion{portIs22}},
			listDoc(22, 22), Pass},
		{"all one mismatch",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAll, Assertions: []policy.Assertion{portIs22}},
			listDoc(22, 80), Fail},
		{"all empty list passes",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAll, Assertions: []policy.Assertion{portIs22}},
			listDoc(), Pass},
		{"all missing list passes",
			policy.Assertion{Path: "spec.rules", Operator: policy.OpAll, Assertions: []policy.Assertion{portIs22}},
			doc(map[string]interface{}{}), Pass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalOne(t, tt.assertion, tt.doc)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnyAllAsLogicalCombinators(t *testing.T) {
	// `any` on a non-list value (the document itself via ".") acts as OR.
	orAssertion := policy.Assertion{
		Path:     ".",
		Operator: policy.OpAny,
		Assertions: []policy.Assertion{
			{Path: "spec.kmsKeyID", Operator: policy.OpExists},
			{Path: "spec.sseEnabled", Operator: policy.OpIsTrue},
		},
	}
	if got := evalOne(t, orAssertion, doc(map[string]interface{}{"kmsKeyID": "k"})); got != Pass {
		t.Errorf("OR with first alternative: got %v, want Pass", got)
	}
	if got := evalOne(t, orAssertion, doc(map[string]interface{}{"sseEnabled": true})); got != Pass {
		t.Errorf("OR with second alternative: got %v, want Pass", got)
	}
	if got := evalOne(t, orAssertion, doc(map[string]interface{}{})); got != Fail {
		t.Errorf("OR with no alternative: got %v, want Fail", got)
	}

	// `all` on a non-list value acts as AND.
	andAssertion := policy.Assertion{
		Path:     ".",
		Operator: policy.OpAll,
		Assertions: []policy.Assertion{
			{Path: "spec.a", Operator: policy.OpIsTrue},
			{Path: "spec.b", Operator: policy.OpIsTrue},
		},
	}
	if got := evalOne(t, andAssertion, doc(map[string]interface{}{"a": true, "b": true})); got != Pass {
		t.Errorf("AND both true: got %v, want Pass", got)
	}
	if got := evalOne(t, andAssertion, doc(map[string]interface{}{"a": true, "b": false})); got != Fail {
		t.Errorf("AND one false: got %v, want Fail", got)
	}
}

func TestMultipleAssertionsAreANDed(t *testing.T) {
	p := &policy.Policy{Assertions: []policy.Assertion{
		{Path: "spec.a", Operator: policy.OpIsTrue},
		{Path: "spec.b", Operator: policy.OpIsTrue},
	}}
	if got := Evaluate(p, doc(map[string]interface{}{"a": true, "b": true})).Result; got != Pass {
		t.Errorf("both pass: got %v", got)
	}
	out := Evaluate(p, doc(map[string]interface{}{"a": true, "b": false}))
	if out.Result != Fail {
		t.Errorf("one fail: got %v", out.Result)
	}
	if len(out.Messages) == 0 {
		t.Error("expected failure messages")
	}
}

func TestUnknownPropagation(t *testing.T) {
	p := &policy.Policy{Assertions: []policy.Assertion{
		{Path: "spec.a", Operator: policy.OpIsTrue},
		{Path: "spec.b", Operator: policy.OpIsTrue},
	}}
	// One unknown + one pass -> Unknown.
	out := Evaluate(p, doc(map[string]interface{}{"a": true, "b": "${schema.spec.b}"}))
	if out.Result != Unknown {
		t.Errorf("pass+unknown: got %v, want Unknown", out.Result)
	}
	// One unknown + one fail -> Fail (a definite failure dominates).
	out = Evaluate(p, doc(map[string]interface{}{"a": false, "b": "${schema.spec.b}"}))
	if out.Result != Fail {
		t.Errorf("fail+unknown: got %v, want Fail", out.Result)
	}
}

func TestCustomAssertionMessage(t *testing.T) {
	p := &policy.Policy{Assertions: []policy.Assertion{
		{Path: "spec.x", Operator: policy.OpIsTrue, Message: "custom message"},
	}}
	out := Evaluate(p, doc(map[string]interface{}{}))
	if out.Result != Fail {
		t.Fatalf("got %v, want Fail", out.Result)
	}
	if len(out.Messages) != 1 || out.Messages[0] != "custom message" {
		t.Errorf("got messages %v, want [custom message]", out.Messages)
	}
}

func TestResolve(t *testing.T) {
	d := map[string]interface{}{
		"spec": map[string]interface{}{
			"nested": map[string]interface{}{"deep": 1},
			"list":   []interface{}{"a", "b"},
		},
	}
	if v, ok := Resolve(d, "spec.nested.deep"); !ok || v != 1 {
		t.Errorf("spec.nested.deep: got %v %v", v, ok)
	}
	if v, ok := Resolve(d, "spec.list.1"); !ok || v != "b" {
		t.Errorf("spec.list.1: got %v %v", v, ok)
	}
	if _, ok := Resolve(d, "spec.missing.deep"); ok {
		t.Error("missing path should not resolve")
	}
	if _, ok := Resolve(d, "spec.list.x"); ok {
		t.Error("non-numeric list index should not resolve")
	}
	if _, ok := Resolve(d, "spec.list.-1"); ok {
		t.Error("negative list index should not resolve")
	}
	if _, ok := Resolve(d, "spec.nested.deep.further"); ok {
		t.Error("path through scalar should not resolve")
	}
}

func TestIsDynamicValue(t *testing.T) {
	tests := []struct {
		v    interface{}
		want bool
	}{
		{"${schema.spec.x}", true},
		{"prefix-${schema.spec.x}", true},
		{"no template", false},
		{"${unclosed", false},
		{42, false},
		{true, false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := IsDynamicValue(tt.v); got != tt.want {
			t.Errorf("IsDynamicValue(%v) = %v, want %v", tt.v, got, tt.want)
		}
	}
}
