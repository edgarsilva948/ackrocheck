package ack

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PolicyDocumentFields are the spec fields where ACK resources commonly embed
// IAM-style policy documents, either as JSON strings or as YAML objects.
var PolicyDocumentFields = []string{
	"policyDocument",
	"assumeRolePolicyDocument",
	"document",
	"policy",
}

// NormalizedKeyPrefix marks normalized policy documents injected into the
// resource document for assertion evaluation. For each spec field that holds
// a parseable policy document, the scanner injects the parsed object under
// __ackrocheck.policyDocuments.<field>.
const NormalizedKeyPrefix = "__ackrocheck"

// NormalizePolicyDocuments scans known spec fields of a raw resource document
// for embedded IAM-style policy documents and injects parsed, canonicalized
// copies under __ackrocheck.policyDocuments. The input map is not modified;
// a shallow-copied document is returned.
//
// The parser is defensive: strings that are not valid JSON objects and
// values of unexpected shape are ignored.
func NormalizePolicyDocuments(raw map[string]interface{}) map[string]interface{} {
	spec, ok := raw["spec"].(map[string]interface{})
	if !ok {
		return raw
	}
	normalized := map[string]interface{}{}
	for _, field := range PolicyDocumentFields {
		v, ok := spec[field]
		if !ok {
			continue
		}
		doc, ok := ParsePolicyDocument(v)
		if !ok {
			continue
		}
		normalized[field] = doc
	}
	if len(normalized) == 0 {
		return raw
	}
	out := make(map[string]interface{}, len(raw)+1)
	for k, v := range raw {
		out[k] = v
	}
	out[NormalizedKeyPrefix] = map[string]interface{}{
		"policyDocuments": normalized,
	}
	return out
}

// ParsePolicyDocument accepts a JSON string or a YAML-decoded object and
// returns a canonicalized policy document:
//   - Statement is always a list ("Statement" as a single object is wrapped)
//   - Action, NotAction, Resource and NotResource are always lists of strings
//   - Principal "*" is canonicalized to {"AWS": ["*"]}
//
// Returns false if the value does not look like a policy document.
func ParsePolicyDocument(v interface{}) (map[string]interface{}, bool) {
	var doc map[string]interface{}
	switch val := v.(type) {
	case string:
		s := strings.TrimSpace(val)
		if !strings.HasPrefix(s, "{") {
			return nil, false
		}
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			return nil, false
		}
	case map[string]interface{}:
		doc = val
	default:
		return nil, false
	}

	stmts, ok := statementList(doc)
	if !ok {
		return nil, false
	}
	canonical := make([]interface{}, 0, len(stmts))
	for _, s := range stmts {
		stmt, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		canonical = append(canonical, canonicalizeStatement(stmt))
	}
	out := make(map[string]interface{}, len(doc))
	for k, v := range doc {
		out[k] = v
	}
	out["Statement"] = canonical
	return out, true
}

func statementList(doc map[string]interface{}) ([]interface{}, bool) {
	raw, ok := findKeyFold(doc, "Statement")
	if !ok {
		return nil, false
	}
	switch s := raw.(type) {
	case []interface{}:
		return s, true
	case map[string]interface{}:
		return []interface{}{s}, true
	default:
		return nil, false
	}
}

func canonicalizeStatement(stmt map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(stmt))
	for k, v := range stmt {
		out[k] = v
	}
	for _, key := range []string{"Action", "NotAction", "Resource", "NotResource"} {
		if v, ok := findKeyFold(stmt, key); ok {
			out[key] = toStringList(v)
		}
	}
	if p, ok := findKeyFold(stmt, "Principal"); ok {
		out["Principal"] = canonicalizePrincipal(p)
	}
	if e, ok := findKeyFold(stmt, "Effect"); ok {
		if s, isStr := e.(string); isStr {
			out["Effect"] = canonicalEffect(s)
		}
	}
	// HasCondition lets declarative policies distinguish unconditional public
	// access from access constrained by a Condition block.
	if _, ok := findKeyFold(stmt, "Condition"); ok {
		out["HasCondition"] = true
	} else {
		out["HasCondition"] = false
	}
	return out
}

// canonicalizePrincipal maps "*" and {"AWS": "*"} variants into a consistent
// shape with list values so assertions can use `contains`.
func canonicalizePrincipal(p interface{}) interface{} {
	switch v := p.(type) {
	case string:
		if v == "*" {
			return map[string]interface{}{"AWS": []interface{}{"*"}}
		}
		return map[string]interface{}{"AWS": []interface{}{v}}
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, val := range v {
			out[k] = toStringList(val)
		}
		return out
	default:
		return p
	}
}

func toStringList(v interface{}) []interface{} {
	switch val := v.(type) {
	case []interface{}:
		return val
	case nil:
		return []interface{}{}
	default:
		return []interface{}{fmt.Sprintf("%v", val)}
	}
}

func canonicalEffect(s string) string {
	switch strings.ToLower(s) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return s
	}
}

// findKeyFold finds a map key case-insensitively (IAM JSON keys are usually
// PascalCase but manifests are hand-written).
func findKeyFold(m map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}
