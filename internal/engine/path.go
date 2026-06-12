package engine

import (
	"strconv"
	"strings"
)

// Resolve walks a dot-separated path through nested maps and lists.
// Numeric segments index into lists (e.g. "spec.rules.0.port").
// It returns the value and whether the full path was found.
func Resolve(doc interface{}, path string) (interface{}, bool) {
	current := doc
	for _, seg := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]interface{}:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			current = v
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			current = node[idx]
		default:
			return nil, false
		}
	}
	return current, true
}

// IsDynamicValue reports whether a value is a KRO/CEL templated expression
// such as "${schema.spec.encrypted}". Such values are user-controlled at
// instance creation time and cannot be statically verified.
func IsDynamicValue(v interface{}) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	open := strings.Index(s, "${")
	return open >= 0 && strings.Index(s[open:], "}") > 0
}
