package ackinv

import (
	"fmt"
	"strings"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

// ValidatePolicyPaths checks every assertion path of every policy against
// the CRD schemas in the inventory. It returns one error per problem:
// either a match.kinds entry that does not exist in the inventory, or an
// assertion path that does not resolve against the CRD spec schema.
//
// Nested assertion paths are joined to their enclosing context: `any`/`all`
// descend into the value at the assertion's path (element-wise for lists,
// which is equivalent here since flattened paths drop the "[]" markers).
func ValidatePolicyPaths(inv *Inventory, policies []policy.Policy) []error {
	index := inv.KindsByGroup()
	var errs []error
	for i := range policies {
		p := &policies[i]
		for _, g := range p.Match.APIGroups {
			kindsForGroup, groupKnown := index[strings.ToLower(g)]
			if !groupKnown {
				errs = append(errs, fmt.Errorf("%s: match.apiGroups %q not present in ACK inventory", p.ID, g))
				continue
			}
			for _, kindName := range p.Match.Kinds {
				kind, ok := kindsForGroup[strings.ToLower(kindName)]
				if !ok {
					errs = append(errs, fmt.Errorf("%s: kind %q not found in group %q in ACK inventory", p.ID, kindName, g))
					continue
				}
				for ai := range p.Assertions {
					errs = append(errs, validateAssertionPaths(p.ID, kind, &p.Assertions[ai], "")...)
				}
			}
		}
	}
	return errs
}

func validateAssertionPaths(policyID string, kind *Kind, a *policy.Assertion, context string) []error {
	full := joinPath(context, a.Path)
	var errs []error
	if full != "" && !kind.HasPath(full) {
		errs = append(errs, fmt.Errorf("%s: path %q does not resolve against CRD %s.%s (assertion path %q in context %q)",
			policyID, full, kind.Kind, kind.Group, a.Path, contextOrRoot(context)))
	}
	for i := range a.Assertions {
		errs = append(errs, validateAssertionPaths(policyID, kind, &a.Assertions[i], full)...)
	}
	return errs
}

// joinPath joins a nested assertion path to its enclosing context. "." means
// the current context itself.
func joinPath(context, path string) string {
	if path == "." {
		return context
	}
	if context == "" {
		return path
	}
	return context + "." + path
}

func contextOrRoot(context string) string {
	if context == "" {
		return "<root>"
	}
	return context
}
