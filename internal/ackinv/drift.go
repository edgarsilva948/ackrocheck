package ackinv

import (
	"fmt"
	"sort"
	"strings"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

// Drift classifies the differences between two inventory snapshots, ordered
// by urgency for triage.
type Drift struct {
	// BrokenPolicies are validation errors of the current built-in controls
	// against the NEW inventory: paths that no longer resolve. These are
	// silently-broken controls and the most urgent category.
	BrokenPolicies []string
	// NewServices are controllers present in new but not old.
	NewServices []string
	// RemovedServices are controllers present in old but not new.
	RemovedServices []string
	// NewKinds are CRDs added to existing services ("service: Kind").
	NewKinds []string
	// RemovedKinds are CRDs removed from existing services.
	RemovedKinds []string
	// NewFields are spec fields added to kinds that already have at least
	// one control matching them ("service Kind: path"). Fields on uncovered
	// kinds are tracked by the coverage report instead.
	NewFields []string
	// RemovedFields are spec fields removed from covered kinds.
	RemovedFields []string
	// ReleaseBumps are release tag changes ("service: old -> new").
	ReleaseBumps []string
}

// Empty reports whether no drift was detected at all.
func (d *Drift) Empty() bool {
	return len(d.BrokenPolicies) == 0 && len(d.NewServices) == 0 &&
		len(d.RemovedServices) == 0 && len(d.NewKinds) == 0 &&
		len(d.RemovedKinds) == 0 && len(d.NewFields) == 0 &&
		len(d.RemovedFields) == 0 && len(d.ReleaseBumps) == 0
}

// Classify computes the drift between two inventories. policies are the
// current built-in controls, used both to detect broken assertion paths and
// to scope field-level drift to covered kinds (field churn on the ~230
// uncovered kinds would drown the signal).
func Classify(old, new *Inventory, policies []policy.Policy) *Drift {
	d := &Drift{}

	for _, err := range ValidatePolicyPaths(new, policies) {
		d.BrokenPolicies = append(d.BrokenPolicies, err.Error())
	}

	covered := map[string]bool{} // "group/kind" lowercased
	for _, p := range policies {
		for _, g := range p.Match.APIGroups {
			for _, k := range p.Match.Kinds {
				covered[strings.ToLower(g)+"/"+strings.ToLower(k)] = true
			}
		}
	}

	oldSvc := map[string]*Service{}
	for i := range old.Services {
		oldSvc[old.Services[i].Name] = &old.Services[i]
	}
	newSvc := map[string]*Service{}
	for i := range new.Services {
		newSvc[new.Services[i].Name] = &new.Services[i]
	}

	for name := range newSvc {
		if _, ok := oldSvc[name]; !ok {
			d.NewServices = append(d.NewServices, name)
		}
	}
	for name := range oldSvc {
		if _, ok := newSvc[name]; !ok {
			d.RemovedServices = append(d.RemovedServices, name)
		}
	}

	for name, ns := range newSvc {
		os, ok := oldSvc[name]
		if !ok {
			continue
		}
		if os.Release != ns.Release {
			d.ReleaseBumps = append(d.ReleaseBumps,
				fmt.Sprintf("%s: %s -> %s", name, orNoneStr(os.Release), orNoneStr(ns.Release)))
		}
		oldKinds := map[string]*Kind{}
		for i := range os.Kinds {
			oldKinds[os.Kinds[i].Kind] = &os.Kinds[i]
		}
		for i := range ns.Kinds {
			nk := &ns.Kinds[i]
			ok2, exists := oldKinds[nk.Kind]
			if !exists {
				d.NewKinds = append(d.NewKinds, fmt.Sprintf("%s: %s", name, nk.Kind))
				continue
			}
			if covered[strings.ToLower(nk.Group)+"/"+strings.ToLower(nk.Kind)] {
				added, removed := diffFields(ok2.Fields, nk.Fields)
				for _, f := range added {
					d.NewFields = append(d.NewFields, fmt.Sprintf("%s %s: %s", name, nk.Kind, f))
				}
				for _, f := range removed {
					d.RemovedFields = append(d.RemovedFields, fmt.Sprintf("%s %s: %s", name, nk.Kind, f))
				}
			}
		}
		newKindNames := map[string]bool{}
		for i := range ns.Kinds {
			newKindNames[ns.Kinds[i].Kind] = true
		}
		for kindName := range oldKinds {
			if !newKindNames[kindName] {
				d.RemovedKinds = append(d.RemovedKinds, fmt.Sprintf("%s: %s", name, kindName))
			}
		}
	}

	for _, s := range [][]string{
		d.BrokenPolicies, d.NewServices, d.RemovedServices, d.NewKinds,
		d.RemovedKinds, d.NewFields, d.RemovedFields, d.ReleaseBumps,
	} {
		sort.Strings(s)
	}
	return d
}

func diffFields(old, new []Field) (added, removed []string) {
	oldSet := map[string]bool{}
	for _, f := range old {
		oldSet[f.Path] = true
	}
	newSet := map[string]bool{}
	for _, f := range new {
		newSet[f.Path] = true
	}
	for p := range newSet {
		if !oldSet[p] {
			added = append(added, p)
		}
	}
	for p := range oldSet {
		if !newSet[p] {
			removed = append(removed, p)
		}
	}
	return added, removed
}

// Report renders the drift as a markdown document suitable for a PR body.
func (d *Drift) Report() string {
	var b strings.Builder
	b.WriteString("# ACK schema drift report\n\n")
	if d.Empty() {
		b.WriteString("No drift detected.\n")
		return b.String()
	}
	section := func(title, explain string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", title, explain)
		for _, it := range items {
			fmt.Fprintf(&b, "- %s\n", it)
		}
		b.WriteString("\n")
	}
	section("🔴 Broken policies", "Assertion paths that no longer resolve against the updated CRD schemas. These controls are silently evaluating missing fields and must be fixed before merge.", d.BrokenPolicies)
	section("🆕 New services", "New ACK controllers. Candidates for the coverage backlog.", d.NewServices)
	section("🗑 Removed services", "Controllers no longer present in the org.", d.RemovedServices)
	section("New kinds", "CRDs added to existing services.", d.NewKinds)
	section("Removed kinds", "CRDs removed from existing services.", d.RemovedKinds)
	section("New fields on covered kinds", "Spec fields added to kinds that already have controls — candidates for new or extended controls.", d.NewFields)
	section("Removed fields on covered kinds", "Spec fields removed from kinds with controls. If a control references one, it also appears under Broken policies.", d.RemovedFields)
	section("Release bumps", "Controller release tag changes included in this refresh.", d.ReleaseBumps)
	return b.String()
}

// Issue is a GitHub issue the drift workflow should open.
type Issue struct {
	Title  string   `json:"title"`
	Labels []string `json:"labels"`
	Body   string   `json:"body"`
}

// Issues converts the drift into at most one issue per category that needs
// human action. Release bumps alone produce no issue.
func (d *Drift) Issues() []Issue {
	var out []Issue
	mk := func(title, label, intro string, items []string) {
		if len(items) == 0 {
			return
		}
		var b strings.Builder
		b.WriteString(intro + "\n\n")
		for _, it := range items {
			fmt.Fprintf(&b, "- [ ] %s\n", it)
		}
		b.WriteString("\nGenerated by the weekly `ack-drift` workflow. See the matching inventory PR for full context.\n")
		out = append(out, Issue{Title: title, Labels: []string{label}, Body: b.String()})
	}
	mk("Broken control paths after ACK CRD update", "broken-policy",
		"The following control assertion paths no longer resolve against the updated CRD schemas:", d.BrokenPolicies)
	mk("New ACK services without coverage", "new-service",
		"New ACK controllers appeared in the org. Evaluate FSBP/Config controls for each:", d.NewServices)
	var schema []string
	schema = append(schema, d.NewKinds...)
	schema = append(schema, d.NewFields...)
	schema = append(schema, d.RemovedKinds...)
	schema = append(schema, d.RemovedFields...)
	mk("ACK schema drift on covered services", "schema-drift",
		"Kinds/fields changed on services AckroCheck covers. Review for new control opportunities:", schema)
	return out
}

func orNoneStr(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
