package controls

import "testing"

func TestBuiltinLoadsAndValidates(t *testing.T) {
	policies, err := Builtin()
	if err != nil {
		t.Fatalf("embedded controls must always load: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("no embedded controls found")
	}
	seen := map[string]bool{}
	for _, p := range policies {
		if seen[p.ID] {
			t.Errorf("duplicate control id %s", p.ID)
		}
		seen[p.ID] = true
		if p.Remediation.Message == "" {
			t.Errorf("control %s has no remediation message", p.ID)
		}
		if p.Compatibility.IntroducedIn == "" {
			t.Errorf("control %s has no introducedIn version", p.ID)
		}
	}
}
