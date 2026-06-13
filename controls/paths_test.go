package controls

import (
	"os"
	"testing"

	"github.com/edgarsilva948/ackrocheck/internal/ackinv"
)

const inventoryPath = "../mappings/ack/inventory.json"

// TestAssertionPathsResolveAgainstCRDs validates every assertion path of
// every built-in control against the pinned ACK CRD schemas in
// mappings/ack/inventory.json. This catches typos in new controls and,
// when the inventory is refreshed, controls silently broken by upstream
// CRD changes (a renamed or removed field makes the old path unresolvable).
func TestAssertionPathsResolveAgainstCRDs(t *testing.T) {
	if _, err := os.Stat(inventoryPath); err != nil {
		t.Fatalf("ACK inventory missing: %v (regenerate with `go run ./tools/ack-inventory`)", err)
	}
	inv, err := ackinv.Load(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	policies, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range ackinv.ValidatePolicyPaths(inv, policies) {
		t.Error(err)
	}
}
