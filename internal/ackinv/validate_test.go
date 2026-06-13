package ackinv

import (
	"strings"
	"testing"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

func testInventory() *Inventory {
	return &Inventory{
		Org: "aws-controllers-k8s",
		Services: []Service{{
			Name: "ec2",
			Kinds: []Kind{{
				Kind:  "SecurityGroup",
				Group: "ec2.services.k8s.aws",
				Fields: []Field{
					{Path: "spec.ingressRules[].fromPort", Type: "integer"},
					{Path: "spec.ingressRules[].toPort", Type: "integer"},
					{Path: "spec.ingressRules[].ipRanges[].cidrIP", Type: "string"},
				},
			}},
		}},
	}
}

func mkPolicy(kind string, assertions []policy.Assertion) policy.Policy {
	return policy.Policy{
		ID: "ACKRO_TEST_001",
		Match: policy.Match{
			APIGroups: []string{"ec2.services.k8s.aws"},
			Kinds:     []string{kind},
		},
		Assertions: assertions,
	}
}

func TestValidateNestedContextPaths(t *testing.T) {
	// Mirrors the real EC2 public-ingress shape: all > any > all nesting
	// with "." context hops.
	p := mkPolicy("SecurityGroup", []policy.Assertion{{
		Path: "spec.ingressRules", Operator: policy.OpAll,
		Assertions: []policy.Assertion{{
			Path: ".", Operator: policy.OpAny,
			Assertions: []policy.Assertion{
				{Path: "ipRanges", Operator: policy.OpAll, Assertions: []policy.Assertion{
					{Path: "cidrIP", Operator: policy.OpNotEquals, Value: "0.0.0.0/0"},
				}},
				{Path: "fromPort", Operator: policy.OpGreaterThan, Value: 22},
			},
		}},
	}})
	if errs := ValidatePolicyPaths(testInventory(), []policy.Policy{p}); len(errs) != 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

func TestValidateCatchesBadPath(t *testing.T) {
	p := mkPolicy("SecurityGroup", []policy.Assertion{{
		Path: "spec.ingressRules", Operator: policy.OpAll,
		Assertions: []policy.Assertion{
			{Path: "fromPrt", Operator: policy.OpExists}, // typo
		},
	}})
	errs := ValidatePolicyPaths(testInventory(), []policy.Policy{p})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "spec.ingressRules.fromPrt") {
		t.Fatalf("expected one fromPrt error, got: %v", errs)
	}
}

func TestValidateCatchesUnknownKindAndGroup(t *testing.T) {
	p := mkPolicy("VPCEndpoint", []policy.Assertion{
		{Path: "spec.vpcID", Operator: policy.OpExists},
	})
	errs := ValidatePolicyPaths(testInventory(), []policy.Policy{p})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), `kind "VPCEndpoint" not found`) {
		t.Fatalf("expected unknown-kind error, got: %v", errs)
	}

	p.Match.APIGroups = []string{"nosuch.services.k8s.aws"}
	errs = ValidatePolicyPaths(testInventory(), []policy.Policy{p})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "not present in ACK inventory") {
		t.Fatalf("expected unknown-group error, got: %v", errs)
	}
}

func TestValidateAcceptsSyntheticPolicyDocPaths(t *testing.T) {
	p := mkPolicy("SecurityGroup", []policy.Assertion{{
		Path: "__ackrocheck.policyDocuments.policy.Statement", Operator: policy.OpAll,
		Assertions: []policy.Assertion{
			{Path: "Effect", Operator: policy.OpEquals, Value: "Allow"},
		},
	}})
	if errs := ValidatePolicyPaths(testInventory(), []policy.Policy{p}); len(errs) != 0 {
		t.Fatalf("expected synthetic paths to be accepted, got: %v", errs)
	}
}
