package policy

import (
	"strings"
	"testing"
)

func validPolicy() Policy {
	return Policy{
		ID:       "ACKRO_TEST_001",
		Title:    "test policy",
		Severity: "high",
		Match: Match{
			APIGroups: []string{"rds.services.k8s.aws"},
			Kinds:     []string{"DBInstance"},
		},
		Assertions: []Assertion{
			{Path: "spec.x", Operator: OpIsTrue},
		},
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"HIGH", SeverityHigh, false},
		{"high", SeverityHigh, false},
		{" Critical ", SeverityCritical, false},
		{"medium", SeverityMedium, false},
		{"LOW", SeverityLow, false},
		{"info", SeverityInfo, false},
		{"bogus", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSeverity(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	order := AllSeverities()
	for i := 0; i < len(order)-1; i++ {
		if order[i].Rank() <= order[i+1].Rank() {
			t.Errorf("%s should rank above %s", order[i], order[i+1])
		}
	}
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Error("critical should be at least high")
	}
	if SeverityLow.AtLeast(SeverityMedium) {
		t.Error("low should not be at least medium")
	}
	if !SeverityMedium.AtLeast(SeverityMedium) {
		t.Error("medium should be at least medium")
	}
}

func TestValidateNormalizesSeverity(t *testing.T) {
	p := validPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Severity != SeverityHigh {
		t.Errorf("severity = %v, want HIGH", p.Severity)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Policy)
		wantMsg string
	}{
		{"missing id", func(p *Policy) { p.ID = "" }, "missing id"},
		{"bad id format", func(p *Policy) { p.ID = "lowercase-id" }, "invalid id"},
		{"missing title", func(p *Policy) { p.Title = "" }, "missing title"},
		{"bad severity", func(p *Policy) { p.Severity = "EXTREME" }, "unknown severity"},
		{"no api groups", func(p *Policy) { p.Match.APIGroups = nil }, "apiGroups"},
		{"no kinds", func(p *Policy) { p.Match.Kinds = nil }, "kinds"},
		{"no assertions", func(p *Policy) { p.Assertions = nil }, "assertions"},
		{"assertion missing path", func(p *Policy) { p.Assertions[0].Path = "" }, "missing path"},
		{"unknown operator", func(p *Policy) { p.Assertions[0].Operator = "fancy" }, "unknown operator"},
		{"equals without value", func(p *Policy) {
			p.Assertions[0] = Assertion{Path: "spec.x", Operator: OpEquals}
		}, "requires a value"},
		{"numeric without value", func(p *Policy) {
			p.Assertions[0] = Assertion{Path: "spec.x", Operator: OpGreaterThan}
		}, "requires a numeric value"},
		{"regex non-string", func(p *Policy) {
			p.Assertions[0] = Assertion{Path: "spec.x", Operator: OpMatchRegex, Value: 42}
		}, "requires a string value"},
		{"regex invalid", func(p *Policy) {
			p.Assertions[0] = Assertion{Path: "spec.x", Operator: OpMatchRegex, Value: "("}
		}, "invalid regex"},
		{"any without nested", func(p *Policy) {
			p.Assertions[0] = Assertion{Path: "spec.x", Operator: OpAny}
		}, "requires nested assertions"},
		{"nested invalid", func(p *Policy) {
			p.Assertions[0] = Assertion{Path: "spec.x", Operator: OpAll, Assertions: []Assertion{
				{Path: "", Operator: OpExists},
			}}
		}, "nested assertion"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			tt.mutate(&p)
			err := p.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	p := validPolicy()
	tests := []struct {
		group, kind string
		want        bool
	}{
		{"rds.services.k8s.aws", "DBInstance", true},
		{"rds.services.k8s.aws", "dbinstance", true}, // case-insensitive kind
		{"RDS.services.k8s.aws", "DBInstance", true}, // case-insensitive group
		{"s3.services.k8s.aws", "DBInstance", false},
		{"rds.services.k8s.aws", "DBCluster", false},
		{"", "DBInstance", false},
	}
	for _, tt := range tests {
		if got := p.Matches(tt.group, tt.kind); got != tt.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tt.group, tt.kind, got, tt.want)
		}
	}
}
