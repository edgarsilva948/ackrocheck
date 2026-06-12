package policy

import (
	"fmt"
	"strings"
)

// Severity is the normalized severity level of a control or finding.
type Severity string

// Supported severities, ordered from least to most severe.
const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// ParseSeverity normalizes a case-insensitive severity string.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToUpper(strings.TrimSpace(s)))
	if _, ok := severityRank[sev]; !ok {
		return "", fmt.Errorf("unknown severity %q (expected one of critical, high, medium, low, info)", s)
	}
	return sev, nil
}

// Rank returns the numeric rank of the severity; higher means more severe.
func (s Severity) Rank() int {
	return severityRank[s]
}

// AtLeast reports whether s is at or above the given threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s.Rank() >= threshold.Rank()
}

// AllSeverities lists severities from most to least severe, for stable output.
func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}
