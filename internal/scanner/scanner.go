// Package scanner evaluates parsed resources against loaded policies and
// produces findings. It handles native ACK resources and best-effort KRO
// ResourceGraphDefinition analysis.
package scanner

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/edgarsilva948/ackrocheck/internal/ack"
	"github.com/edgarsilva948/ackrocheck/internal/engine"
	"github.com/edgarsilva948/ackrocheck/internal/kro"
	"github.com/edgarsilva948/ackrocheck/internal/parser"
	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

// Framework selects which resource families to scan.
type Framework string

// Supported frameworks.
const (
	FrameworkACK Framework = "ack"
	FrameworkKRO Framework = "kro"
)

// Options configure a scan.
type Options struct {
	// Frameworks to scan. Empty means all.
	Frameworks []Framework
	// MinSeverity filters out findings below this severity.
	MinSeverity policy.Severity
	// IncludePassed collects controls that passed into Report.Passed. Off by
	// default so the common case does no extra work and failure-only
	// consumers are unaffected.
	IncludePassed bool
}

// Scanner evaluates resources against a set of policies.
type Scanner struct {
	policies []policy.Policy
	opts     Options
}

// New creates a Scanner. Policies are assumed validated by the loader.
func New(policies []policy.Policy, opts Options) *Scanner {
	if opts.MinSeverity == "" {
		opts.MinSeverity = policy.SeverityInfo
	}
	return &Scanner{policies: policies, opts: opts}
}

// Scan evaluates all parsed resources and returns a complete report.
func (s *Scanner) Scan(parsed *parser.Result) *Report {
	report := &Report{}
	report.Summary.FilesScanned = parsed.FilesScanned
	for _, pe := range parsed.Errors {
		report.ParseErrors = append(report.ParseErrors, ParseIssue{FilePath: pe.FilePath, Error: pe.Err.Error()})
	}
	report.Summary.ParseErrors = len(report.ParseErrors)

	for i := range parsed.Resources {
		res := &parsed.Resources[i]
		switch {
		case kro.IsResourceGraphDefinition(res):
			if s.frameworkEnabled(FrameworkKRO) {
				report.Summary.ResourcesScanned++
				findings, passed := s.scanRGD(res)
				report.Findings = append(report.Findings, findings...)
				report.Passed = append(report.Passed, passed...)
			}
		case ack.IsACKGroup(res.APIGroup()):
			if s.frameworkEnabled(FrameworkACK) {
				report.Summary.ResourcesScanned++
				findings, passed := s.scanResource(res, nil)
				report.Findings = append(report.Findings, findings...)
				report.Passed = append(report.Passed, passed...)
			}
		}
	}

	report.Findings = s.filterSeverity(report.Findings)
	SortFindings(report.Findings)
	report.Summary.Findings = len(report.Findings)
	for _, f := range report.Findings {
		switch f.Severity {
		case policy.SeverityCritical:
			report.Summary.Critical++
		case policy.SeverityHigh:
			report.Summary.High++
		case policy.SeverityMedium:
			report.Summary.Medium++
		case policy.SeverityLow:
			report.Summary.Low++
		case policy.SeverityInfo:
			report.Summary.Info++
		}
	}
	SortPassed(report.Passed)
	report.Summary.Passed = len(report.Passed)
	return report
}

// scanResource evaluates one resource against all matching policies, returning
// findings (failures/warnings) and, when Options.IncludePassed is set, the
// controls that passed. parent is non-nil when the resource is embedded in a
// KRO RGD.
func (s *Scanner) scanResource(res *parser.Resource, parent *parser.Resource) ([]Finding, []PassedCheck) {
	doc := ack.NormalizePolicyDocuments(res.Raw)
	var findings []Finding
	var passed []PassedCheck
	for i := range s.policies {
		p := &s.policies[i]
		if !p.Matches(res.APIGroup(), res.Kind) {
			continue
		}
		if p.Match.ProductionOnly && !isProduction(res) {
			continue
		}
		outcome := engine.Evaluate(p, doc)
		if outcome.Result == engine.Pass {
			if s.opts.IncludePassed && p.Severity.AtLeast(s.opts.MinSeverity) {
				passed = append(passed, PassedCheck{
					ControlID:    p.ID,
					Title:        p.Title,
					Severity:     p.Severity,
					ResourceKind: res.Kind,
					ResourceName: res.Name,
					FilePath:     res.FilePath,
				})
			}
			continue
		}
		f := Finding{
			ControlID:          p.ID,
			Title:              p.Title,
			Severity:           p.Severity,
			Category:           p.Category,
			Status:             StatusFailed,
			ResourceAPIVersion: res.APIVersion,
			ResourceKind:       res.Kind,
			ResourceName:       res.Name,
			ResourceNamespace:  res.Namespace,
			FilePath:           res.FilePath,
			DocumentIndex:      res.DocIndex,
			Line:               res.Line,
			Message:            buildMessage(p, outcome.Messages),
			Remediation:        p.Remediation.Message,
			RemediationPatch:   renderPatch(p.Remediation.Patch),
			GuideURL:           GuideURL(p.ID),
			References:         p.References,
		}
		if outcome.Result == engine.Unknown {
			f.Status = StatusWarning
			f.Message = buildWarningMessage(p, outcome.Messages)
		}
		if parent != nil {
			f.ParentResourceKind = parent.Kind
			f.ParentResourceName = parent.Name
			f.EmbeddedResourceKind = res.Kind
			f.EmbeddedResourceName = res.Name
		}
		findings = append(findings, f)
	}
	return findings, passed
}

// scanRGD extracts embedded templates from a ResourceGraphDefinition and
// scans any that belong to ACK API groups with the normal policy engine.
func (s *Scanner) scanRGD(rgd *parser.Resource) ([]Finding, []PassedCheck) {
	var findings []Finding
	var passed []PassedCheck
	for _, emb := range kro.ExtractEmbedded(rgd) {
		res := emb.Resource
		if !ack.IsACKGroup(res.APIGroup()) {
			continue
		}
		if res.Name == "" {
			res.Name = emb.ID
		}
		f, pc := s.scanResource(&res, rgd)
		findings = append(findings, f...)
		passed = append(passed, pc...)
	}
	return findings, passed
}

func (s *Scanner) frameworkEnabled(f Framework) bool {
	if len(s.opts.Frameworks) == 0 {
		return true
	}
	for _, fw := range s.opts.Frameworks {
		if fw == f {
			return true
		}
	}
	return false
}

func (s *Scanner) filterSeverity(fs []Finding) []Finding {
	out := fs[:0]
	for _, f := range fs {
		if f.Severity.AtLeast(s.opts.MinSeverity) {
			out = append(out, f)
		}
	}
	return out
}

func buildMessage(p *policy.Policy, details []string) string {
	msg := p.Description
	if msg == "" {
		msg = p.Title
	}
	if len(details) > 0 {
		msg += " (" + strings.Join(details, "; ") + ")"
	}
	return msg
}

// renderPatch marshals a policy's informational remediation patch to a YAML
// snippet (trailing newline trimmed) developers can copy into their manifest.
// Returns "" when there is no patch or it cannot be marshaled.
func renderPatch(patch map[string]interface{}) string {
	if len(patch) == 0 {
		return ""
	}
	out, err := yaml.Marshal(patch)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}

func buildWarningMessage(p *policy.Policy, details []string) string {
	msg := p.Title + ": value is user-controlled via a templated expression and cannot be statically verified."
	if len(details) > 0 {
		msg += " " + strings.Join(details, "; ")
	}
	return msg
}

// isProduction reports whether a resource is marked as production via labels
// (environment/env: prod|production) or the annotation
// ackrocheck.dev/environment: production|prod.
func isProduction(res *parser.Resource) bool {
	for _, key := range []string{"environment", "env"} {
		if v, ok := res.Labels[key]; ok && isProdValue(v) {
			return true
		}
	}
	if v, ok := res.Annotations["ackrocheck.dev/environment"]; ok && isProdValue(v) {
		return true
	}
	return false
}

func isProdValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "prod", "production":
		return true
	default:
		return false
	}
}
