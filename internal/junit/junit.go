// Package junit renders scan reports as JUnit XML for CI systems.
package junit

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"

	"github.com/edgarsilva948/ackrocheck/internal/scanner"
)

// TestSuites is the JUnit root element.
type TestSuites struct {
	XMLName  xml.Name    `xml:"testsuites"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Suites   []TestSuite `xml:"testsuite"`
}

// TestSuite groups findings by file.
type TestSuite struct {
	Name     string     `xml:"name,attr"`
	Tests    int        `xml:"tests,attr"`
	Failures int        `xml:"failures,attr"`
	Errors   int        `xml:"errors,attr"`
	Cases    []TestCase `xml:"testcase"`
}

// TestCase is one finding (failure) or parse error.
type TestCase struct {
	Name      string   `xml:"name,attr"`
	ClassName string   `xml:"classname,attr"`
	Failure   *Failure `xml:"failure,omitempty"`
	Error     *Failure `xml:"error,omitempty"`
}

// Failure carries the finding details.
type Failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// Write renders the report as JUnit XML. Each finding becomes a failed test
// case grouped in a suite per manifest file; parse errors become errored
// cases in their own suite.
func Write(w io.Writer, r *scanner.Report) error {
	byFile := map[string][]scanner.Finding{}
	for _, f := range r.Findings {
		byFile[f.FilePath] = append(byFile[f.FilePath], f)
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	root := TestSuites{Name: "ackrocheck"}
	for _, file := range files {
		suite := TestSuite{Name: file}
		for _, f := range byFile[file] {
			body := fmt.Sprintf("Resource: %s %s %s\nFile: %s (document %d)\nReason: %s",
				f.ResourceAPIVersion, f.ResourceKind, f.ResourceName, f.FilePath, f.DocumentIndex, f.Message)
			if f.ParentResourceKind != "" {
				body += fmt.Sprintf("\nEmbedded in: %s %s", f.ParentResourceKind, f.ParentResourceName)
			}
			if f.Remediation != "" {
				body += "\nFix: " + f.Remediation
			}
			suite.Cases = append(suite.Cases, TestCase{
				Name:      fmt.Sprintf("%s %s/%s", f.ControlID, f.ResourceKind, f.ResourceName),
				ClassName: f.ControlID,
				Failure: &Failure{
					Message: fmt.Sprintf("[%s] %s", f.Severity, f.Title),
					Type:    f.Status,
					Body:    body,
				},
			})
			suite.Failures++
			suite.Tests++
		}
		root.Suites = append(root.Suites, suite)
		root.Tests += suite.Tests
		root.Failures += suite.Failures
	}

	if len(r.ParseErrors) > 0 {
		suite := TestSuite{Name: "parse-errors"}
		for _, pe := range r.ParseErrors {
			suite.Cases = append(suite.Cases, TestCase{
				Name:      pe.FilePath,
				ClassName: "ParseError",
				Error: &Failure{
					Message: pe.Error,
					Type:    "ParseError",
					Body:    pe.Error,
				},
			})
			suite.Errors++
			suite.Tests++
		}
		root.Suites = append(root.Suites, suite)
		root.Tests += suite.Tests
		root.Errors += suite.Errors
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(&root); err != nil {
		return fmt.Errorf("encoding JUnit XML: %w", err)
	}
	_, err := io.WriteString(w, "\n")
	return err
}
