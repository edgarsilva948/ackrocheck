// Command ack-inventory regenerates the committed ACK controller inventory
// (mappings/ack/inventory.json) and the coverage report (docs/coverage.md).
//
// It enumerates every <service>-controller repo in the aws-controllers-k8s
// GitHub org, pins each to its latest release tag, downloads the CRD
// manifests and flattens their OpenAPI v3 spec schemas into field paths.
// Output is deterministic for a given set of release tags, so a git diff of
// the inventory is exactly the upstream schema drift since the last run.
//
// Usage:
//
//	go run ./tools/ack-inventory [-out mappings/ack/inventory.json] [-coverage docs/coverage.md]
//	go run ./tools/ack-inventory -drift-report drift.md -issues-json issues.json
//
// With -drift-report, the committed inventory at -out is loaded before being
// overwritten and the differences are classified (broken policies, new
// services/kinds/fields, release bumps) into a markdown report. With
// -issues-json, actionable drift categories are additionally written as a
// JSON list of {title, labels, body} for the weekly workflow to open as
// GitHub issues.
//
// Authentication: GITHUB_TOKEN/GH_TOKEN, or `gh auth token`.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/edgarsilva948/ackrocheck/controls"
	"github.com/edgarsilva948/ackrocheck/internal/ackinv"
)

func main() {
	var (
		out         = flag.String("out", "mappings/ack/inventory.json", "inventory output path")
		coverage    = flag.String("coverage", "docs/coverage.md", "coverage report output path (empty to skip)")
		driftReport = flag.String("drift-report", "", "write a markdown drift report comparing the previous committed inventory (empty to skip)")
		issuesJSON  = flag.String("issues-json", "", "write actionable drift as a JSON issue list (empty to skip)")
		org         = flag.String("org", ackinv.DefaultOrg, "GitHub organization")
		concurrency = flag.Int("concurrency", 8, "concurrent controller fetches")
	)
	flag.Parse()

	if err := run(*out, *coverage, *driftReport, *issuesJSON, *org, *concurrency); err != nil {
		fmt.Fprintf(os.Stderr, "ack-inventory: %v\n", err)
		os.Exit(1)
	}
}

func run(out, coverage, driftReport, issuesJSON, org string, concurrency int) error {
	var previous *ackinv.Inventory
	if driftReport != "" || issuesJSON != "" {
		prev, err := ackinv.Load(out)
		if err != nil {
			return fmt.Errorf("drift requested but cannot load previous inventory: %w", err)
		}
		previous = prev
	}

	client := ackinv.NewClient(org)
	if client.Token == "" {
		fmt.Fprintln(os.Stderr, "warning: no GitHub token found; unauthenticated rate limits apply")
	}

	repos, err := client.ListControllerRepos()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "found %d controller repos in %s\n", len(repos), org)

	type result struct {
		svc *ackinv.Service
		err error
	}
	results := make([]result, len(repos))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, repo := range repos {
		wg.Add(1)
		go func(i int, repo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			svc, err := client.BuildService(repo)
			results[i] = result{svc, err}
		}(i, repo)
	}
	wg.Wait()

	inv := &ackinv.Inventory{Org: org}
	var failed []error
	for i, r := range results {
		if r.err != nil {
			failed = append(failed, r.err)
			fmt.Fprintf(os.Stderr, "error: %v\n", r.err)
			continue
		}
		inv.Services = append(inv.Services, *r.svc)
		fmt.Fprintf(os.Stderr, "  %-28s %-10s %d kinds\n", repos[i], orNone(r.svc.Release), len(r.svc.Kinds))
	}
	// Partial inventories make drift diffs lie (a transient fetch failure
	// would look like a removed service), so any failure aborts the run.
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d controllers failed; inventory not written", len(failed), len(repos))
	}

	if err := ackinv.Save(out, inv); err != nil {
		return fmt.Errorf("writing inventory: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d services)\n", out, len(inv.Services))

	policies, err := controls.Builtin()
	if err != nil {
		return fmt.Errorf("loading built-in controls: %w", err)
	}

	if coverage != "" {
		report := ackinv.CoverageReport(inv, policies)
		if err := os.WriteFile(coverage, []byte(report), 0o644); err != nil {
			return fmt.Errorf("writing coverage report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", coverage)
	}

	if previous == nil {
		return nil
	}
	drift := ackinv.Classify(previous, inv, policies)
	if driftReport != "" {
		if err := os.WriteFile(driftReport, []byte(drift.Report()), 0o644); err != nil {
			return fmt.Errorf("writing drift report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", driftReport)
	}
	if issuesJSON != "" {
		issues := drift.Issues()
		if issues == nil {
			issues = []ackinv.Issue{}
		}
		data, err := json.MarshalIndent(issues, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(issuesJSON, append(data, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing issues JSON: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d issues)\n", issuesJSON, len(issues))
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
