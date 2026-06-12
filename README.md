# AckroCheck

[![CI](https://github.com/edgarsilva948/ackrocheck/actions/workflows/ci.yaml/badge.svg)](https://github.com/edgarsilva948/ackrocheck/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/edgarsilva948/ackrocheck/graph/badge.svg)](https://codecov.io/gh/edgarsilva948/ackrocheck)
[![Go Report Card](https://goreportcard.com/badge/github.com/edgarsilva948/ackrocheck)](https://goreportcard.com/report/github.com/edgarsilva948/ackrocheck)
[![Go Reference](https://pkg.go.dev/badge/github.com/edgarsilva948/ackrocheck.svg)](https://pkg.go.dev/github.com/edgarsilva948/ackrocheck)
[![Go Version](https://img.shields.io/github/go-mod/go-version/edgarsilva948/ackrocheck)](go.mod)
[![Release](https://img.shields.io/github/v/release/edgarsilva948/ackrocheck?include_prereleases)](https://github.com/edgarsilva948/ackrocheck/releases)
[![License](https://img.shields.io/github/license/edgarsilva948/ackrocheck)](LICENSE)

> Checkov-like security checks for AWS ACK and KRO manifests.

AckroCheck is a static security scanner for Kubernetes YAML that defines AWS
resources through [ACK](https://aws-controllers-k8s.github.io/docs/)
(AWS Controllers for Kubernetes) CRDs and
[KRO](https://kro.run) `ResourceGraphDefinition`. It detects missing or
insecure security configuration — unencrypted databases, public buckets,
wildcard IAM, world-open security groups — before the manifests reach a
cluster.

It is a single self-contained binary:

- **No** container image, daemon, or Kubernetes cluster required
- **No** AWS credentials or AWS API calls
- **No** network access during scans — fully offline and deterministic
- Built-in controls are plain YAML, embedded in the binary, reviewable in
  [`controls/`](controls/)

## Why

Tools like Checkov and tfsec cover Terraform and CloudFormation, but teams
managing AWS through ACK CRDs or KRO resource graphs have the same risks and
no manifest-level scanner. AckroCheck fills that gap with the same shift-left
workflow: scan in CI, fail the build on findings, upload SARIF to GitHub code
scanning.

## Installation

### From a release

Download the binary for your platform from the
[releases page](https://github.com/edgarsilva948/ackrocheck/releases),
unpack, and put `ackrocheck` on your `PATH`. Binaries are published for
linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and windows/amd64, with
checksums.

### From source

```bash
go install github.com/edgarsilva948/ackrocheck/cmd/ackrocheck@latest
```

or clone and build:

```bash
git clone https://github.com/edgarsilva948/ackrocheck
cd ackrocheck
make build        # produces ./bin/ackrocheck
```

## Usage

```bash
# scan a directory recursively (exit 1 if HIGH+ findings)
ackrocheck scan ./manifests

# machine-readable output
ackrocheck scan ./manifests --output json
ackrocheck scan ./manifests --output sarif --output-file results.sarif
ackrocheck scan ./manifests --output junit --output-file results.xml

# tune thresholds
ackrocheck scan ./manifests --fail-on medium     # fail the build on MEDIUM+
ackrocheck scan ./manifests --fail-on none       # never fail, report only
ackrocheck scan ./manifests --severity high      # only report HIGH+

# restrict frameworks
ackrocheck scan ./manifests --framework ack,kro

# bring your own controls (local YAML only)
ackrocheck scan ./manifests --external-controls ./my-controls/

# inspect controls
ackrocheck controls list
ackrocheck controls show ACKRO_AWS_RDS_001

ackrocheck version
```

### Example output

```text
FAILED ACKRO_AWS_RDS_001 HIGH
Resource: rds.services.k8s.aws/v1alpha1 DBInstance app-db
File: manifests/db.yaml:2 (document 0)
Reason: RDS DBInstance resources should explicitly enable encryption at rest. (spec.storageEncrypted is missing or not true)
Fix: Set spec.storageEncrypted to true.

AckroCheck summary:
  Files scanned: 12
  Resources scanned: 18
  Findings: 5
  Critical: 0
  High: 3
  Medium: 2
  Low: 0
  Info: 0
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the fail threshold (default `high`) |
| `1` | Findings at or above the fail threshold |
| `2` | Scan error or invalid CLI usage |

Parse errors in individual files do **not** abort the scan; they are reported
and the remaining files are scanned.

## Supported resources (MVP)

| Service | Kind | Controls |
|---|---|---|
| RDS | DBInstance | storage encryption, public access, backup retention ≥ 7, deletion protection (production) |
| S3 | Bucket | public access block (4 settings), server-side encryption, public bucket policy |
| IAM | Policy, Role, User, Group | `Action: "*"`, sensitive actions on `Resource: "*"`, wildcard trust principal, `iam:PassRole` on `*` |
| SQS | Queue | KMS/SSE encryption, public queue policy |
| SNS | Topic | KMS encryption, public topic policy |
| ECR | Repository | scan-on-push, public repository policy |
| EC2 | SecurityGroup | 0.0.0.0/0 and ::/0 ingress on 22/3389, 0.0.0.0/0 on database ports |
| DynamoDB | Table | KMS SSE |
| KMS | Key | key rotation |
| Lambda | Function | customer-managed KMS key |
| Secrets Manager | Secret | customer-managed KMS key |

Run `ackrocheck controls list` for the authoritative list. Field mapping
assumptions per service are documented in
[`mappings/ack/README.md`](mappings/ack/README.md).

Production-only controls (currently RDS deletion protection) detect
production resources via `metadata.labels` `environment`/`env` set to
`prod`/`production`, or the annotation
`ackrocheck.dev/environment: production`.

## KRO support

AckroCheck statically analyzes `kro.run/v1alpha1` `ResourceGraphDefinition`s:
embedded ACK resource templates under `spec.resources[].template` are scanned
with the normal policy engine, and findings carry both the RGD and the
embedded resource context.

KRO templates may expose security-relevant fields as user input via CEL
expressions (`storageEncrypted: ${schema.spec.encrypted}`). AckroCheck does
**not** evaluate CEL — such fields produce **WARNING** findings ("value is
user-controlled and cannot be statically verified") instead of pass/fail.
Warnings never affect the exit code. Full limitations:
[`mappings/kro/README.md`](mappings/kro/README.md).

## Policy format

Controls are declarative YAML — no Rego, no plugins, no executed code:

```yaml
id: ACKRO_AWS_RDS_001
title: RDS DBInstance should enable storage encryption
severity: HIGH
match:
  apiGroups: [rds.services.k8s.aws]
  kinds: [DBInstance]
assertions:
  - path: spec.storageEncrypted
    operator: is_true
remediation:
  message: Set spec.storageEncrypted to true.
```

Missing fields fail "positive" assertions: an omitted `storageEncrypted`
fails the same way an explicit `false` does. The full schema, all 16
operators, and `any`/`all` composition rules are documented in
[`docs/policy-schema.md`](docs/policy-schema.md). Adding a control:
[`docs/adding-a-control.md`](docs/adding-a-control.md).

## CI examples

### GitHub Actions with code scanning

```yaml
jobs:
  ackrocheck:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Install AckroCheck
        run: go install github.com/edgarsilva948/ackrocheck/cmd/ackrocheck@latest
      - name: Scan manifests
        run: ackrocheck scan ./manifests --output sarif --output-file results.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - name: Gate on high severity
        run: ackrocheck scan ./manifests --quiet
```

### GitLab CI with JUnit report

```yaml
ackrocheck:
  image: golang:1.26
  script:
    - go install github.com/edgarsilva948/ackrocheck/cmd/ackrocheck@latest
    - ackrocheck scan ./manifests --output junit --output-file results.xml
  artifacts:
    when: always
    reports:
      junit: results.xml
```

## Development

```bash
make test                 # run all tests
make test-coverage        # coverage.out + coverage.html
make lint                 # gofmt check + go vet
make build                # ./bin/ackrocheck
make run-example          # scan the bundled failing fixtures
make goreleaser-snapshot  # local multi-platform snapshot build (requires goreleaser)
```

Releases are produced by GoReleaser when a `v*` tag is pushed
(`.github/workflows/release.yaml`). No Docker involved.

### Test coverage

CI runs the full suite with coverage on every push. Current totals are ~95%
overall, with the policy engine, parser, and report generation above 90%.
Targets: ≥80% total, ≥90% for engine/parser/report packages.

Example manifests live in [`testdata/pass`](testdata/pass) (clean),
[`testdata/fail`](testdata/fail) (findings), and
[`testdata/kro`](testdata/kro) (RGDs, including one with templated fields).

## Known limitations (MVP)

- **No CEL evaluation** — templated KRO fields are warnings, not verdicts;
  RGD schema defaults are not folded in.
- **Static analysis only** — controls see what the manifest declares. Account
  defaults, registry-level ECR settings, or resources created outside ACK are
  invisible.
- **IAM analysis is structural** — wildcard detection covers `*` and a
  conservative sensitive-action list; it is not a full IAM Access Analyzer.
- **Line numbers point at document starts**, not the failing field.
- **No suppression/skip mechanism yet** (no inline `ackrocheck:skip`
  comments or baseline file).
- **External controls are local YAML only** — by design; no remote policy
  fetching and no executable policies.
- Coverage of ACK services is the table above; other ACK controllers parse
  fine but have no controls yet.

## Roadmap

- Field-accurate line numbers in findings
- Inline suppression comments and a baseline file
- KRO schema default folding and instance-overlay analysis
- More ACK service families (EKS, ElastiCache, OpenSearch, MQ, …)
- CIS/Security Hub control mappings in `references`
- An `ackrocheck controls validate` command for external control authoring

## License

Apache-2.0 (see [LICENSE](LICENSE)).
