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

**Status: stable.** The CLI flags, exit codes, output formats (text/JSON/SARIF/
JUnit), and control IDs are stable and follow semantic versioning — a control's
meaning never changes under a fixed ID (see [stability rules](docs/policy-schema.md#stability-rules)).
The scope is deliberately minimal today (21 ACK services, 49 controls) and
growing; see [What's next](#whats-next). Safe to wire into CI now.

It is a single self-contained binary:

- **No** container image, daemon, or Kubernetes cluster required
- **No** AWS credentials or AWS API calls
- **No** network access during scans — fully offline and deterministic
- Built-in controls are plain YAML, embedded in the binary, reviewable in
  [`controls/`](controls/)
- Every control's assertion paths are validated against the real ACK CRD
  schemas in CI, and a weekly job tracks upstream schema drift
  ([`docs/coverage.md`](docs/coverage.md))

## Why

Tools like Checkov and tfsec cover Terraform and CloudFormation, but teams
managing AWS through ACK CRDs or KRO resource graphs have the same risks and
no manifest-level scanner. AckroCheck fills that gap with the same shift-left
workflow: scan in CI, fail the build on findings, upload SARIF to GitHub code
scanning.

## Installation

Pick the method that fits the environment. All releases ship signed checksums
and binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and
windows/amd64.

### Homebrew (macOS / Linux)

```bash
brew install edgarsilva948/tap/ackrocheck
```

Upgrades come through `brew upgrade`. The cask removes the macOS quarantine
bit on install, so no Gatekeeper prompt.

### Install script (laptops & CI)

Downloads the release archive for your OS/arch, verifies it against the
published `checksums.txt`, and installs the binary:

```bash
curl -fsSL https://raw.githubusercontent.com/edgarsilva948/ackrocheck/main/install.sh | sh
```

Pin a version and/or install location (recommended for CI — reproducible and
no surprise upgrades):

```bash
curl -fsSL https://raw.githubusercontent.com/edgarsilva948/ackrocheck/main/install.sh \
  | ACKROCHECK_VERSION=v0.1.0 ACKROCHECK_BIN_DIR="$HOME/.local/bin" sh
```

The script refuses to install if the checksum cannot be verified. It needs
only `curl`/`wget`, `tar`, and `sha256sum`/`shasum`.

### `go install`

```bash
go install github.com/edgarsilva948/ackrocheck/cmd/ackrocheck@latest
```

Convenient where a Go toolchain is already present, but slower in CI (it
compiles from source) and resolves the latest tag rather than a pinned binary.

### Manual download

Grab the archive for your platform from the
[releases page](https://github.com/edgarsilva948/ackrocheck/releases), verify
it against `checksums.txt`, unpack, and put `ackrocheck` on your `PATH`. This
is the only path for Windows today (download the `.zip`).

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

# also show the controls that passed (in green)
ackrocheck scan ./manifests --show-passed

# bring your own controls (local YAML only)
ackrocheck scan ./manifests --external-controls ./my-controls/

# inspect controls
ackrocheck controls list
ackrocheck controls show ACKRO_AWS_RDS_001

ackrocheck version
```

### Example output

Each finding shows the resource, the exact reason, a copy-paste fix, and a
link to the control's [guide](https://edgarsilva948.github.io/ackrocheck/controls/):

```text
FAILED ACKRO_AWS_RDS_001 HIGH  RDS DBInstance should enable storage encryption
  Resource: rds.services.k8s.aws/v1alpha1 DBInstance app-db
  File: manifests/db.yaml:2 (document 0)
  Reason: RDS DBInstance resources should explicitly enable encryption at rest. (spec.storageEncrypted is missing or not true)
  Fix: Set spec.storageEncrypted to true.
  Apply:
      spec:
          storageEncrypted: true
  Guide: https://edgarsilva948.github.io/ackrocheck/controls/ackro_aws_rds_001/

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

With `--show-passed`, controls that passed are also listed (green) with a
`Passed:` count in the summary — useful as evidence of what was verified.
The control guide is generated from the control YAML and published to GitHub
Pages (`make controls-docs`).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the fail threshold (default `high`) |
| `1` | Findings at or above the fail threshold |
| `2` | Scan error or invalid CLI usage |

Parse errors in individual files do **not** abort the scan; they are reported
and the remaining files are scanned.

## Supported resources

49 controls across 21 ACK services. Each control maps to an AWS Security Hub
FSBP control and/or an AWS Config rule (see each control's `references`).

| Service | Kind(s) | What it checks |
|---|---|---|
| RDS | DBInstance | storage encryption, public access, backup retention ≥ 7, deletion protection (prod) |
| S3 | Bucket | public access block (4 settings), server-side encryption, public bucket policy |
| IAM | Policy, Role, User, Group | `Action: "*"`, sensitive actions on `Resource: "*"`, wildcard trust principal, `iam:PassRole` on `*` |
| EC2 | SecurityGroup | 0.0.0.0/0 and ::/0 ingress on 22/3389, 0.0.0.0/0 on database ports |
| EKS | Cluster | private endpoint, KMS secrets encryption, audit logging |
| ECS | Service, TaskDefinition | no auto-assigned public IPs, no privileged containers |
| ElastiCache | ReplicationGroup | encryption at rest and in transit |
| EFS | FileSystem | encryption at rest |
| ELBv2 | Listener | HTTP→HTTPS redirect |
| CloudFront | Distribution | encryption in transit, access logging |
| MSK (Kafka) | Cluster | TLS in transit, no unauthenticated access |
| DocumentDB | DBCluster | storage encryption, deletion protection (prod) |
| OpenSearch | Domain | encryption at rest, node-to-node encryption, enforce HTTPS |
| CloudTrail | Trail | KMS log encryption, log file validation |
| SQS | Queue | KMS/SSE encryption, public queue policy |
| SNS | Topic | KMS encryption, public topic policy |
| ECR | Repository | scan-on-push, public repository policy |
| DynamoDB | Table | KMS SSE |
| KMS | Key | key rotation |
| Lambda | Function | customer-managed KMS key |
| Secrets Manager | Secret | customer-managed KMS key |

Run `ackrocheck controls list` for the authoritative list and
[`docs/coverage.md`](docs/coverage.md) for service/kind coverage against the
full ACK CRD inventory. Field mapping assumptions per service are documented
in [`mappings/ack/README.md`](mappings/ack/README.md).

Production-only controls (RDS and DocumentDB deletion protection) detect
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
        run: |
          curl -fsSL https://raw.githubusercontent.com/edgarsilva948/ackrocheck/main/install.sh \
            | ACKROCHECK_VERSION=v0.1.0 sh
      - name: Scan manifests
        run: ackrocheck scan ./manifests --output sarif --output-file results.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - name: Gate on high severity
        run: ackrocheck scan ./manifests --quiet
```

Pin `ACKROCHECK_VERSION` to a real release tag so builds are reproducible and
the checksum is verified.

### GitLab CI with JUnit report

```yaml
ackrocheck:
  image: alpine:3
  before_script:
    - apk add --no-cache curl tar
    - curl -fsSL https://raw.githubusercontent.com/edgarsilva948/ackrocheck/main/install.sh
        | ACKROCHECK_VERSION=v0.1.0 sh
  script:
    - ackrocheck scan ./manifests --output junit --output-file results.xml
  artifacts:
    when: always
    reports:
      junit: results.xml
```

## What's next

AckroCheck is stable but intentionally small. The near-term direction:

- **Broaden coverage.** More controls per covered service and more ACK service
  families (MemoryDB, MQ, Route 53, API Gateway, ACM, and uncovered kinds of
  services already supported). The weekly drift job surfaces new services and
  fields as ACK ships them; see [`docs/coverage.md`](docs/coverage.md).
- **Suppression & baselines.** Inline `ackrocheck:ignore` comments and a
  baseline file to adopt the tool on existing repos without a wall of findings.
- **Field-accurate line numbers.** Findings currently point at the start of the
  YAML document; the goal is the exact offending field.
- **Deeper KRO analysis.** Fold `ResourceGraphDefinition` schema defaults and
  instance overlays into evaluation instead of warning on every CEL expression.
- **External control ergonomics.** An `ackrocheck controls validate` command so
  teams authoring their own YAML controls get the same CRD-path validation the
  built-in controls get in CI.

### Current limitations

- **Static analysis only** — controls see what the manifest declares. Account
  defaults, runtime state, and resources created outside ACK are invisible.
- **No CEL evaluation** — templated KRO fields are warnings, not verdicts.
- **IAM analysis is structural** — wildcard and sensitive-action detection, not
  a full IAM Access Analyzer.
- **External controls are local YAML only** — by design; no remote fetching and
  no executable policies.

## License

Apache-2.0 (see [LICENSE](LICENSE)).
