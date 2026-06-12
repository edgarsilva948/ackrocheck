# AckroCheck policy schema

Built-in and external controls are declarative YAML documents. One file may
contain multiple policies separated by `---`. Policies never execute code.

## Full example

```yaml
id: ACKRO_AWS_RDS_001
title: RDS DBInstance should enable storage encryption
description: RDS DBInstance resources should explicitly enable encryption at rest.
severity: HIGH
category: DATA_PROTECTION
resource:
  provider: aws
  service: rds
  type: DBInstance
match:
  apiGroups:
    - rds.services.k8s.aws
  kinds:
    - DBInstance
  productionOnly: false       # optional; see "Production detection"
assertions:
  - path: spec.storageEncrypted
    operator: is_true
    message: spec.storageEncrypted is missing or not true   # optional override
remediation:
  message: Set spec.storageEncrypted to true.
  patch:                       # optional, informational
    spec:
      storageEncrypted: true
references:
  - type: aws_security_hub
    id: RDS.3
compatibility:
  status: stable               # stable | experimental | deprecated
  introducedIn: 0.1.0
notes: Free-text assumptions and limitations.
```

## Fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable identifier, `[A-Z][A-Z0-9_]+`. Never reuse or repurpose. |
| `title` | yes | One-line summary shown in findings. |
| `description` | no | Used as the finding message base. |
| `severity` | yes | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (case-insensitive). |
| `category` | no | Free-form grouping, e.g. `DATA_PROTECTION`. |
| `resource` | no | Informational provider/service/type metadata. |
| `match.apiGroups` | yes | API groups the control applies to (case-insensitive). |
| `match.kinds` | yes | Kinds the control applies to (case-insensitive). |
| `match.productionOnly` | no | Restrict to production-marked resources. |
| `assertions` | yes | List of checks, combined with logical AND. |
| `remediation.message` | recommended | Shown as the `Fix:` line. |
| `remediation.patch` | no | Informational YAML snippet. AckroCheck never modifies files. |
| `references` | no | Links to external standards (`type` + `id`). |
| `compatibility` | recommended | Lifecycle metadata for changelogs. |
| `notes` | recommended | Documented assumptions and limitations. |

## Assertions

Each assertion has a `path`, an `operator`, and (for most operators) a
`value`. Paths are dot-separated and may index lists numerically
(`spec.rules.0.port`). The special path `.` refers to the current document
(or, inside `any`/`all`, the current list element).

### Operators

| Operator | Value | Missing field behaves as |
|---|---|---|
| `exists` | – | FAIL |
| `not_exists` | – | PASS |
| `equals` | any | FAIL |
| `not_equals` | any | PASS |
| `is_true` | – | FAIL |
| `is_false` | – | FAIL |
| `greater_than` | number | FAIL |
| `greater_than_or_equal` | number | FAIL |
| `less_than` | number | FAIL |
| `less_than_or_equal` | number | FAIL |
| `contains` | any | FAIL |
| `not_contains` | any | PASS |
| `match_regex` | string (RE2) | FAIL |
| `not_match_regex` | string (RE2) | PASS |
| `any` | nested `assertions` | see below |
| `all` | nested `assertions` | see below |

Missing-field semantics are deliberate: "positive" requirements
(`equals: true`, `is_true`, `greater_than_or_equal`) fail when the field is
absent, so an omitted `storageEncrypted` fails the same way an explicit
`false` does. "Negative" requirements (`not_equals`, `not_contains`,
`not_match_regex`, `not_exists`) pass when the field is absent.

Value comparison is YAML-friendly: numbers compare across int/float/string
forms (`"14" >= 7` passes), and `"true"`/`"false"` strings compare equal to
booleans under `equals` (but **not** under `is_true`/`is_false`, which require
real booleans).

`contains` means: substring for strings, membership for lists, key presence
for maps.

### `any` and `all`

When the value at `path` is a **list**, they are quantifiers over elements.
An element matches when all nested assertions pass against it:

- `any`: at least one element matches. Empty/missing list **fails**.
- `all`: every element matches. Empty/missing list **passes**.

```yaml
# every ingress rule must avoid 0.0.0.0/0 on port 22
- path: spec.ingressRules
  operator: all
  assertions:
    - path: .
      operator: any        # rule is OK if ANY of these hold
      assertions:
        - path: ipRanges
          operator: all
          assertions:
            - path: cidrIP
              operator: not_equals
              value: "0.0.0.0/0"
        - path: fromPort
          operator: greater_than
          value: 22
        - path: toPort
          operator: less_than
          value: 22
```

When the value at `path` is **not** a list (a map, scalar, or the document
itself via `path: .`), they act as logical combinators over the nested
assertions: `any` = OR, `all` = AND.

```yaml
# pass if EITHER field is acceptable
- path: .
  operator: any
  assertions:
    - path: spec.kmsMasterKeyID
      operator: exists
    - path: spec.sqsManagedSSEEnabled
      operator: is_true
```

### Templated values (KRO)

If the value a comparison operator sees is a `${...}` expression, the result
is **unknown** rather than pass/fail, and the policy reports a WARNING
finding. See `mappings/kro/README.md`.

## Production detection

With `match.productionOnly: true` the control only runs against resources
marked production by any of:

```yaml
metadata:
  labels:
    environment: prod        # or production
    env: production          # or prod
  annotations:
    ackrocheck.dev/environment: production
```

## External controls

Pass `--external-controls <dir-or-file>` to load additional local policies.
They are validated with the same rules as built-in controls and **may not
reuse a built-in control ID** — built-in IDs are stable and cannot be
silently redefined.

## Stability rules

- Control IDs are stable; never renumber or repurpose them.
- Never change what a stable control means. Tighten/loosen behavior only with
  a new control ID, and mark the old one `compatibility.status: deprecated`.
- `compatibility.introducedIn` records the release that added the control.
