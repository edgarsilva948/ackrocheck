# ACK resource mappings

AckroCheck detects ACK resources by API group: any resource whose
`apiVersion` group ends in `.services.k8s.aws` is treated as an ACK resource.
The service name is the group prefix (`rds.services.k8s.aws` → `rds`).

Controls select resources with `match.apiGroups` and `match.kinds`, so adding
support for a new ACK service requires **no Go changes** — only a new policy
file under `controls/aws/<service>/`.

## Field mapping assumptions per service

These are the spec fields the built-in controls rely on, based on the ACK
controller CRDs at the time of writing. If an ACK controller changes its CRD
shape, update the policy paths (and `notes`) here and in the control.

| Service | Kind | Fields used by controls |
|---|---|---|
| rds | DBInstance | `spec.storageEncrypted`, `spec.publiclyAccessible`, `spec.backupRetentionPeriod`, `spec.deletionProtection` |
| s3 | Bucket | `spec.publicAccessBlock.*` (inline, no separate CRD), `spec.encryption.rules[]`, `spec.policy` (JSON string) |
| iam | Policy/Role/User/Group | `spec.policyDocument`, `spec.assumeRolePolicyDocument`, `spec.document`, `spec.policy` (JSON strings or YAML objects) |
| sqs | Queue | `spec.kmsMasterKeyID`, `spec.sqsManagedSSEEnabled`, `spec.policy` |
| sns | Topic | `spec.kmsMasterKeyID`, `spec.policy` |
| ecr | Repository | `spec.imageScanningConfiguration.scanOnPush`, `spec.policy` |
| ec2 | SecurityGroup | `spec.ingressRules[]` with `fromPort`, `toPort`, `ipRanges[].cidrIP`, `ipv6Ranges[].cidrIPv6` (inline rules; ACK has no separate rule CRD) |
| dynamodb | Table | `spec.sseSpecification.enabled` |
| kms | Key | `spec.enableKeyRotation` |
| lambda | Function | `spec.kmsKeyARN` |
| secretsmanager | Secret | `spec.kmsKeyID` |

## IAM policy document normalization

Before evaluation, the scanner parses embedded IAM-style policy documents
(JSON strings or YAML objects) found at `spec.policyDocument`,
`spec.assumeRolePolicyDocument`, `spec.document`, and `spec.policy`, and
injects a canonicalized copy at:

```text
__ackrocheck.policyDocuments.<field>
```

Canonicalization rules:

- `Statement` is always a list (single objects are wrapped)
- `Action`, `NotAction`, `Resource`, `NotResource` are always lists
- `Principal: "*"` becomes `{"AWS": ["*"]}`
- `Effect` is normalized to `Allow`/`Deny`
- `HasCondition: true|false` is added so policies can distinguish
  unconditional public access from access scoped by a `Condition`

Controls reference these normalized paths instead of the raw string.
Unparseable documents are ignored (the control passes — there is nothing to
verify) rather than crashing the scan.
