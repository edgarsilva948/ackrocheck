# KRO resource mappings

AckroCheck has best-effort static support for KRO
(`kro.run/v1alpha1` `ResourceGraphDefinition`).

## What is analyzed

1. The scanner detects RGDs by API group `kro.run` and kind
   `ResourceGraphDefinition`.
2. Embedded resource templates are read from `spec.resources[].template`
   (the legacy `manifest` key is also accepted).
3. Templates with an ACK `apiVersion`/`kind` are evaluated with the normal
   ACK policy engine.
4. Findings carry both the parent RGD (`parent_resource_kind/name`) and the
   embedded resource (`embedded_resource_kind/name`).

## Dynamic values (CEL expressions)

KRO templates frequently contain CEL expressions:

```yaml
spec:
  storageEncrypted: ${schema.spec.encrypted}
```

AckroCheck does **not** evaluate CEL. When a field a control checks is a
templated `${...}` expression, the result is a **WARNING** finding instead of
FAILED: the field is user-controlled at instance creation time and cannot be
statically verified. This is exactly the case the warning is for — an RGD
that exposes encryption, public access, IAM scope, ingress rules, or deletion
protection as user input deserves human review.

Warnings never trigger a non-zero exit code (`--fail-on` counts FAILED
findings only).

## Known limitations

- CEL expressions are not evaluated; conditional resource inclusion
  (`includeWhen`) is ignored.
- `ResourceGraphDefinition` instances (the consumer CRs) are not expanded —
  only the RGD itself is analyzed.
- Cross-resource references (`${database.status.endpoint}`) are treated like
  any other dynamic value.
- Defaults declared in the RGD schema (e.g. `encrypted: boolean | default=true`)
  are not yet folded into the analysis.
