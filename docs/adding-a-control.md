# Adding a new control

Built-in controls are plain YAML files embedded into the binary with
`go:embed`. No Go changes are needed for a new check on an existing or new
ACK service.

## Steps

1. **Pick a stable ID.** Format: `ACKRO_AWS_<SERVICE>_<NNN>`, e.g.
   `ACKRO_AWS_RDS_005`. Use the next free number for the service; never reuse
   a retired number.

2. **Create or extend a policy file** under `controls/aws/<service>/`.
   One file can hold several related policies separated by `---`. See
   [docs/policy-schema.md](policy-schema.md) for the schema and operators.

3. **Document assumptions** in the `notes` field — especially which ACK CRD
   fields the control reads and what missing fields mean. If you add a new
   service, add a row to `mappings/ack/README.md`.

4. **Add fixtures**: a failing manifest in `testdata/fail/` and a passing one
   in `testdata/pass/`, then extend `TestFailFixtures` /
   `TestPassFixturesProduceNoFindings` in
   `internal/scanner/scanner_test.go` with the new control ID.

5. **Run the suite**:

   ```bash
   make test
   ```

   The embedded loader validates every policy at load time; an invalid policy
   fails `TestBuiltinControlsLoad` immediately.

6. **Verify by hand**:

   ```bash
   make build
   ./bin/ackrocheck controls show ACKRO_AWS_RDS_005
   ./bin/ackrocheck scan testdata/fail --no-color
   ```

## Custom (external) controls

Users can ship their own controls without forking:

```bash
ackrocheck scan ./manifests --external-controls ./my-controls/
```

External controls use the same schema, are validated the same way, and may
not reuse built-in IDs. Use your own prefix, e.g. `ACME_AWS_RDS_001`.

## Adding a new ACK service mapping

Nothing in Go needs to change. ACK detection is generic (any group ending in
`.services.k8s.aws`). To support a new service:

1. Create `controls/aws/<service>/` with at least one policy whose
   `match.apiGroups` lists the service group.
2. Document the CRD fields the policies rely on in `mappings/ack/README.md`.
3. Add pass/fail fixtures and test expectations.

## Adding a new KRO mapping

KRO extraction lives in `internal/kro/kro.go`. The MVP reads
`spec.resources[].template` (and `manifest`). If KRO adds a new embedding
shape, extend `ExtractEmbedded` and add a fixture under `testdata/kro/`.
Document any new limitation in `mappings/kro/README.md`.
