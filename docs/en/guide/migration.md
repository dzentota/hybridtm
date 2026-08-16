# Migrating from plain `hybridtm`

If you started with just the `hybridtm/hybridtm` library (DSL + code
attributes + `hybridtm analyze`/`compile`) and want Studio's
persistence, multi-tenancy, and canvas editor, nothing about your
existing setup needs to change — Studio is additive.

## Your DSL keeps working

`threat-model.php` and any `#[DataFlow]`/`#[Mitigation]` attributes in
your source are unaffected. `PhpDslWriter`/`PhpDslReader` round-trip
the same file format Studio's export/import endpoints use, so a model
you've hand-written can be imported directly:

```bash
curl -X POST http://127.0.0.1:8000/threat-model-projects/{id}/import/php \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @threat-model.php
```

`PhpDslReader` parses via AST (never `require`s the uploaded file — see
ADR-08), and surfaces anything outside its recognizable subset as a
warning rather than failing outright: you get a partial model back,
not an error.

## Your KB keeps working

Point Studio's KB loader at your existing KB directory instead of the
bundled one — `apps/api/config/services.yaml`'s `kb_paths` parameter
is a list, later paths overriding earlier ones (the same layering
`YamlKbLoader` already does for you). Nothing about the KB YAML format
changed.

## What you gain, and what stays a CLI-only concern

| Capability | Plain `hybridtm` | Studio |
|---|---|---|
| Run analysis | `hybridtm analyze` | Same Rule Engine, via API or canvas |
| Compile to Threagile | `hybridtm compile` | Same codec, via `export/threagile` |
| Persistence | You manage the file | `ModelVersion` history, optimistic locking |
| Multi-user | — | Multi-tenancy, 5-role project RBAC |
| Governance | — | Draft→Approved workflow, policy-as-code |
| Audit trail | Your VCS history | Append-only `AuditLogEntry` per change |
| Visual editing | — | Studio's canvas |

Nothing forces the switch wholesale: `hybridtm analyze`/`compile`
remain fully functional standalone commands, and CI pipelines built
around them (see the [hybridtm-analyze GitHub
Action](https://github.com/hybridtm/hybridtm/tree/main/.github/actions/hybridtm-analyze))
don't need Studio running at all.
