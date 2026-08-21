# Knowledge Base Authoring

The KB is a directory of YAML files, one entity per file, validated
against JSON Schemas in `schema/kb/*.json` — copy an example from
`examples/kb/*.json` rather than starting from a blank file. Loaded via
`HybridTM\Kb\YamlKbLoader`, which also resolves `spec.extends` chains.

Five entity kinds, identified by `kind:`:

| Kind | Id pattern | Purpose |
|---|---|---|
| `Component` | `db-mysql`, `abstract/relational-db` | A palette entry: traits, properties, ports, which rules apply |
| `Threat` | `THREAT-SOME-NAME` | Title, summary, STRIDE, base likelihood/impact, standards mappings |
| `Countermeasure` | `CM-SOME-NAME` | Remediation: cost/effort/effectiveness, implementation hints per product |
| `Rule` | `category/some-rule` | A `when`/`unless`/`then` condition, or a PHP class for graph-shaped rules |
| `Trait` | `snake_case_name` | Documents a trait string for the Studio palette — optional, `hasTrait()` works without one |

## A minimal component

```yaml
apiVersion: hybridtm.io/kb/v1
kind: Component
metadata:
  id: db-mysql
  name: MySQL
  version: 1.0.0
  categories: [data, datastore]
  maturity: stable
spec:
  extends: abstract/relational-db
  mapping:
    type: datastore   # required on every file, even with extends — schema
                       # validation runs per-file, before extends resolves
    technologies: [database]
  properties:
    - { id: version, label: 'MySQL version', type: string, group: 'General' }
  rules: []
```

`extends` merges the parent's `traits`/`properties`/`ports`/`rules`/
`mapping` — a child only needs to declare what's genuinely new.

## The one mistake to avoid

A component's `rules:` list is **palette-display metadata only** — the
Rule Engine evaluates every component-scope rule in the whole KB
against every technical asset in the model, filtered solely by that
rule's own `when` condition, regardless of which component's `rules:`
array mentions it.

This matters because an unset property reads back as its type's zero
value (`false`, `''`, `0`) — never "unknown". If you put a property on
one concrete component and scope a rule with a trait that *other*
components sharing that trait also have, every one of those other
components gets evaluated against a property it never declared, and a
`== false` check can spuriously fire on all of them.

**Fix:** either

- put the property on the shared abstract ancestor (making it
  genuinely universal to everything with that trait), or
- add a new trait specific enough that only the intended components
  declare it, and scope the rule with that (traits carry no such
  false-positive risk — `hasTrait()` is a real membership check, not a
  property read with a type-zero fallback).

## A minimal rule

```yaml
apiVersion: hybridtm.io/kb/v1
kind: Rule
metadata:
  id: storage/unencrypted-at-rest
  priority: 100
spec:
  scope: component   # component | flow | boundary | model
  description: 'Datastore holding data without encryption at rest.'
  when:
    all:
      - "component.hasTrait('datastore')"
      - "component.props.bool('encryption_at_rest') == false"
  unless:
    any:
      - "component.hasMitigationFor('CWE-311')"
  then:
    - raise: THREAT-DATA-AT-REST-UNENCRYPTED
      require: [CM-ENCRYPT-AT-REST]
    - suggest_fix:
        set: { encryption_at_rest: true }
        label: 'Enable encryption at rest'
```

### The expression sandbox

`when`/`unless` conditions run through symfony/expression-language, but
the sandbox is structural, not a runtime interceptor: `component`
exposes only `ComponentSubject`'s public surface — `id`, `name`,
`encryption`, `internet`, `redundant`, `multiTenant`,
`customDevelopedParts`, `outOfScope`, `props`, `hasTrait(...)`,
`hasAllTraits(...)`, `storesConfidentialityAtLeast(...)`,
`hasMitigationFor(...)`. Flow-scope rules additionally get `flow`
exposing `source`/`target` (each a `ComponentSubject`), `protocol`
(`.value`, `.isEncrypted()`), `vpn`, `ipFiltered`, `readonly`,
`crossesTrustBoundary()`, `carriesDataAtLeast(...)`. Nothing else is
reachable from a rule expression.

### Derived traits

Computed by the engine itself from model topology, available to any
rule via `hasTrait(...)` without any component declaring them:
`internet_reachable`, `stores_pii`, `handles_strictly_confidential`,
`single_point_of_failure`, `directly_exposed_datastore`, `behind_waf`.

## Golden-file fixtures

Every declarative rule needs a fixture pair in
`tests/Fixtures/Rules/<name>.json` — a `positive` canonical model that
triggers it, a `negative` one that doesn't. `RuleGoldenFileTest`
fails the build if a rule has no fixture, and runs every fixture
through the real Rule Engine + the real KB.
