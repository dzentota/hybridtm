# The Recognizable PHP DSL Subset (ADR-08)

`threat-model.php` is plain, executable PHP — running it with `php bin/hybridtm compile` always
works no matter what it contains. But two other tools need to *read* it without executing it:

- **`PhpDslReader`** (T-4.3), used anywhere `require`-ing an arbitrary uploaded file would be a
  remote-code-execution risk — a web editor, a multi-tenant API, a CI step that only wants to
  inspect a file a contributor changed.
- **HybridTM Studio's** round-trip editor, which needs to parse a hand-written DSL file, let you
  edit it visually, and write it back without mangling whatever it didn't understand.

Both work by parsing the file's AST (`nikic/php-parser`) and recognizing a deliberately narrow
grammar — a **subset** of PHP, not all of it. A file that stays inside the subset round-trips
losslessly. A file that steps outside it still gets read as far as possible (per-construct, not
all-or-nothing) — every construct outside the subset is reported with its line number, and the
model built from everything that *was* recognized is still returned. Only writing the file back
out is unsafe once it contains something the writer can't reproduce.

This document is that subset's specification. If `PhpDslReader` and this document disagree, the
code is authoritative and this document has a bug — file it as one.

## Why a subset at all, and not just `require`

`require` executes the file: any function call, any loop, any side effect in it runs with full
PHP privileges. That's fine for a trusted developer running `hybridtm compile` on their own
machine. It is never fine for a service that accepts someone else's `threat-model.php` — accepting
that file and `require`-ing it is accepting arbitrary code execution from whoever wrote it.

The alternative is to read the file's structure without running it: parse it into an AST, then
walk only the parts of that AST that have one unambiguous meaning, and construct the equivalent
`ThreatModel` object directly by calling its real constructors and setters with the literal values
extracted from the source. That is what `DslVisitor` does. It never calls `eval`, never
`require`s the file, and never executes a function or method defined *in* the DSL file.

## The grammar

### 1. Entity construction

```php
$model = new ThreatModel('My App');
$web   = new TechnicalAsset('web-app', 'Web Application');
$pii   = new DataAsset('customer-pii', 'Customer PII');
$dmz   = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
$story = new AbuseCase('brute-force-login', 'Guess passwords at login');
```

Recognized: `new ThreatModel(...)`, `new TechnicalAsset(...)`, `new DataAsset(...)`,
`new TrustBoundary(...)`, `new AbuseCase(...)`, assigned to a plain variable (`$foo = new ...`). Constructor arguments
must themselves be recognizable values (§3) — most commonly string literals for `id`/`name`, and
for `TrustBoundary`'s third argument, a `TrustBoundaryType::Case` enum reference.

**Not recognized** — constructing any other class, or constructing one of the above with a
computed class name:

```php
$link = new CommunicationLink('a-to-b', 'b');   // only produced via ->communicatesTo(), never `new` directly
$class = 'TechnicalAsset';
$web = new $class('web-app');                    // dynamic class name
```

### 2. Property assignment

```php
$web->description     = 'Public-facing storefront';
$web->technology       = Technology::WebServiceRest;
$web->internet         = true;
$web->dataAssetsStored = ['customer-pii', 'session-token'];
```

Recognized: `$var->property = <value>;` where `$var` is a tracked variable (one built by a
recognized `new` expression, or received from a recognized method call — see §4) and `<value>` is
a **literal**, an **enum case reference**, or a **literal array** of either (§3). The property
must actually exist on the object — a typo'd property name is reported, not silently accepted (PHP
itself would only emit a deprecation notice for an undeclared dynamic property and let it through;
the reader checks explicitly instead).

**Not recognized** — anything computed on the right-hand side:

```php
$web->description = 'Handles ' . $orderCount . ' orders/day';   // string concatenation
$web->internet     = $isPublicFacing;                            // a variable, not a literal
$web->encryption   = Encryption::from($configuredEncryption);     // a function call
```

### 3. Recognized values

| Kind | Example | Notes |
|---|---|---|
| String literal | `'customer-pii'` | No interpolation (`"...${x}..."` is not a plain string literal) |
| Integer / float literal | `42`, `3.14` | |
| Boolean / null | `true`, `false`, `null` | |
| Enum case reference | `Technology::WebServiceRest` | Class must be one of the 16 enums the DSL uses (see `DslVisitor::ENUM_CLASSES`) |
| Array literal | `['a', 'b']`, `['x' => 1]` | Every element must itself be a recognized value — an array containing a variable or a function call is not recognized |

### 4. `->communicatesTo(...)`

```php
$web->communicatesTo(
    targetId: 'user-db',
    protocol: Protocol::SqlAccessProtocolEncrypted,
    authentication: Authentication::Credentials,
    authorization: Authorization::TechnicalUser,
    description: 'Reads and writes user records',
);
```

Recognized as a bare statement (the common case — the link's identity is fully determined by its
source and target, so nothing needs to be captured). Positional or named arguments both work.

If you need to set a field `communicatesTo()` doesn't take as a constructor argument — `vpn`,
`ipFiltered`, `readonly`, `dataSent`, `dataReceived`, `tags`, or a non-default `usage` — capture
the return value and assign to it afterward, same as any other tracked variable:

```php
$link = $web->communicatesTo(targetId: 'user-db');
$link->vpn       = true;
$link->dataSent  = ['session-token'];
```

**Not recognized** — passing a `CommunicationLink` you already have (there is no `new
CommunicationLink(...)` in the grammar to produce one) or computing the target id:

```php
$web->communicatesTo(targetId: $downstreamServices[0]);   // computed argument
```

### 5. `->addAssets(...)`

```php
$dmz->addAssets('web-app', 'api-gateway');
```

Recognized with any number of string-literal arguments.

### 6. Attaching to the model

```php
$model->addTechnicalAsset($web);
$model->addDataAsset($pii);
$model->addTrustBoundary($dmz);
$model->addAbuseCase($story);
```

Recognized when the argument is a plain variable referring to something already tracked (built by
a recognized `new`). **Not recognized** — an inline `new` expression as the argument, since
nothing captures a name for the reader to track it under:

```php
$model->addTechnicalAsset(new TechnicalAsset('web-app'));   // construct it in its own statement first
```

`AbuseCase` scalar properties (`asA`, `iWant`, `soThat`, `actorId`, array fields, `status` via
`AbuseCaseStatus::…`) are assigned like any other entity property (§2).

### 7. The file's shell

`declare(strict_types=1);`, `use` imports, and a single trailing `return $model;` (where `$model`
is the tracked `ThreatModel` variable) are expected and are not treated as part of the "logic" —
they're always accepted. A `require`/`require_once`/`include`/`include_once` statement (e.g.
`require_once __DIR__ . '/vendor/autoload.php';`, needed to run the file standalone with plain
`php`) is likewise accepted and ignored — it has no bearing on model construction.

## What's outside the subset entirely

Not "not yet recognized" — genuinely a different, separately-scoped concern:

- **Control flow** — `if`, `foreach`, `while`, ternaries, match expressions used as statements.
  A DSL file with a loop generating ten similar assets can't be represented as "the same ten
  `new TechnicalAsset(...)` calls" without running the loop, which the reader will never do.
- **Function and method calls** other than the six listed above — `strtoupper(...)`,
  a helper function you defined in the same file, `$model->getTechnicalAsset(...)`, etc.
- **`PropertyBag`** (`$web->properties->set('internet_facing', true)`) and the multi-value
  **`TechnologyList`** (`$web->technologies->add(Technology::ReverseProxy)`) — both are method
  calls on a nested object, one level beyond what's recognized. Round-tripping these needs its own
  grammar extension, not a stretch of the current one.
- **Every remaining T-1.1 governance entity** — `Question`, `SecurityRequirement`,
  `SharedRuntime`, `IndividualRiskCategory`, `RiskTracking`. (`AbuseCase` / Abuser Stories
  *are* in the recognizable subset and round-trip via `PhpDslWriter` / `PhpDslReader`.)

## What happens when a file isn't fully recognized

`DslReadResult::isCanonical()` is `false`, and `DslReadResult::$nonCanonical` lists every
unrecognized construct with its line number and a short reason. The `$model` on the result is
still populated with everything that *could* be built from the recognized parts of the file —
reading and viewing stay available, per ADR-08. What stops being safe is writing the file back
out: `PhpDslWriter` only knows how to reproduce what it itself would have written, so writing a
non-canonical file's model back would silently drop whatever wasn't recognized. Studio's editor
opens such a file read-only with a banner pointing at the first unrecognized line, rather than
risk that.
