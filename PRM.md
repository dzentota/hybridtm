---

# PRD: HybridTM (PHP Threat Modeler)

**The Unified PyTM & Threatspec Port for PHP**

## 1. Product Overview

**Project Name:** HybridTM (or PhpTM)

**Goal:** To create a unified continuous threat modeling framework for PHP that combines "Threat Modeling WITH Code" (a PyTM port) and "Threat Modeling IN Code" (a Threatspec port using PHP 8 Attributes).

**How it Works:** Developers define high-level infrastructure (servers, databases) in a standalone file (PyTM-style), while business logic and data flows are annotated directly within the application source code (Threatspec-style). A CLI compiler powered by an AST (Abstract Syntax Tree) engine statically analyzes the code, merges both models into a single graph, and exports it in Open Threat Model (OTM) format for CI/CD integration.

## 2. Core Architecture

The system consists of 4 isolated yet interconnected packages:

1. **Macro API (The PyTM Port):** Fluent interfaces for programmatic architecture description.
2. **Micro Attributes (The Threatspec Port):** A set of PHP 8 Attributes for source code markup.
3. **AST Engine:** A parser based on `nikic/php-parser` to extract attributes without executing the code.
4. **The Compiler & Exporter:** A CLI application (Symfony Console-based) that merges macro and micro models and generates JSON.

---

## 3. Technical Specifications

### 3.1. Module 1: Macro API (PyTM Port)

The agent must implement classes to describe the base infrastructure.

**Requirements:**

* **Base Class `Element**`: Properties `$id`, `$name`, `$description`.
* **`Element` Subclasses**: `Server`, `Datastore`, `ExternalEntity`, `Process` (the PHP app itself).
* **`Boundary` Class (Zone)**: For grouping elements (e.g., VPC or Public Internet).
* **`Dataflow` Class**: Describes the connection between two `Elements` (contains `$source`, `$destination`, `$payload`, `$protocol`).
* **`ThreatModel` Class**: The main Registry storing all elements and connections.
* **Interface**: Must support fluent methods, for example: `$server->communicatesWith($db, 'SQL Queries');`.

### 3.2. Module 2: Micro Attributes (Threatspec Port)

The agent must implement the Threatspec "verb" set as pure PHP 8 Attributes in the `HybridTM\Attributes` namespace.

**Requirements (Strictly DTOs, no logic):**

* `#[Mitigates(threat: string, control: string, component: string)]` — Describes a security control.
* `#[Exposes(threat: string, details: string)]` — Records a known risk or security technical debt.
* `#[Transfers(data: string, source: string, destination: string, protocol: string)]` — Micro-description of a data flow. `source` and `destination` must reference Element IDs from the Macro model (PyTM).
* `#[Accepts(threat: string, reason: string)]` — Explicit risk acceptance.

### 3.3. Module 3: AST Engine & Graph Merger

**Critical Constraint:** It is STRICTLY FORBIDDEN to use the `Reflection API`. All analysis must be static.

* Use `nikic/php-parser`.
* Implement a custom `NodeVisitorAbstract`.
* **Merger Logic:**
1. When the parser finds `#[Transfers]`, it looks up elements in the `ThreatModel` registry by the `source` and `destination` IDs. If found, it creates or enriches a `Dataflow`. If not, it generates a Warning or creates an "Unknown Element."
2. When the parser finds `#[Mitigates]`, it links the "Control" to the corresponding component in the global threat graph.



### 3.4. Module 4: CLI Compiler & OTM Exporter

* Use `symfony/console`.
* Create the command: `php bin/hybridtm compile --config=threat-model.php --src=src/ --out=threat-model.otm.json`.
* **Process:**
1. Include (via `require`) the macro model file (`threat-model.php`) to retrieve the `$model` instance.
2. Run the AST Engine on the `--src` directory, passing the `$model` for mutations.
3. Serialize the final `$model` graph into Open Threat Model (OTM) JSON format.



---

## 4. Implementation Phases (Agent: Read Carefully!)

Implement the project strictly following these phases. Stop and request a user review after completing each phase.

**Phase 1: PyTM Foundation (Macro)**

* Initialize `composer.json` (PHP 8.2+).
* Create domain classes (`Element`, `Server`, `Dataflow`, `ThreatModel`, etc.).
* Write a demo file `example/threat-model.php` creating a simple architecture.

**Phase 2: Threatspec Attributes (Micro)**

* Create PHP 8 Attribute classes (`Mitigates`, `Exposes`, `Transfers`, `Accepts`).
* Write `example/src/UserController.php` adding business logic with these attributes.

**Phase 3: The AST Engine (Core)**

* Install `nikic/php-parser`.
* Write the parser (`ThreatspecNodeVisitor`) to extract arguments from Phase 2 attributes.
* Write the logic to merge extracted data with the Phase 1 `ThreatModel` object.

**Phase 4: CLI & Compilation**

* Install `symfony/console`.
* Implement the logic to run the parser across the entire source directory and export the graph to JSON (OTM format).

---

## 5. LLM Agent Rules for using the Framework

Upon completion of Phase 4, generate a `.cursorrules` (or `SKILL.md`) file with the following instructions for future AI agents:

1. You are a DevSecOps Agent.
2. When adding new servers/databases/external APIs, you MUST update `threat-model.php` (using PyTM syntax).
3. When writing business logic (especially controllers, auth services, or file system operations), you MUST use `#[Transfers]` and `#[Mitigates]` attributes (Threatspec syntax).
4. The `source` and `destination` in attributes MUST ALWAYS match the string IDs of elements defined in `threat-model.php`.
5. Before committing, always run `php bin/hybridtm compile` and fix any identified syntax or model errors.

---
