---
layout: home
hero:
  name: HybridTM
  text: Threat modeling as code
  tagline: A PHP DSL, Abuser Stories linked to code, a Knowledge Base of reusable components and rules, a Rule Engine, and a Studio to edit it all visually.
  actions:
    - theme: brand
      text: Getting Started
      link: /en/guide/getting-started
    - theme: alt
      text: Abuser Stories
      link: /en/guide/abuser-stories
features:
  - title: Library-first
    details: hybridtm/hybridtm works standalone — DSL, code attributes, KB loader, Rule Engine, Threagile/OTM/SARIF codecs — no server required.
  - title: Abuser Stories
    details: Attacker-shaped stories in the model, linked to #[AbuserStory] + #[Mitigation] in code, with CI coverage gates (--fail-on-uncovered-stories).
  - title: Studio
    details: A Symfony API (multi-tenancy, RBAC, model workflow, reports) and a React canvas editor with a Stories panel, both built on the same library.
  - title: Explainable findings
    details: Every finding carries a RuleTrace — the exact when/unless conditions that fired — so "why did this happen" always has an answer.
---
