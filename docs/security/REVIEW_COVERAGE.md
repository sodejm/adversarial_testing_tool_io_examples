# Existing-code human review coverage

Baseline commit: `5fa2f772e9409831298524ab50a30f9595fe9bad`. Status: initial inventory; no completed human
review is asserted. Scope includes all tracked first-party code, infrastructure,
CI, agent instructions and build/release tooling, including paths outside the
subsystem rows below. The maintainer must expand rows to exact file inventories;
these subsystem entries are prioritization, not proof of exhaustive review.

| ID | Scope | Status | Human owner | Deadline |
| --- | --- | --- | --- | --- |
| R1 | Harness → mock MCP / LLM over Docker network and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R2 | Fixture / model / tool response → harness → report parser and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R3 | Parser → report artifact → browser/CI consumer and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R4 | Optional harness → external provider and all implementing code/configuration/tests | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-CI | All CI, dependencies, packaging, release, scripts and agent/tool authority | Pending independent human review | Maintainer assignment pending | Before affected release; triage within 30 days, first pass within 90 days |
| R-REST | All remaining tracked first-party files; enumerate and reconcile against Git inventory | Pending independent human review | Maintainer assignment pending | First pass within 90 days |

For each reviewed row add exact paths, reviewed SHA, reviewer identity/date,
checks/evidence, findings, disposition, residual risk acceptance/expiry and next
review trigger. Record third-party provenance and review separately. Changed
behavior invalidates prior scope approval. Follow the
[engineering review policy](../ENGINEERING_REVIEW.md). No automated result or
threat-model entry closes this human-review backlog.
