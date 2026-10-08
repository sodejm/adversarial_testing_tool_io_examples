# Repository agent instructions

Use the README for setup and supported behavior. Preserve existing user work.

## Required checkpoints, human review, and threat modeling

- Follow [Engineering review policy](docs/ENGINEERING_REVIEW.md). Create a local
  commit after each substantial coherent change and its relevant validation; do
  not defer all checkpoints until task completion. Use operational, imperative
  commit messages with actual validation and recovery details. Preserve unrelated
  work, existing checkpoints, signing requirements and stronger project gates.
- Update affected documentation in the same change. Require independent human
  review of the exact commit before merge/release; automated review is additional
  evidence. Record and schedule retroactive review of existing code in
  [Review coverage](docs/security/REVIEW_COVERAGE.md); do not mark pending code reviewed.
- Maintain the detailed [Threat model](docs/THREAT_MODEL.md) when code, dependencies,
  data flows, trust boundaries or deployment assumptions change. Record a specific
  no-impact rationale when unchanged. Reconcile at every release and quarterly.
  Keep source evidence, implemented/proposed controls, abuse cases, risk owners,
  validation and unresolved assumptions current. Human approval remains pending
  until an independent reviewer records it.
