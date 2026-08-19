# Changelog

All notable changes to this independent reference design are documented here.

## 0.2.3 — 2026-08-19

### Publication hardening

- Fixed the GitHub Actions install step by explicitly provisioning the declared build backend before using `--no-build-isolation`.
- Added repository-wide LF normalization so the byte-level source manifest verifies on Windows checkouts.
- Updated GitHub Actions to current Node 24-based major versions, disabled persisted checkout credentials, and made the full matrix non-fail-fast.
- Added an installed-CLI check to CI.

### Reviewer experience

- Added a five-minute architecture summary and a shorter review path at the top of the README.
- Added live repository metadata, a polished X reply, and a concise comment for the existing related `openai/codex#33624` discussion.
- Replaced publication placeholders and obsolete first-publish instructions with the current contribution route.

No broker or result-policy behavior changed from v0.2.2.

## 0.2.2 — 2026-08-18

### Canonical consolidation

- Added `START_HERE.md` as the single entry point for implementation and submission.
- Incorporated the production `docs/IMPLEMENTATION_CHECKLIST.md` into the repository.
- Replaced time-sensitive service-status text with evergreen submission and disclosure guidance.
- Clarified that ZIP, Git bundle, and wheel outputs are transport formats for one release, not separate versions.
- No broker or policy behavior changed from v0.2.1.

### Verification

- Re-ran the complete 36-test suite and all 28 destructive-command replay cases.
- Regenerated and verified the repository manifest and release artifacts.

## 0.2.1 — 2026-08-18

### Plan-policy binding

- Added a versioned commit-plan protocol and a stable digest of the effective guard policy.
- Bound signed plans and approval tokens to that policy digest.
- Re-evaluate the exact diff, findings, decision, and summary under the bound policy immediately before commit.
- Reject plans if the broker policy changed after planning, preventing approval reuse across a weaker policy configuration.
- Reject symlinked broker-state subdirectories and audit-log paths; open audit files with no-follow regular-file checks where supported.

### Verification

- Rejected symlinked broker-state directories and audit logs; audit opens use no-follow semantics where available.
- Expanded the suite to 36 unit/integration tests; all 28 cross-shell replay cases remain passing.

## 0.2.0 — 2026-08-18

### Architecture

- Reframed protection around a transactional persistence boundary rather than command recognition.
- Added broker-owned per-task worktree, home, temp, exact-result planning, bounded approval, quarantine-first commit, restore, and discard semantics.
- Split broad runtime access from real-workspace persistence authority.

### Integrity and safety

- Added HMAC-authenticated transactions, plans, approvals, commit records, and audit events.
- Added strict opaque object identifiers, plan and approval lifetimes, state/path identity checks, manifest recomputation, drift detection, unsafe-symlink denial, change budgets, protected-path rules, and secret-free command telemetry.
- Added explicit production assumptions and failure boundaries; the Python implementation is not represented as an OS sandbox.

### Verification and submission

- Added 33 unit/integration tests and 28 cross-shell replay cases.
- Added a security argument, threat model, Codex integration proposal, production hardening requirements, rollout gates, issue-ready submission text, Git bundle/ZIP packaging, and artifact checksums.

## 0.1.0 — 2026-08-18

- Initial experimental transaction broker and shell replay corpus.
