# Rollout and Evaluation Plan

This document turns the RFC into a deployable program. The rollout is intentionally gated by observed filesystem properties, not by command-classifier recall alone.

## 1. Release principles

1. **Preserve the existing safety layers.** Model instructions, command parsing, execution policy, sandbox approvals, Auto-review, and destructive-action replays remain active.
2. **Introduce persistence mediation separately.** A command may be allowed to execute inside a disposable transaction while its resulting diff is denied or sent for exact-result approval.
3. **Fail closed on missing platform guarantees.** Transactional mode must not silently become direct-host editing when snapshotting, confinement, path resolution, journaling, or quarantine is unavailable.
4. **Keep recovery independent.** Replaced and deleted content remains in quarantine until a separate retention decision; successful task completion does not imply immediate purge.
5. **Measure compatibility without collecting source.** Default telemetry should use counts, sizes, decision codes, timing, drift, rollback, and hashed identifiers—not raw commands, file contents, or secret-bearing paths.

## 2. Staged rollout

### Stage 0 — Offline adversarial validation

Build platform adapters and run them against disposable machines and filesystems before product exposure.

Required suites include:

- direct syscalls and native helpers, not only shell commands;
- Bash/Zsh/Fish, PowerShell, Cmd, and nested interpreters;
- symlink, junction, reparse-point, mount, hard-link, case-folding, and Unicode attacks;
- baseline and staged races at every plan/commit transition;
- disk-full, quota, permission, antivirus/indexer, and sharing-violation failures;
- crash and power-loss injection before and after every durable journal record;
- duplicate, replayed, expired, swapped, and corrupt plan/approval state;
- every permission mode, including broad process/network access and explicit break glass.

Exit only when protected host trees remain unchanged before commit and every injected commit failure reaches the approved digest, the original digest, or an explicit `repair_required` state with recovery material intact.

### Stage 1 — Shadow planning

Keep current direct-edit behavior, but independently create a disposable transaction and exact plan for selected internal sessions.

Compare:

- observed host changes versus planned changes;
- unsupported metadata and repository shapes;
- manifest and planning cost;
- false hard denials and review volume;
- path rendering/privacy behavior;
- compatibility with build systems, generated files, large binaries, ignored files, and concurrent editors.

Shadow mode must never be described as providing the new safety property because the agent still has direct host authority.

### Stage 2 — Internal transactional persistence

Run internal and recoverable workloads with host writes denied and broker persistence enabled.

Start with:

- small repositories;
- ordinary add/modify workloads;
- approval-required deletes and type changes;
- short quarantine retention plus independent snapshots;
- explicit operator access to journal, quarantine, and restore tools.

Exercise broker restart and repair procedures during this stage rather than waiting for production incidents.

### Stage 3 — User opt-in

Expose transactional persistence as an explicit experimental mode with clear semantics:

- the agent edits a disposable workspace;
- task completion does not persist until policy/approval succeeds;
- the review shows the exact result, not merely the command;
- restore is available while the no-drift condition holds;
- unsupported filesystems or metadata stop the operation instead of downgrading silently.

Collect opt-in compatibility feedback and publish known limitations.

### Stage 4 — Default for approval-oriented modes

After platform and compatibility gates pass, make transactional persistence the default for modes equivalent to **Ask for approval** and **Approve for me**.

Command approval, sandbox expansion, network access, exact-result persistence, purge, and direct-host break glass remain distinct grant types.

### Stage 5 — Broad-access semantics

Broad or “Full access” modes should continue using transactional persistence by default. Provide direct-host mutation only through a separate, explicit, short-lived break-glass grant with unmistakable UX, scope display, audit, and recovery guidance.

## 3. Acceptance gates

### Safety gates

- No agent or descendant process can mutate the real workspace, real home/profile, broker state, or quarantine before broker commit in the supported configuration.
- Every live-workspace mutation is represented in one authenticated plan and one journaled commit transition.
- Changed baseline, staged generation, plan content, approval, object identity, expiry, or policy state is rejected.
- Path traversal, symlink/reparse traversal, mount/device crossing, unsupported metadata, and ambiguous normalization fail closed.
- Replaced/deleted entries remain recoverable until independent purge.
- Crash/fault injection never causes an unjournaled destructive mutation or automatic purge of recovery material.

### Compatibility gates

- Common build, test, package, formatter, code-generation, and VCS-read workflows operate in the disposable workspace.
- Repository metadata is not shared writable with the host repository.
- Large and binary projects have documented budgets and explicit fallback behavior.
- Concurrent editor drift produces a clear rebase/retry flow rather than silent overwrite.
- Plans are rendered completely and consistently on every supported UI/platform.

### Operational gates

- Broker startup detects and reconciles incomplete operations.
- Workspace locks use fencing and recovery, not permanent stale lock files.
- Quarantine has access control, quotas, retention, storage-pressure behavior, and audited purge.
- Key rotation, audit anchoring, multi-process serialization, and tenant/user separation are tested.
- The product can disable the feature safely without leaving ambiguous transactions or hidden direct-host authority.

## 4. Evaluation matrix

| Evaluation family | Pass condition |
|---|---|
| Destructive command replay | Known high-risk forms are routed correctly, and classifier misses still cannot alter protected host state. |
| Arbitrary-code filesystem attacks | Native and interpreted deletion/overwrite attempts affect only transaction roots before commit. |
| Exact-plan binding | Any path, type, mode, content, baseline, staged-generation, expiry, or policy change invalidates approval. |
| Commit correctness | Final workspace equals the approved digest or is restored to the original digest; ambiguity enters repair mode. |
| Recovery | Crash at every journal transition preserves enough durable state to finish, roll back, or request repair. |
| Path semantics | Traversal, links, mounts, reparse points, case/Unicode collisions, and unsupported entries cannot escape the plan. |
| Permission modes | Broad execution permissions do not implicitly grant direct host persistence. |
| Privacy | Default telemetry contains no raw command, source content, credential, quarantine content, or unredacted sensitive path. |
| Performance | Planning, review, commit, and storage overhead meet product-defined budgets without weakening invariants. |

The included `evals/destructive_replays.json` exercises the advisory classifier. Production acceptance additionally requires real filesystem-state assertions on every supported platform.

## 5. Metrics that are useful without overclaiming

Track distributions and error classes rather than a single “safe” percentage:

- transactions started, planned, committed, discarded, restored, and repaired;
- plans allowed, reviewed, denied, expired, or invalidated by drift;
- change counts/bytes and delete fractions;
- snapshot, scan, review, commit, restore, and cleanup latency percentiles;
- quarantine growth, retention, quota pressure, and purge outcomes;
- unsupported metadata/filesystem/platform findings;
- command-classifier decision versus exact-plan decision;
- rollback and crash-recovery outcomes;
- user cancellation and approval comprehension signals.

Never infer the host-safety property merely from a low incident rate or high classifier recall. Validate the authority boundary directly with continuous negative tests.

## 6. Rollback of the rollout

A product rollback must preserve user data:

1. Stop starting new transactional sessions.
2. Keep the broker, journal reader, quarantine, restore, and repair tools available.
3. Finish or explicitly repair every in-flight commit before disabling adapters.
4. Do not delete transaction or quarantine state as part of feature rollback.
5. Require an explicit product decision before returning any mode to direct-host writes.

The feature flag controls admission, not the existence of recovery obligations.
