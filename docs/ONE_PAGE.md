# Agent Workspace Guard in Five Minutes

## Problem

Coding agents can mutate files through far more than recognizable deletion commands: shell aliases, language APIs, package hooks, VCS operations, native helpers, renames, truncation, symlinks, and tools that do not yet exist. Command inspection is valuable for early rejection and user feedback, but it cannot generally prove the final runtime target of arbitrary code.

The dangerous property is not merely that a model can produce a malformed cleanup command. It is that the process executing that command may already possess write authority over the user's real workspace or home directory.

## Proposed boundary

> During ordinary task execution, the agent and every descendant process can write only to a disposable transaction. A separate trusted broker may persist one exact, fresh, policy-approved filesystem result to the live workspace.

This changes a classifier miss from possible host data loss into damage to disposable task state.

## Flow

1. **Begin** — A trusted host creates a transaction with a disposable workspace generation, fresh task-specific home and temp roots, a baseline identity, and a signed receipt.
2. **Execute** — The OS sandbox makes the live workspace, real home, broker state, audit log, and quarantine non-writable to the agent and its descendants.
3. **Freeze** — At a checkpoint, the broker freezes the staged generation.
4. **Plan** — The broker computes a canonical semantic diff: exact relative paths, entry types, before/after hashes, sizes, modes, link targets, aggregate counts, baseline and staged identities, policy digest, expiry, and signature.
5. **Decide** — A deterministic result policy allows, requires exact-result approval, or denies the plan.
6. **Approve** — Any approval is short-lived and bound to the complete plan fingerprint. Changing any path, hash, type, mode, target, policy, baseline, or staged generation creates a different authorization object.
7. **Commit** — A broker outside the agent sandbox revalidates all state, moves replaced entries into protected same-filesystem quarantine, installs only the approved staged entries, and verifies the resulting generation.
8. **Restore or dispose** — Restore succeeds only if later user work would not be overwritten. Task cleanup is performed by opaque transaction identity, not by a model-generated recursive path.

## Default result policy

A practical starting point is:

- **Allow:** small, ordinary additions of regular non-executable files within strict count and byte budgets.
- **Require exact-result approval:** modifications, deletions, type changes, executable additions, sensitive paths, and safe in-workspace symlinks.
- **Deny under ordinary policy:** protected VCS or broker paths, escaping links, special files, excessive plans, path ambiguity, stale generations, and mass deletion.

These defaults are examples. The security property comes from authority separation and exact-result mediation, not from any one threshold.

## How this addresses the reported failure class

| Failure pattern | Boundary behavior |
|---|---|
| `HOME` or another system variable is reused for scratch state | The host supplies a fresh task home; the real home is outside agent write authority. |
| Cleanup resolves to the wrong directory | The malformed operation can affect only the disposable transaction when sandboxing is correctly enforced. |
| A temporary path already exists | The broker creates a fresh opaque namespace and refuses caller-selected existing roots. |
| A deletion syntax is absent from a classifier | Host files remain non-writable; the evaluated staged result is still visible in the semantic diff. |
| Review approves misleading command text | Review authorizes one concrete signed result, not an effectful command whose target can vary at runtime. |
| Full access is enabled | Runtime breadth and live-workspace persistence remain separate capabilities. Direct host mutation becomes explicit break-glass behavior. |

## What the repository demonstrates

The standard-library-only Python implementation exercises:

- transaction, task-home, and task-temp lifecycle;
- content-hashed manifests and semantic diffs;
- signed state transitions, plans, approvals, commits, and audit events;
- deterministic policy and exact-plan approval binding;
- quarantine-first commit, rollback, conservative restore, and drift detection;
- symlink, protected-path, executable, special-file, change-budget, and mass-deletion controls;
- a defense-in-depth cross-shell inspector and destructive-action replay corpus.

Run:

```bash
./scripts/verify.sh
```

The current suite contains 36 unit/integration tests and 28 destructive-command replay cases.

## What production still requires

The Python implementation is a protocol model, not an OS sandbox. A production integration must supply:

- kernel-enforced write isolation for the agent and descendants;
- a broker process or principal unavailable to the agent;
- immutable or frozen staged generations;
- authenticated IPC and single-writer coordination;
- handle-relative, no-follow filesystem operations;
- durable crash recovery and repair states;
- platform-specific handling for reparse points, hard links, ACLs, extended metadata, case folding, mounts, and VCS metadata;
- protected quarantine with quotas, retention, and independent purge authorization.

See [`RFC.md`](RFC.md), [`SECURITY_ARGUMENT.md`](SECURITY_ARGUMENT.md), and [`IMPLEMENTATION_CHECKLIST.md`](IMPLEMENTATION_CHECKLIST.md) for the full design and acceptance gates.

## Positioning

Agent Workspace Guard is an independent RFC and executable reference implementation. It complements model instructions, command checks, approval UX, automatic review, evaluations, and training changes. It is not a claim about undisclosed product internals, a complete production sandbox, or proof that passing a command classifier establishes safety.
