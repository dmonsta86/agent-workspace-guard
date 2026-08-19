# Proposed Codex Integration

## Scope and repository snapshot

This document maps the RFC onto the public `openai/codex` repository as inspected on **August 18, 2026**. It is an independent integration sketch, not a claim about private infrastructure and not a compiled upstream patch.

The public repository already contains useful layers that should remain:

- `codex-rs/shell-command/src/command_safety/` for known command-shape classification;
- `codex-rs/core/src/exec_policy.rs` for policy, sandbox, and approval routing;
- `codex-rs/execpolicy/` for structured allow/prompt/forbidden rules;
- platform sandbox and permission machinery;
- protocol/UI plumbing for approval requests.

The proposal adds a distinct **persistence boundary after execution**. Command policy decides how code may run. Workspace Guard decides what exact evaluated result may become user state.

## Proposed component boundary

A possible Rust layout is:

```text
codex-rs/workspace-guard/
  lib.rs
  ids.rs                 opaque typed IDs and versions
  manifest.rs            entry identity and tree generations
  diff.rs                semantic exact change plans
  policy.rs              one result-policy core
  approval.rs            plan-bound authorization
  transaction.rs         staged root lifecycle
  broker_client.rs       authenticated typed IPC
  audit.rs               redacted authenticated events
  platform/
    linux.rs
    macos.rs
    windows.rs

codex-rs/workspace-guard-broker/
  main.rs                 isolated service entry point
  commit.rs               quarantine/apply/rollback/restore
  journal.rs              durable recovery state machine
  quarantine.rs           retention and purge capability
  platform/
    linux.rs
    macos.rs
    windows.rs
```

The broker should be a separate process/principal rather than a library loaded into the untrusted agent execution domain.

## Protocol types

Illustrative types:

```rust
struct WorkspaceTransaction {
    id: TransactionId,
    user_id: UserId,
    session_id: SessionId,
    task_id: TaskId,
    workspace_id: WorkspaceId,
    staged_generation: GenerationId,
    staged_root: BrokerOpaqueRoot,
    home_root: BrokerOpaqueRoot,
    temp_root: BrokerOpaqueRoot,
    baseline_digest: TreeDigest,
    created_at: SystemTime,
    state: TransactionState,
}

struct EntryIdentity {
    kind: EntryKind,
    content_digest: Option<ContentDigest>,
    metadata_digest: MetadataDigest,
    size: u64,
}

struct WorkspaceChange {
    path: NormalizedRelativePath,
    kind: ChangeKind,
    before: Option<EntryIdentity>,
    after: Option<EntryIdentity>,
}

struct WorkspaceCommitPlan {
    version: PlanVersion,
    id: PlanId,
    transaction_id: TransactionId,
    workspace_id: WorkspaceId,
    baseline_digest: TreeDigest,
    staged_digest: TreeDigest,
    changes: Vec<WorkspaceChange>,
    findings: Vec<WorkspaceFinding>,
    decision: Decision,
    created_at: SystemTime,
    expires_at: SystemTime,
    fingerprint: PlanDigest,
    state: PlanState,
}

struct WorkspaceApproval {
    id: ApprovalId,
    plan_id: PlanId,
    plan_fingerprint: PlanDigest,
    reviewer: ReviewerIdentity,
    created_at: SystemTime,
    expires_at: SystemTime,
    signature: BrokerSignature,
}
```

Path types should reject absolute, drive-qualified, UNC, empty, dot, parent, non-normalized, and platform-ambiguous forms at construction time. Model-visible protocol objects should not expose host broker-state paths.

## Session flow

### 1. Create transaction before tool execution

Before the first model-controlled command:

1. validate the selected project root;
2. obtain a stable baseline generation;
3. create an isolated staged generation without a writable pointer to the user's VCS metadata;
4. create broker-owned home/temp/application-state roots;
5. configure the platform sandbox so only transaction roots are writable;
6. set command cwd to the staged root;
7. inject broker-owned environment roots;
8. retain transaction and real-workspace identities in trusted state, not prompt text.

The generic reference backend excludes `.git`. Production should use a filesystem snapshot/overlay, a fully isolated disposable clone, or a read-only VCS service. A normal Git worktree with shared writable repository metadata is not sufficient isolation by itself.

### 2. Execute with existing policy

Continue to call current command-safety and execution-policy machinery.

Recommended semantics:

- explicit host-root/home/profile, privilege, mount, device, filesystem-format, and ACL intent remains forbidden;
- attempts to replace broker-owned environment roots are denied or corrected;
- destructive commands may be allowed inside the transaction when policy permits because they cannot directly mutate the real workspace;
- a “safe” command classification never grants persistence;
- reusable prefix approvals affect execution only;
- nested interpreters and package hooks remain inside the same sandbox capability set.

### 3. Checkpoint and freeze

At task completion, before a persistence request, or after a high-risk command:

1. stop/freeze transaction writers or create an immutable staged generation;
2. ask the broker to plan against the signed baseline;
3. receive an exact canonical plan and deterministic policy result;
4. display a result summary and selected path details;
5. either auto-allow, request exact-result approval, or deny.

The model may explain the plan but must not be able to alter the review object or mint its authorization.

### 4. Review exact result

Auto-review or the user should receive:

- exact relative paths and change types;
- before/after entry types and content summaries;
- delete count/fraction, replacement count, and byte totals;
- sensitive/protected/symlink/executable findings;
- baseline/staged identities, protocol/policy identity, and short expiry;
- a stable human-readable plan ID/fingerprint fragment;
- whether a command-level detector also raised risk.

The approval request should be a distinct protocol type from:

- command execution approval;
- network permission;
- sandbox expansion;
- direct-host break-glass access;
- quarantine purge.

### 5. Commit through broker

The trusted broker:

1. verifies all signed identities, state, freshness, policy digest, deterministic re-evaluation, and approval;
2. binds to immutable baseline and staged generations;
3. prepares new entries on the target filesystem;
4. journals each exact operation;
5. moves existing targets to protected quarantine;
6. installs staged entries with handle-relative/no-follow platform operations;
7. verifies the resulting generation;
8. rolls back or enters repair state on failure;
9. returns a commit/restore handle;
10. marks competing plans stale.

No model-generated shell command participates in real-workspace commit or transaction cleanup.

### 6. Dispose

Dispose worktree/home/temp/application-state roots by transaction ID. Keep quarantine according to retention policy. Do not call a model-generated `rm`, PowerShell, Cmd, or language deletion API with a path string.

## Full-access semantics

The present concept of broad access should be decomposed into capabilities:

```text
process execution
network access
read scopes
task-root writes
additional sandbox mounts
exact-result workspace persistence
quarantine purge
direct-host mutation (break glass)
```

Ordinary “Full access” may broaden the first five while transactional persistence remains active. Direct-host mutation should be separately named, nonpersistent, highly visible, and unavailable to automatic self-approval.

## Platform adapters

### Linux

- Use a mount namespace and a staged snapshot/OverlayFS/reflink backend.
- Apply Landlock or equivalent filesystem-right constraints to agent descendants.
- Keep real workspace/home and broker state non-writable and preferably absent.
- Use opened root descriptors, constrained resolution such as the `openat2` family, and descriptor-relative rename/create operations.
- Reject unintended mount/device crossings.

### macOS

- Use an isolated staged tree, preferably APFS copy-on-write facilities where supported.
- Run the agent under a sandbox profile that exposes only intended roots as writable.
- Keep the broker in a separate process and resolve mutations relative to opened directory handles with no-follow checks.
- Define behavior for case-insensitive filesystems, extended attributes, flags, ACLs, and open-file semantics.

### Windows

- Use a per-task staged tree plus the existing restricted-process/sandbox model.
- Give the agent access only to transaction roots; keep real-workspace delete/ACL rights in the broker identity.
- Treat junctions, reparse points, alternate data streams, case folding, ACL inheritance, sharing modes, and same-volume rename explicitly.
- Resolve and mutate through handles rather than trusting normalized strings alone.

A backend that cannot establish the required authority and atomicity properties should fail closed or clearly state that the transactional security claim is unavailable.

## Auto-review evolution

The key question changes from:

> Is this command likely destructive?

To:

> Should this exact evaluated result from this baseline be persisted?

Command intent remains a useful feature, but result identity is authoritative. Recommended reviewer outputs are:

- `allow_exact_plan`;
- `require_user_for_exact_plan`;
- `deny_exact_plan`;
- `request_replan_or_rebase`;
- never “approve any future command with this prefix” as persistence authorization.

## Evaluation integration

Each observed incident should generate two kinds of fixtures:

1. **Command-routing fixture:** did the heuristic produce useful deny/review feedback?
2. **Filesystem-property fixture:** could arbitrary execution alter the real workspace/home before exact commit, and did the broker persist only the approved result?

The second is the release gate. The included `evals/destructive_replays.json` is intentionally only the first fixture type; the unit/integration tests exercise the second at reference level.

## Suggested implementation sequence

1. Add typed transaction/plan protocol objects without changing execution.
2. Shadow-compute exact diffs and compare with existing task outcomes.
3. Introduce disposable staged execution behind a feature flag.
4. Add distinct exact-result approval rendering and automatic-review input.
5. Implement one platform broker backend with crash-injection tests.
6. Enable quarantine commits for selected sessions/filesystems.
7. Split direct-host mutation from Full access.
8. Expand to other platforms only after each backend satisfies the same property suite.

## Upstream submission shape

Because this is a cross-cutting architectural change, the initial upstream artifact should be an RFC/design issue with:

- the security invariant and assumptions;
- a minimal protocol sketch;
- compatibility/performance questions;
- a staged rollout proposal;
- the reference implementation and tests;
- explicit acknowledgement that maintainers may select a smaller internal design.

A source PR should follow only if maintainers choose the direction and identify an acceptable scoped change.
