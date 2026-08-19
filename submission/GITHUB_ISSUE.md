# Standalone Issue Fallback

> A directly related issue already exists at https://github.com/openai/codex/issues/33624. Prefer posting `OPENAI_CODEX_COMMENT.md` there rather than opening a duplicate. Use this file only if maintainers request a separate RFC issue.

## Suggested issue title

**[RFC] Transactional workspace persistence: disposable execution + exact-diff commit broker**

---

## Context

The recent destructive-action hardening—safer model instructions, stronger execution checks, clearer Full access UX, Auto-review updates, targeted replays, and training changes—addresses important observed failure modes.

I am proposing an additional architectural boundary for the remaining class of misses:

> During ordinary agent execution, Codex should not have direct write authority over the user's real workspace or real home. It should work in a disposable transaction, and a separate broker should persist only an exact, signed, policy-approved result.

This is intended to complement the current layers, not replace them.

## Why add a persistence boundary

A free-form coding agent can reach deletion or overwrite through `rm`, `find -delete`, VCS cleanup, synchronization tools, PowerShell/Cmd variants, package hooks, language APIs, native code, rename/truncation semantics, or a future tool absent from a classifier.

Command/AST checks are valuable for routing and feedback, but the final target can also depend on runtime environment, cwd, configuration, symlinks/reparse points, mounts, case rules, and concurrent filesystem state.

The stronger invariant is therefore:

> Arbitrary code in the agent sandbox cannot mutate protected host files; only one exact, fresh, authorized result plan can be persisted by a trusted broker.

## Proposed flow

### 1. Begin a task transaction

A trusted host component creates:

- a stable baseline identity;
- a disposable staged workspace generation;
- fresh broker-owned `HOME`/`USERPROFILE`, `TMPDIR`/`TMP`/`TEMP`, and `CODEX_HOME` roots;
- an opaque transaction ID and signed receipt.

The OS sandbox makes the real workspace, real home, broker state, and quarantine non-writable to the agent and descendants.

### 2. Execute normally inside the transaction

Keep existing `shell-command`, `exec_policy`, `execpolicy`, platform sandbox, approval, and model-feedback layers.

Obvious root/home/privilege/mount/format/ACL intent can remain denied. A missed destructive spelling can damage only disposable task state, not host files.

### 3. Freeze and plan the evaluated result

At checkpoint/task completion, freeze the staged generation and compute a canonical semantic diff containing:

- exact normalized relative paths;
- add/modify/delete/type-change kind;
- before/after entry types and hashes;
- counts, bytes, findings, and baseline/staged generation digests;
- protocol version and complete-policy digest;
- short expiry, fingerprint, state, and broker signature.

### 4. Apply deterministic result policy

Suggested ordinary defaults:

- small regular add-only plans may auto-commit within strict budgets;
- modifications, deletions, type changes, executable additions, sensitive paths, and safe in-workspace symlinks require exact-result review;
- protected VCS/broker paths, escaping links, special files, excessive plans, and mass deletion are denied under ordinary policy.

### 5. Bind review to the exact result

Approval contains the complete plan fingerprint, reviewer identity, workspace/session binding, expiry, and broker signature.

Any changed protocol/policy, path, hash, type, mode, baseline, staged generation, finding, or expiry creates a different plan. Command-prefix approval is not persistence approval.

### 6. Quarantine-first commit

A broker outside the agent sandbox:

1. revalidates signed state, protocol/policy digest, deterministic policy result, approval, expiry, and immutable generations;
2. pre-stages new entries on the live filesystem;
3. journals intent;
4. atomically moves every existing planned target into protected same-filesystem quarantine;
5. installs staged entries with handle-relative/no-follow operations;
6. verifies the final generation;
7. rolls back or enters explicit repair state on mismatch.

The normal broker does not recursively delete a user path. Permanent quarantine purge is a separate broker-owned retention action.

### 7. Dispose by identity

Task cleanup is `discard(transaction_id)`. The model does not emit a recursive cleanup command or choose the path that the broker deletes.

## How this maps to the reported failure class

| Concern | Proposed control |
|---|---|
| `HOME` or another system variable reused for scratch | Real home is outside agent write authority; broker supplies a disposable task home. |
| Malformed cleanup points at user files | The command remains confined to transaction roots; normal cleanup uses opaque transaction identity. |
| Temporary path already exists | Broker creates a fresh namespace and refuses caller-selected existing roots. |
| Unknown deletion/overwrite form | Host mutation is blocked by authority; the evaluated staged deletion still appears in the exact diff. |
| Auto-review misses intent | Review sees the concrete signed result after execution. |
| Full access enabled accidentally | Runtime access and real-workspace persistence remain separate capabilities. |
| Training/eval misses a syntax variant | Command replay improves incidence; filesystem-property tests still protect the boundary. |

## Full access semantics

I recommend separating these capabilities:

```text
process execution
network
read scopes
task-root writes
additional sandbox mounts
exact-result workspace persistence
quarantine purge
direct-host mutation (break glass)
```

Ordinary broad/Full access can expand runtime capability while transactional persistence remains active. Direct host mutation should be separately named, nonpersistent, highly visible, and excluded from the transactional security claim.

## Reference implementation

Repository: **https://github.com/dmonsta86/agent-workspace-guard**

Included:

- transaction/worktree/home/temp lifecycle;
- recomputed manifests and exact semantic diffs;
- signed state transitions, plans, approvals, commits, and audit events;
- bounded approval/plan lifetimes and state/path identity checks;
- result policy and findings;
- quarantine-first commit, rollback, and drift-safe restore;
- defense-in-depth command inspection with secret-free telemetry;
- Codex integration RFC, security argument, threat model, production implementation checklist, platform hardening, and rollout gates.

Verification:

```bash
./scripts/verify.sh
```

Packaged result:

```text
36 unit/integration tests passed
28/28 destructive-command replay cases passed
```

## Important limitation

The Python code is a protocol/reference implementation, not a standalone production sandbox. A production implementation still needs:

- kernel-enforced authority separation;
- a separate broker principal and authenticated IPC;
- immutable/frozen generations;
- handle-relative/no-follow platform adapters;
- durable single-writer crash recovery;
- explicit handling of reparse points, hard links, ACLs, extended metadata, case rules, mounts, and VCS metadata;
- protected quarantine retention and independent purge authorization.

The repository states these assumptions explicitly and does not claim perfect command recognition, zero latency, or an impermeable Python boundary.

## Suggested rollout

1. Shadow-generate exact plans and compatibility/performance telemetry.
2. Pilot disposable worktree/home/temp execution with runtime sandbox denial tests.
3. Add a distinct exact-result approval type to protocol/UI and Auto-review.
4. Pilot quarantine commit on one supported platform/filesystem with crash injection.
5. Default transactional persistence in ordinary approval modes after property gates pass.
6. Split direct-host mutation from Full access.
7. Optimize with snapshots, overlays, reflinks, content-addressed manifests, and deduplication without changing authorization semantics.

## Open design questions

- Which existing session/workspace abstraction is the best home for transaction identity?
- Which platform backend can satisfy the immutable-generation and handle-relative commit properties first?
- What add-only threshold preserves normal workflows without creating an easy persistence bypass?
- How should exact-result approvals be summarized for very large but legitimate refactors?
- Which metadata/VCS operations should be supported initially versus denied?
- What retention and storage guarantees are appropriate for quarantine?

I am filing this as a design analysis rather than an unsolicited code PR. The implementation is intended to make the invariant and tradeoffs concrete; the production shape can be narrower or use different internal primitives.
