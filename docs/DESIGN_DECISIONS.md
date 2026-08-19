# Design Decisions

## 1. Protect persistence, not only command syntax

### Alternatives considered

**Prompt/model instructions only**

Useful for reducing incidence, but probabilistic behavior cannot be the hard boundary.

**Expanded regex or shell AST policy**

Useful for known shapes, remediation, routing, and evaluations. Incomplete for arbitrary child programs, runtime path identity, new APIs, symlink/mount races, and native code.

**Deletion-only syscall broker**

Stronger than a filter, but still leaves truncation, rename-overwrite, replacement, synchronization semantics, metadata damage, and VCS mutation.

**Transactional workspace plus exact-result commit broker — selected**

Confines every write, supports arbitrary coding tools in disposable state, reviews the evaluated result, and makes recovery/approval binding natural.

## 2. The agent never owns the real workspace writer capability

Making the workspace writable and trying to intercept “dangerous” operations leaves the guarantee dependent on interception completeness. The selected design removes ambient authority and gives a small trusted broker the only live mutation capability.

## 3. Home and temp roots are disposable capabilities

The host creates fresh per-task roots and injects their identities. The model cannot grant temporary provenance by assigning `HOME`, `TMP`, or a path variable. Cleanup is `discard(transaction_id)`, not a generated recursive command.

## 4. Approval attaches to a result fingerprint

The same command can affect different paths under different cwd, environment, configuration, repository state, program version, and filesystem layout. Approval therefore binds to the complete exact plan and expires quickly.

## 5. Replace/delete means quarantine, not purge

The first live operation against an existing target is a same-filesystem move into protected quarantine. This provides:

- removal from the live namespace without recursive deletion;
- rollback material;
- user-visible restore;
- a clear separation between persistence and irreversible purge.

Permanent purge is a separate broker-owned retention action.

## 6. Small add-only plans may auto-commit

Adding ordinary regular files/directories within strict budgets does not destroy baseline content. This preserves a low-friction path for common outputs. New executable content, sensitive-looking paths, unsafe links, large additions, and all existing-file changes remain reviewable or denied.

Deployments may choose stricter policy.

## 7. Mass deletion is denied under ordinary policy

A generic approval prompt is easy to misread when a large fraction of a workspace disappears. Mass deletion requires a distinct break-glass policy, stronger rendering, explicit recovery posture, and nonpersistent authorization.

## 8. VCS metadata is isolated, not copied blindly

A `.git` directory or `.git` pointer can expose shared writable repository metadata. The reference backend excludes it. Production should use a filesystem snapshot/overlay, a fully isolated disposable clone, or a read-only/proxied VCS service.

A normal Git worktree with shared repository metadata is not treated as a complete security boundary by itself.

## 9. Full access is decomposed into capabilities

Process execution, network, reads, task-root writes, additional mounts, exact-result persistence, purge, and direct-host mutation are different powers. Combining them in one switch encourages accidental overgranting.

Transactional persistence should remain active under ordinary broad access. Direct-host mutation is separate break-glass behavior.

## 10. One semantic result policy

Shell-specific detectors may differ by platform, but exact-result policy should be one typed semantic core. This prevents Python/TypeScript/PowerShell or Bash/PowerShell/Cmd rule drift from becoming a persistence inconsistency.

## 11. State is authenticated and short-lived

Transaction/plan state, state transitions, approvals, commit records, and audit events are authenticated. Object IDs are typed and path-bound. Plan/approval TTLs are bounded. This prevents stale or copied state from becoming an ambient capability.

## 12. Default telemetry does not contain raw commands

Commands can contain credentials, tokens, private paths, source, or customer data. The reference inspector emits a digest, length, decision, and finding codes. Detailed local diagnostics should be opt-in and sanitized before submission.

## 13. Unsupported semantics fail closed

Special files, unsafe symlinks, mount crossings, unknown metadata, insufficient atomicity, corrupt state, and ambiguous crash recovery are not silently flattened into ordinary files or direct host execution.

## 14. No unsupported guarantee language

The repository uses conditional security properties tied to explicit assumptions. It does not claim:

- perfect destructive-command recognition;
- zero latency;
- an impermeable Python sandbox;
- universal filesystem support;
- complete crash safety without platform adapters;
- that quarantine replaces backups;
- that approved code is semantically safe.
