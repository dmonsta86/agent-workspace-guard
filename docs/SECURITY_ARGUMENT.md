# Security Argument

## Claim boundary

Agent Workspace Guard does **not** claim that arbitrary commands can be classified perfectly or that the Python reference implementation is itself an OS sandbox.

The production security claim is conditional:

> Under assumptions A1–A8, arbitrary code executed by the agent cannot mutate the user's real workspace or real home before a successful broker commit; every mutation performed by the broker is represented by one fresh, signed, policy-authorized plan; replaced or deleted entries remain recoverable until an independent purge.

The reference implementation exercises the protocol and many integrity checks, but assumptions A1, A4, A5, and A7 require platform integration beyond this repository.

## Definitions

- **Real workspace:** the user-controlled project tree whose contents must not change except through the broker.
- **Transaction roots:** a fresh staged worktree, home, temp area, and model/application state created for one task.
- **Baseline generation:** an immutable identity of the real workspace at transaction creation.
- **Staged generation:** the frozen transaction state from which a commit plan is derived.
- **Plan:** a canonical list of exact relative-path changes plus protocol version, policy digest/result, baseline/staged digests, expiry, state, and broker signature.
- **Approval:** a short-lived broker-verifiable token containing the exact plan fingerprint and reviewer identity.
- **Broker:** the trusted component with narrowly scoped authority to mutate the real workspace and broker-owned state.
- **Quarantine:** protected same-filesystem storage into which existing live entries are moved before replacement or deletion.

## Assumptions

### A1 — Kernel-enforced write confinement

The agent and every descendant process can write only transaction roots and explicitly approved scratch/cache mounts. They cannot write, truncate, unlink, rename, change ACLs, mount over, or otherwise mutate the real workspace, real home/profile, broker state, quarantine, or unrelated host paths.

### A2 — Broker isolation

The agent cannot impersonate the broker, invoke internal mutation primitives, read the signing key, modify broker state, or mint approvals. Broker IPC authenticates user, session, transaction, and workspace identity.

### A3 — Fresh transaction provenance

Transaction roots are created by the broker with unguessable identities and are not caller-selected existing paths. A path is not trusted merely because its name or environment variable suggests that it is temporary.

### A4 — Stable generations

The baseline and staged generations used for planning and committing are immutable, frozen, or otherwise protected from concurrent writers. Optimistic digest checks may supplement but must not replace this property in the production boundary.

### A5 — Handle-relative commit semantics

The broker resolves normalized relative components beneath opened root handles without following symlinks/reparse points or crossing unintended mount/device boundaries. It does not authorize mutation using string-prefix containment alone.

### A6 — Cryptographic state integrity

Plan, transaction, approval, commit, and audit state is authenticated with a key unavailable to the agent. Object identity, protocol version, policy digest, state, expiry, and path namespace are included in verification. The cryptographic primitive and key storage are correctly implemented.

### A7 — Durable single-writer journal

Only one commit operation mutates a given workspace generation at a time. Every operation is durably journaled so restart recovery can either finish the approved commit or restore the prior state without guessing.

### A8 — Trusted platform and reviewer boundary

The kernel, filesystem, broker binary, and user account are not compromised. A reviewer or automatic review service can still approve harmful source code; AWG limits and records filesystem persistence but does not prove semantic benevolence of approved content.

## Security properties

### P1 — Pre-commit host confinement

Before a successful broker commit, agent execution cannot change the real workspace or real home.

### P2 — Exact persistence authorization

For every broker mutation of a real-workspace path, there is one pending plan containing that normalized relative path and its expected before/after identity. The plan is policy-allowed or has a valid approval bound to its complete fingerprint.

### P3 — Approval non-transferability

An approval for plan `p` cannot authorize plan `q` when any signed field differs, including protocol/policy identity, path set, file type, content digest, mode, baseline generation, staged generation, decision, expiry, transaction, or workspace.

### P4 — Stale-state rejection

A commit does not proceed when the real workspace differs from the approved baseline or the staged generation differs from the approved result.

### P5 — No recursive user-path purge

The normal commit mutation vocabulary contains rename-to-quarantine and install-from-staging, not recursive deletion rooted in a model- or user-supplied path.

### P6 — Recoverability before independent purge

Every replaced or deleted existing entry is retained in quarantine. Restore is permitted only when the live workspace still matches the committed generation, preventing restore from silently overwriting later work.

### P7 — Temporary-path provenance

The model cannot convert an existing host path into a trusted temporary root by assigning `HOME`, `TMP`, `TEMP`, `USERPROFILE`, `CODEX_HOME`, or another variable. Trust derives from a broker receipt and capability scope.

### P8 — Fail-closed ambiguity

Invalid identifiers, absolute or parent paths, escaping symlinks, special files, mount crossings, corrupt signatures, inconsistent manifests, expired state, excessive plans, and unsupported metadata stop the operation under ordinary policy.

## Proof sketch

### P1

By A1, the kernel denies mutation outside transaction roots to the agent and descendants. The broker has not yet committed, so no trusted component has changed the real workspace. Therefore arbitrary command syntax—including unrecognized or dynamically generated deletion code—cannot mutate the protected host trees before commit.

### P2

By A2, only the broker can mutate the real workspace. The broker accepts only normalized relative operations derived from the frozen staged/baseline generations (A4), verifies the signed plan and policy/approval, rejects policy-version drift, re-evaluates the deterministic result policy (A6), and resolves beneath fixed root handles (A5). Thus each broker mutation has a corresponding exact plan entry.

### P3

The approval contains the plan fingerprint, and the fingerprint commits to the complete immutable plan. Under A6, an attacker without the key cannot produce a valid token for a different fingerprint. Expiry and terminal plan state prevent indefinite or repeated authorization.

### P4

The broker binds the plan to baseline and staged generation identities and revalidates/finalizes against the same immutable generations (A4). A mismatch stops before mutation. The single-writer rule (A7) prevents another broker commit from racing the same generation.

### P5 and P6

For every existing target, the first live mutation is an atomic same-filesystem move into broker-owned quarantine. Installation occurs only afterward. Normal commit has no purge primitive against real-workspace paths. The journal (A7) preserves enough state to roll back or recover, and quarantine remains until separately authorized retention cleanup.

### P7

By A3, transaction roots are broker-created fresh objects. By A1, real host roots remain outside agent write authority even if process-local environment variables change. Variable text therefore cannot alter the underlying capability boundary.

### P8

The parser and policy reject inputs outside their structured domain, while A5 prevents path-resolution ambiguity at mutation time. Unsupported platform guarantees cause transactional mode to fail closed rather than silently downgrade the claim.

## Why command filters cannot establish P1–P4 alone

A command filter observes text or a partial syntax tree before arbitrary execution. The runtime effect may depend on environment expansion, cwd, configuration, package hooks, another interpreter, native code, symlinks, mounts, case rules, and concurrent state. Even a deterministic parser can deterministically miss a mechanism outside its model.

Command inspection is still valuable for:

- immediate denial of obvious root/home/privilege/mount/format intent;
- preserving disposable task progress;
- explaining risk to the model or user;
- routing to stronger review;
- generating evaluation labels.

It is not the premise of the host-file safety proof. A classifier miss is safe only because A1 confines authority and P2 mediates persistence.

## What this design does not prove

- That approved source code is benign, correct, license-compatible, or free of secrets.
- That a network-enabled agent cannot exfiltrate readable data.
- That the agent cannot consume CPU, memory, disk, or time inside its quota.
- That quarantine is a substitute for an independent backup.
- That a compromised kernel, broker, reviewer, administrator, or user account is contained.
- That the Python reference implementation closes OS-level races without the production adapters.
- That an explicit direct-host break-glass mode remains safe; enabling that mode intentionally abandons P1 for its scope.

## Verification obligations

A production implementation should not claim these properties until it passes tests that directly attempt to violate each assumption and property:

- native syscall and alternate-language mutation attempts against real workspace/home;
- writable-mount, symlink, junction, reparse-point, hard-link, and case-collision attacks;
- staged and real-workspace races at every plan/commit phase;
- approval replay, state swapping, expiry, corrupt manifests, and key/path substitution;
- process crashes and power-loss simulation at every journal transition;
- storage exhaustion during staging, quarantine, rollback, and restore;
- concurrent broker operations and external editor drift;
- behavior under every UI permission mode, especially Full access.

The acceptance criterion is the filesystem property—not merely whether the originating command was blocked.
