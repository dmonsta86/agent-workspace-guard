# Threat Model

## Protected assets

- Real workspace contents, including untracked, ignored, generated, and metadata-bearing files.
- Real user home/profile, application configuration, credentials, and caches not explicitly delegated.
- Version-control metadata, refs, indexes, and object stores.
- Broker state, signing keys, IPC credentials, plans, approvals, journals, quarantine, and audit records.
- User work created after an earlier broker commit.

## Adversary

Assume the model, repository, dependency, build script, package hook, or tool may cause arbitrary user-level code to execute inside the agent task domain. That code may:

- emit malformed or intentionally destructive commands;
- invoke nested shells, interpreters, package managers, native binaries, or direct APIs;
- modify cwd and environment variables;
- create, replace, and race symlinks, junctions, reparse points, hard links, or files;
- destroy the entire staged tree, home, or temp namespace;
- claim an existing path as temporary;
- race plan/commit by changing staged content;
- spoof logs or manipulate prompts and automatic review;
- request broad permissions with misleading rationale;
- exhaust disk, inode, CPU, memory, or journal budgets;
- replay, swap, truncate, or corrupt state files it can reach.

The security design should remain safe against an unrecognized command or binary. It must not depend on the adversary using a known shell spelling.

## Trusted computing base

- Host kernel and filesystem implementation.
- Platform sandbox/namespace/token configuration.
- Transaction/snapshot backend.
- Commit broker, platform adapter, journal, and signing-key storage.
- Authenticated broker IPC and identity binding.
- Approval UI or trusted automatic reviewer that issues approval through the broker.
- Quarantine storage and retention service.

A compromised kernel, administrator, broker binary, approval authority, or user account is outside the primary threat model.

## Required isolation

The agent and descendants must not have direct authority to:

- write, truncate, delete, rename, link into, mount over, or change metadata/ACLs on the real workspace/home;
- access broker keys, writable state, quarantine, or IPC credentials;
- obtain a stronger process token or escape the sandbox;
- mutate a shared writable VCS repository through a staged `.git` pointer.

Read and network access remain separate privacy/security decisions. This design does not prevent exfiltration of data the agent is allowed to read.

## Security objectives

### O1 — Host mutation confinement

Before a successful broker commit, arbitrary agent code cannot alter protected host files.

### O2 — Exact result mediation

Every broker mutation of the live workspace is represented in one canonical plan derived from stable baseline/staged generations.

### O3 — Exact, fresh authorization

Approval is bound to one complete plan fingerprint, user/session/workspace identity, and short lifetime.

### O4 — Recoverable destructive persistence

Existing entries are quarantined before replacement or deletion and remain available until independent purge.

### O5 — Broker-owned temporary provenance

Only broker-created roots receive transaction trust. Variable names and path appearance do not establish provenance.

### O6 — Fail-closed ambiguity

Invalid or unsupported path, metadata, state, lifetime, generation, filesystem, resource, or recovery conditions stop the operation.

## Attack analysis

| Attack | Primary control | Additional layer |
|---|---|---|
| `HOME` reused as scratch and deleted | real home outside agent write authority; disposable task home | reserved-root command finding |
| Unset/defaulted variable resolves to root | host root unavailable for mutation | catastrophic-target denial |
| Unknown API or native binary deletes files | only staged roots writable | replay/intent routing |
| Existing directory claimed as temp | fresh broker root and signed receipt | opaque transaction IDs |
| Writable `.git` points to real repository | VCS metadata isolated/proxied | protected-path policy |
| Symlink/junction points outside project | handle-relative no-follow broker; sandbox | unsafe-link hard denial |
| Staged tree changes after review | immutable staged generation | short expiry and recheck |
| Real workspace changes after planning | baseline generation/fencing | drift-safe rebase UX |
| Approval replay on changed plan | fingerprint-bound token | plan terminal state |
| Signed record copied to another state path | requested-ID/path identity validation | authenticated state |
| Baseline manifest edited without key | recompute contents/totals/digest | state inaccessible to agent |
| Crash after live entry moved | durable journal and quarantine | startup recovery/repair |
| Mass deletion hidden in normal work | exact counts/fraction and normal-policy denial | explicit break-glass mode |
| User enables broad/Full access | persistence remains broker-mediated | separate direct-host capability |
| Raw command contains a credential | default inspector emits digest/length only | local-only detailed diagnostics |
| Quarantine fills disk | preflight capacity/quota and fail before mutation | retention/storage policy |

## Residual risks

- A sandbox or broker misconfiguration can invalidate the primary property. Effective denial must be tested at runtime.
- A trusted reviewer can authorize harmful or backdoored source code. Exact scope and recovery reduce impact but do not replace code review.
- Network/read permissions can permit data exfiltration independent of filesystem persistence.
- Quarantine can contain sensitive prior versions and requires strong access control and lifecycle governance.
- External editors cause plans to invalidate; automatic merge is intentionally outside the reference design.
- The Python implementation uses path-based operations and optimistic scans. Production must use the primitives in `PRODUCTION_HARDENING.md`.
- Direct-host break-glass execution abandons host confinement for its explicit scope.
