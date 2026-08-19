# Implementation Checklist

This checklist is for integrating the transactional persistence boundary into a real coding-agent host. The Python package demonstrates protocol behavior; it is not the process sandbox.

## 1. Establish the authority split first

Do not expose transactional mode until an adversarial child process is unable to mutate:

- the real workspace and its VCS metadata;
- the user's real home/profile and application-state roots;
- broker state, signing material, approval state, quarantine, and audit storage;
- unrelated host paths, writable mounts, devices, and privileged control surfaces.

Apply the restriction to the complete descendant process tree, not only the first shell. A command classifier, environment-variable convention, prompt instruction, or read-only UI label does not satisfy this requirement.

**Gate:** launch native syscall, nested-shell, package-hook, and alternate-language writes against every protected root. Transactional mode must fail closed if any write succeeds.

## 2. Create broker-owned transaction roots

For each task, a trusted component creates fresh opaque objects for:

- staged worktree;
- task home/profile;
- temp/runtime directory;
- application/config/cache/data/state directories;
- baseline generation and transaction receipt.

Reject caller-selected existing roots. Never infer temporary provenance from a path name or from `HOME`, `TMP`, `TEMP`, `USERPROFILE`, or similar text supplied by the model.

**Gate:** every transaction root has a broker-issued identity and is disjoint from the real workspace, real home, and broker state.

## 3. Remove writable VCS back-pointers

A disposable tree must not contain a writable `.git` file or directory that points into the user's live repository. Choose one of:

- filesystem snapshot/overlay with VCS metadata protected independently;
- fully isolated disposable clone;
- read-only/proxied VCS metadata service;
- a deliberately limited first release that excludes unsupported VCS operations.

**Gate:** destructive Git commands in the transaction cannot change live refs, index, config, hooks, worktrees, remotes, or object-store state.

## 4. Freeze a stable staged generation

Before planning or approval, stop writers or create an immutable generation. Hash-after-copy checks are useful diagnostics but are not a production substitute for snapshot/freeze semantics.

**Gate:** an adversarial writer cannot change any approved byte, mode, type, link target, or path after the review object is created.

## 5. Produce one canonical result plan

The broker computes the semantic difference between immutable baseline and staged generations. Include:

- protocol version and complete-policy digest;
- transaction, session/user, task, and workspace identities;
- normalized relative paths only;
- add/modify/delete/type-change kind;
- before/after entry type, content identity, mode, size, and link target where relevant;
- aggregate counts and byte totals;
- deterministic findings and decision;
- baseline/staged generation identities;
- short creation/expiry times, plan ID, state, fingerprint, and signature.

Reject absolute, drive-qualified, UNC, dot, parent, empty, ambiguous-case, escaping-link/reparse, cross-mount, and unsupported metadata forms.

**Gate:** serializing, deserializing, or reordering data cannot change the canonical fingerprint; any semantic change must change it.

## 6. Separate execution approval from persistence approval

Use distinct capabilities and UI objects for:

- command execution;
- network;
- read scopes;
- sandbox expansion;
- exact-result persistence;
- quarantine purge;
- direct-host break-glass mutation.

A persistence approval is short-lived and bound to one complete plan fingerprint, reviewer identity, session/workspace, and policy digest. The agent cannot mint or broaden it.

**Gate:** a token for one plan, policy, transaction, workspace, reviewer, or expiry cannot authorize another.

## 7. Commit through a small trusted broker

Immediately before mutation, the broker must:

1. authenticate the caller and request context;
2. verify signed transaction, plan, approval, and terminal state;
3. verify protocol and policy identity, then re-run deterministic policy;
4. rebind to the same immutable baseline and staged generations;
5. acquire a durable single-writer workspace lease;
6. prepare new entries on the target filesystem;
7. journal the complete intended operation set;
8. move every existing operation root into protected same-filesystem quarantine;
9. install staged entries using handle-relative, no-follow platform APIs;
10. verify the final generation and durably mark completion;
11. roll back or enter an explicit repair state on any failure.

Normal commit must not contain a recursive-delete primitive over a user-supplied path.

**Gate:** crash and power-loss injection at every journal transition yields either the approved result, the original result, or an explicit recoverable repair state—never an untracked hybrid.

## 8. Govern quarantine independently

Quarantine is broker-owned, inaccessible to the agent, quota-controlled, encrypted where appropriate, and retained under an explicit policy. Purge is a separate authorization from commit and restore.

Restore must fail when the live workspace no longer equals the recorded committed generation; it must not overwrite later user work.

**Gate:** storage exhaustion, missing backup entries, concurrent edits, and partial restore all fail visibly and preserve evidence.

## 9. Authenticate state and audit

Protect transaction, plan, approval, commit, and audit state with keys unavailable to the agent. Include object type and identity in every signature domain. Reject symlinked/reparse state paths and swapped records. Anchor audit heads outside the broker host or in an append-only service.

Do not put raw shell commands, credentials, source contents, or personal paths into default telemetry. Prefer event type, decision, reason codes, counts, and keyed or unkeyed hashes according to the privacy model.

**Gate:** state edits, record swaps, truncation, replay, expired tokens, key substitution, and audit rewriting are detected.

## 10. Keep command review as defense in depth

Continue blocking obvious root/home/profile, privilege, mount, format, device, and ACL intent. Use command detections to checkpoint, warn, preserve task progress, and create evaluations.

Do not make host-file protection depend on enumerating every deletion API, alias, interpreter, package hook, binary, or future tool.

**Gate:** unknown destructive programs and direct filesystem syscalls still cannot mutate protected host trees.

## 11. Roll out by property gates

Recommended order:

1. offline adversarial and crash testing;
2. shadow plan generation against normal tasks;
3. internal sandboxed transactions with no persistence;
4. exact-result review plus quarantine commit on one platform/filesystem;
5. opt-in user rollout;
6. default transactional persistence for approval-oriented modes;
7. broad-access modes with persistence still mediated;
8. separately named direct-host break-glass mode only where unavoidable.

Stop rollout on any host-write escape, approval mismatch, unrecoverable commit, unexplained final-tree mismatch, or silent downgrade of a required platform guarantee.

## Reference acceptance command

The repository reference should remain green while the production adapters are developed:

```bash
./scripts/verify.sh
```

Passing these tests validates the reference protocol behavior only. Production acceptance is the platform property matrix in `docs/ROLLOUT_AND_EVALUATION.md`, `docs/SECURITY_ARGUMENT.md`, and `docs/PRODUCTION_HARDENING.md`.
