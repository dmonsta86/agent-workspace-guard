# Production Hardening Requirements

The reference implementation is designed to make the protocol inspectable. The following controls are mandatory before the system is represented as a production security boundary.

## 1. Enforce the authority split in the kernel

The agent and every descendant process must be unable to mutate the real workspace, real home/profile, broker state, quarantine, and unrelated host paths—even through native code or direct syscalls.

- Apply platform filesystem rights, namespace/sandbox, process-token, and mount controls.
- Cover write, truncate, delete, rename/refer, create, metadata/ACL changes, mount operations, devices, and alternate streams.
- Ensure child processes cannot escape or obtain a stronger token.
- Run startup self-tests that attempt forbidden mutations and verify denial.
- Fail closed when the effective boundary cannot be established. Do not infer protection from a UI mode alone.

## 2. Isolate the broker

- Run the broker outside the agent sandbox under a distinct identity/capability.
- Expose a small typed IPC protocol; never expose arbitrary filesystem primitives.
- Authenticate user, session, transaction, workspace, and request nonce.
- Keep signing keys and broker paths unavailable to the agent.
- Prevent the agent from replacing the broker executable, socket/pipe endpoint, or trusted UI response.
- Rate-limit and budget plan/commit requests.

## 3. Use immutable generations

The plan and commit must refer to stable baseline and staged generations.

Preferred approaches:

- native filesystem snapshots or copy-on-write clones;
- a frozen overlay generation;
- immutable content-addressed objects;
- writer suspension plus exclusive generation lock when no snapshot primitive exists.

Re-scanning before and after copying, as the Python reference does, is useful detection but not a complete replacement for immutability against a concurrent malicious process.

## 4. Resolve by handles, not path strings

Commit adapters must:

- open and retain handles/descriptors to workspace, staging, and quarantine roots;
- accept only typed normalized relative components;
- reject absolute, drive-qualified, UNC, empty, dot, parent, and ambiguous forms;
- perform no-follow resolution for every component;
- reject symlink, junction, reparse, mount, or device traversal not explicitly represented in the plan;
- verify expected object identity before moving/replacing;
- use descriptor/handle-relative rename and create operations;
- avoid string-prefix containment and check-then-use paths.

On Linux, the intended family includes constrained `openat2` resolution and descriptor-relative rename operations. Windows needs opened-handle/reparse-point discipline. macOS needs equivalent no-follow, opened-directory, and filesystem-identity checks.

## 5. Make the journal crash-recoverable

Before each live mutation, durably record:

- operation ID and plan fingerprint;
- expected source/destination identities;
- intended transition;
- quarantine and staged object identity.

After each mutation, durably record completion and sync the relevant journal and directory metadata.

On broker startup:

- detect every incomplete commit/restore;
- reconcile live, staged, and quarantine identities;
- deterministically finish or roll back when safe;
- enter an explicit `repair_required` state when evidence is ambiguous;
- never purge objects needed for recovery.

Use crash/fault injection at every transition, including process termination, host restart, short write, lost fsync, disk full, and permission failure.

## 6. Enforce single-writer coordination

The reference audit log is thread-safe within one process, but production needs cross-process and cross-device coordination.

- Serialize commits per workspace generation.
- Use leases/locks with owner identity, fencing token, expiry, and recovery—not a permanent stale lock file.
- Coordinate with product-managed editors or explicitly treat external editor changes as drift.
- Fence a restarted broker from an older instance.
- Anchor audit heads or commit sequence numbers in trusted storage to detect truncation/forking.

## 7. Protect and govern quarantine

- Keep quarantine on the same filesystem/volume when atomic rename is required.
- Encrypt or strongly access-control prior versions.
- Separate quarantine by user, tenant, workspace, and commit.
- Apply quotas, storage-pressure behavior, and retention windows.
- Never purge using a model-supplied path.
- Require independent authorization for irreversible purge.
- Audit commit, restore, export, retention extension, and purge.
- Define behavior when quarantine space is insufficient before beginning live mutation.

Quarantine improves recoverability; it is not an independent backup against account, disk, or broker compromise.

## 8. Preserve filesystem semantics deliberately

Define and test policy for:

- permission and executable bits;
- ownership, ACLs, inheritance, and file flags;
- extended attributes, resource forks, and alternate data streams;
- hard links and link-count identity;
- symlinks, junctions, and reparse points;
- sparse/compressed/encrypted files;
- timestamps and birth/change time;
- case folding and Unicode normalization;
- file locks, sharing modes, and open handles;
- submodules and repository metadata;
- sockets, FIFOs, devices, and other special entries.

Unknown or unsupported semantics must deny or require an explicitly weaker non-security mode. Silent metadata loss can itself be destructive.

## 9. Isolate VCS metadata

Do not expose a writable `.git` pointer into the user's repository. A disposable Git worktree can still reference shared repository objects and refs.

Use one of:

- a filesystem snapshot/overlay of the working tree with VCS metadata unavailable;
- a fully isolated disposable clone;
- a read-only object/ref mirror plus a brokered VCS service;
- another backend whose shared objects cannot be mutated by the agent.

Treat VCS commit/ref publication as a separate exact operation if it is supported.

## 10. Bound resources and denial of service

Set limits for:

- manifest entries and bytes;
- individual file size;
- plan changes and serialized plan size;
- directory depth and path length;
- hashing, copy, commit, and restore time;
- transaction lifetime and number of open transactions;
- home/temp/cache growth;
- quarantine growth;
- audit and telemetry volume.

Budget exhaustion must stop before partially mutating the live workspace or must enter journaled rollback/repair.

## 11. Protect approvals and UX semantics

- Render the exact subject and scope of every grant.
- Treat empty, truncated, unrenderable, or version-unknown plans as non-approvable.
- Show delete/overwrite/type-change counts and high-risk paths prominently.
- Bind displayed content to the signed plan fingerprint.
- Keep approval lifetimes short and nonpersistent by default.
- Separate command execution, network, read scope, sandbox expansion, exact-result persistence, purge, and direct-host break glass.
- Do not allow a rejected plan to be retried through silent policy downgrade.
- Make restore discoverable while its no-drift precondition holds.

## 12. Minimize telemetry exposure

- Do not collect raw commands or file contents by default.
- Hash or redact identifiers and relative paths where possible.
- Never upload secrets, credentials, personal files, or quarantine contents without explicit user action.
- Record decision/finding codes, counts, sizes, latency, drift, rollback, and compatibility outcomes.
- Separate local forensic artifacts from opt-in product telemetry.

## 13. Validate adversarially across platforms

Test:

- Bash, Zsh, Fish, PowerShell, and Cmd wrappers;
- Python, Node, Ruby, .NET, compiled helpers, package hooks, and build scripts;
- direct syscalls and unrecognized binaries;
- symlinks, junctions, reparse points, hard links, mount points, case collisions, and Unicode variants;
- baseline and staged races;
- crashes at every journal transition;
- low disk space, quota exhaustion, antivirus/file-indexer interference, and sharing violations;
- untracked/ignored files and large/binary repositories;
- every permission mode, especially broad/Full access;
- broker restart, duplicate request, replay, state swap, clock anomaly, and key rotation.

The release criterion is protected host-state behavior, not command-classifier recall alone.
