# Verification Record

This record describes the tagged reference implementation. It is evidence of repository behavior under the stated test environment, not proof that the Python process is an OS security boundary. v0.2.2 is a consolidation release; broker and policy code are unchanged from v0.2.1.

## Build environment

- Date: August 18, 2026 (America/Chihuahua)
- Python: 3.13.5
- Git: 2.47.3
- Runtime dependencies: Python standard library only
- Release tag: `v0.2.2`

## Source verification

```bash
./scripts/verify.sh
python3 examples/demo.py
```

Result:

- **36/36 unit and integration tests passed.**
- **28/28 destructive-command replay cases passed.**
- Repository SHA-256 manifest covering 48 files, Python compilation, and CLI smoke checks passed.
- The demo completed exact planning, approval binding, quarantine-first commit, authenticated audit verification, and drift-safe restore.

## Release-artifact verification

The release was generated from a clean checkout with:

```bash
python3 scripts/package_release.py --output /path/to/output
```

That script fails unless `v0.2.2` points at the clean release commit. It then:

1. verifies the source manifest and test suite;
2. creates a Git archive ZIP and Git bundle, then validates archive paths and contents;
3. builds the wheel twice with a fixed source epoch and requires byte-for-byte equality;
4. extracts the ZIP and reruns the manifest, 36 tests, 28 replays, CLI check, and demo;
5. clones the Git bundle, verifies the exact release commit, and reruns the manifest, tests, replays, and CLI check;
6. installs the wheel into an isolated virtual environment and confirms a catastrophic deletion replay is denied without echoing the raw command;
7. writes SHA-256 checksums for the ZIP, Git bundle, and wheel.

## Tested reference invariants

The suite exercises real-workspace isolation **before broker commit within the reference transaction model**, broker-owned environment roots, add-only automatic policy, approval-required overwrite/delete, mass-deletion denial, exact-plan approval binding, real/staged drift rejection, baseline/plan/state tamper detection, object-ID path traversal rejection, VCS metadata exclusion, symlink non-following and escape denial, executable-content review, quarantine restore, audit-chain integrity, signing-key symlink rejection, and cross-shell destructive replays.

## Not established by these tests

The suite does not establish kernel isolation, immutable snapshot behavior, handle-relative no-follow mutation, complete process-crash recovery, cross-process audit serialization, or production-scale performance. Those are explicit production integration requirements in `docs/SECURITY_ARGUMENT.md` and `docs/PRODUCTION_HARDENING.md`.
