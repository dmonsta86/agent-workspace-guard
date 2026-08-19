# Reviewer Guide — v0.2.3

Agent Workspace Guard is an independent RFC and executable reference implementation for a transactional persistence boundary for coding agents.

> The agent writes only to a disposable transaction. A separate trusted broker persists one exact, signed, policy-approved filesystem result to the live workspace.

Command inspection remains defense in depth. It is not represented as proof that arbitrary commands are safe.

## Five-minute review

Read these in order:

1. [`docs/ONE_PAGE.md`](docs/ONE_PAGE.md) — concise architecture and scope.
2. [`docs/SECURITY_ARGUMENT.md`](docs/SECURITY_ARGUMENT.md) — assumptions, properties, and proof sketch.
3. [`docs/CODEX_INTEGRATION.md`](docs/CODEX_INTEGRATION.md) — proposed integration shape.
4. [`docs/IMPLEMENTATION_CHECKLIST.md`](docs/IMPLEMENTATION_CHECKLIST.md) — production acceptance gates.
5. [`docs/RFC.md`](docs/RFC.md) — complete design.

## Verify the reference implementation

Linux/macOS:

```bash
./scripts/verify.sh
```

PowerShell:

```powershell
./scripts/verify.ps1
```

Expected reference results:

```text
36 unit/integration tests passed
28/28 destructive-command replay cases passed
repository manifest verified
```

The GitHub Actions workflow runs the suite on Python 3.11 and 3.13 across Linux, macOS, and Windows.

## Production implementation order

1. Remove the agent and all descendants' write authority over the live workspace, real home, broker state, audit storage, and quarantine.
2. Create fresh broker-owned workspace, home, temp, config, cache, and state roots per transaction.
3. Freeze an immutable staged generation before producing a review object.
4. Compute one canonical result plan containing exact normalized paths, types, hashes, sizes, modes, policy result, and generation identities.
5. Bind approval to the complete plan fingerprint and policy digest.
6. Commit through a separate broker using handle-relative, no-follow operations and same-filesystem quarantine.
7. Add durable journaling, single-writer coordination, drift-safe restore, and independently authorized quarantine retention.

The complete production gate is in [`docs/IMPLEMENTATION_CHECKLIST.md`](docs/IMPLEMENTATION_CHECKLIST.md).

## Contribution route

A related upstream Codex issue already exists at `openai/codex#33624`. Prefer the concise comment in [`submission/OPENAI_CODEX_COMMENT.md`](submission/OPENAI_CODEX_COMMENT.md) over a duplicate issue. Repository metadata and public copy are in [`submission/`](submission/).

For a concrete, nonpublic sandbox or authorization bypass, use the product's current private security-reporting process instead of publishing exploit details.

## Accurate positioning

This is an independent RFC and protocol/reference implementation. It is not a complete OS sandbox, a claim about undisclosed internals, perfect destructive-command detection, or proof of an active vulnerability.
