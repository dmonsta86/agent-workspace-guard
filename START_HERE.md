# Start Here — Canonical Release v0.2.2

This repository is the **single canonical copy** of the Agent Workspace Guard proposal. It supersedes the earlier loose documents, preliminary ZIPs, and the original regex-only shell-safety packet.

The proposed security boundary is:

> **The agent writes only to a disposable transaction. A separate trusted broker persists one exact, signed, policy-approved filesystem result to the real workspace.**

The command inspector remains defense in depth. It is not represented as proof that arbitrary commands are safe.

## What to submit

Use the repository itself as the primary review artifact.

1. Publish this directory as a Git repository under your account.
2. Run `./scripts/verify.sh` and retain the CI link.
3. Paste `submission/GITHUB_ISSUE.md` into the appropriate upstream design/feature channel after checking the current contribution guidance.
4. Replace the repository placeholder in that issue text.
5. Link reviewers directly to:
   - `docs/RFC.md`
   - `docs/SECURITY_ARGUMENT.md`
   - `docs/CODEX_INTEGRATION.md`
   - `docs/IMPLEMENTATION_CHECKLIST.md`
6. Use `submission/TIBO_REPLY.md` only after the public repository URL works.

For a concrete, nonpublic sandbox or authorization bypass, follow the product's current private security-reporting process instead of publishing exploit details.

## What to implement first

The Python package demonstrates protocol behavior; it is not the operating-system sandbox. A production effort should begin in this order:

1. Remove the agent and all descendants' write authority over the real workspace, real home, broker state, audit storage, and quarantine.
2. Create fresh broker-owned workspace, home, temp, config, cache, and state roots for every transaction.
3. Freeze an immutable staged generation before producing a review object.
4. Compute one canonical result plan containing exact normalized paths, types, hashes, sizes, modes, policy result, and generation identities.
5. Bind approval to the complete plan fingerprint and policy digest.
6. Commit through a separate broker using handle-relative, no-follow operations and same-filesystem quarantine.
7. Add durable journaling, single-writer coordination, restore-with-drift-checking, and independent quarantine retention.

The complete production gate is in `docs/IMPLEMENTATION_CHECKLIST.md`.

## Verify this copy

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

## Publish this ZIP as Git

After extracting the canonical ZIP:

```bash
cd agent-workspace-guard
git init -b main
git add .
git commit -m "Agent Workspace Guard v0.2.2"
git tag -a v0.2.2 -m "Agent Workspace Guard v0.2.2"
git remote add origin <your-repository-remote>
git push -u origin main
git push origin v0.2.2
```

The release tooling can later generate a Git bundle and installable wheel from a clean tagged checkout:

```bash
python3 scripts/package_release.py --output release
```

## Accurate positioning

Describe this as an independent RFC and executable reference implementation for a transactional persistence boundary. Do not describe it as a confirmed fix for undisclosed internals, a complete production sandbox, perfect destructive-command detection, or proof of an active vulnerability.
