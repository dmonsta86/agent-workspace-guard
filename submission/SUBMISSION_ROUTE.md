# Recommended Submission Route

This guidance is intentionally independent of live service status. Recheck the destination project's current contribution and security policies immediately before submission.

## Primary route for this package

This repository is an architectural hardening proposal and executable reference implementation. It does not, by itself, establish a nonpublic vulnerability in a deployed product.

Recommended sequence:

1. Publish this repository under your own account so reviewers can inspect source, history, tests, and CI.
2. Search the destination issue/discussion tracker for an existing proposal covering transactional workspaces, destructive actions, exact-result approval, quarantine, or commit brokers.
3. Add the analysis to an existing thread when it clearly matches; otherwise open a focused design or feature proposal.
4. Paste `submission/GITHUB_ISSUE.md` and replace the repository placeholder.
5. Link directly to `docs/RFC.md`, `docs/SECURITY_ARGUMENT.md`, `docs/CODEX_INTEGRATION.md`, `docs/IMPLEMENTATION_CHECKLIST.md`, and the successful CI run.
6. Use the public X reply only after the repository URL works.
7. Do not open an unsolicited implementation pull request unless the current upstream contribution guide permits it or a maintainer invites a defined slice.

The public repository URL should be the primary review surface. The canonical source ZIP is the immutable transfer copy.

## When private security reporting is appropriate

Use the product's current private security-reporting route instead of a public issue when you have a concrete, validated, nonpublic sandbox, authorization, or host-write bypass whose disclosure could put users at risk.

A useful private report includes:

- affected product, build, and platform;
- exact preconditions and permission mode;
- a minimal sanitized reproduction;
- expected and actual protected-host behavior;
- evidence that a stated or observable boundary is bypassed;
- impact and recovery observations;
- no live credentials, customer data, personal paths, or unnecessary private source.

A public architecture proposal and a separate private vulnerability report can coexist. Do not publish exploit details merely to promote the design.

## Publish from the canonical ZIP

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

Verify before publishing:

```bash
./scripts/verify.sh
git status --short --branch
git log --oneline --decorate -n 3
git fsck --full
```

## Optional release artifacts

From a clean checkout whose `v0.2.2` tag points at `HEAD`:

```bash
python3 scripts/package_release.py --output release
```

The script independently verifies and generates:

- a source ZIP without `.git`;
- a complete Git bundle;
- an installable Python wheel;
- SHA-256 checksums.

These are transport formats for the same release, not separate versions.

## Presentation guidance

Describe this as:

- a transactional persistence architecture;
- defense in depth beneath command classification;
- an RFC and executable reference implementation;
- conditional on OS sandbox and production broker assumptions.

Do not describe it as:

- a confirmed fix for undisclosed internals;
- a perfect command detector;
- zero-overhead or impermeable;
- ready to drop into production without platform work;
- proof that a currently deployed system is vulnerable.
