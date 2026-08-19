# Agent Workspace Guard v0.2.3

This release hardens the public repository and reviewer experience without changing the broker or result-policy behavior introduced in v0.2.2.

## Highlights

- Fixes the GitHub Actions package-install failure by installing the declared build backend before using `--no-build-isolation`.
- Makes the source SHA-256 manifest stable across Windows, macOS, and Linux checkouts through repository-wide LF normalization.
- Updates the workflow to current Node 24-based GitHub Actions, disables persisted checkout credentials, runs the full matrix without fail-fast cancellation, and checks the installed `awg` CLI.
- Adds a five-minute architecture summary and a shorter review path.
- Adds ready-to-use repository metadata, an X reply, and an implementation-focused comment for the existing related Codex safety issue.
- Replaces placeholder URLs and obsolete first-publication instructions with the live repository and current contribution route.

## Verification

Local verification for this release passes:

- 36/36 unit and integration tests;
- 28/28 destructive-command replay cases;
- the 53-file source manifest;
- Python compilation and CLI smoke checks;
- editable package installation;
- a simulated `core.autocrlf=true` checkout with no CRLF-induced manifest drift.

## Scope

Agent Workspace Guard remains an independent RFC and executable protocol/reference implementation. It is not a standalone OS sandbox or a claim about undisclosed product internals. Production deployment still requires kernel-enforced authority separation, an agent-inaccessible broker, immutable staged generations, handle-relative/no-follow filesystem operations, durable crash recovery, and platform-specific filesystem hardening.
