# Comment for openai/codex#33624

I built a small independent RFC and executable reference implementation that explores a complementary lower-level boundary for this failure class:

**Repository:** https://github.com/dmonsta86/agent-workspace-guard

The core invariant is:

> During ordinary task execution, the agent and every descendant process can write only to a disposable transaction. A separate trusted broker may persist one exact, fresh, policy-approved filesystem result to the live workspace.

That shifts the security question from “did we recognize every destructive command spelling?” to “did untrusted code ever possess the live-workspace writer capability?” Command checks, model instructions, action-time confirmation, Auto-review, and replay evaluations remain valuable, but a missed syntax can damage only disposable task state when the OS sandbox is correctly enforced.

The proposed flow is:

1. create a fresh disposable workspace plus broker-owned `HOME`/`USERPROFILE`, temp, config, and cache roots;
2. keep the live workspace, real home, broker state, audit storage, and quarantine non-writable to the agent and descendants;
3. freeze the staged result and compute a canonical semantic diff with exact paths, types, hashes, sizes, modes, link targets, baseline/staged identities, policy digest, expiry, and signature;
4. allow, require review, or deny that concrete result under deterministic policy;
5. bind any approval to the complete plan fingerprint rather than to a command prefix;
6. commit through a separate broker, moving replaced entries into same-filesystem quarantine before installing only the approved staged entries;
7. restore only when later user work would not be overwritten, and dispose task state by opaque transaction identity rather than a model-generated cleanup path.

This maps closely to the requested properties in this issue: scoped Full Access, a human-reviewable deletion/change manifest, recoverable deletion, cross-tool enforcement, and an append-only audit trail. It also covers deletes and overwrites reached through language APIs, package hooks, VCS operations, native helpers, or future tools absent from a command classifier.

The repository includes a full RFC, threat model, security argument, Codex integration sketch, production checklist, standard-library-only Python protocol implementation, 36 unit/integration tests, and 28 destructive-action replay cases.

Important limitation: the Python code is not represented as a production sandbox. The security property depends on kernel-enforced authority separation, an agent-inaccessible broker, immutable staged generations, authenticated IPC, handle-relative/no-follow commit operations, durable crash recovery, and platform-specific filesystem handling. Those requirements are explicit in the docs.

I am sharing this as design analysis rather than an unsolicited PR. The five-minute summary is in `docs/ONE_PAGE.md`; the complete architecture is in `docs/RFC.md`.
