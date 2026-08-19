# Recommended Submission Route

## Current best route

The repository is public at:

```text
https://github.com/dmonsta86/agent-workspace-guard
```

A directly related upstream issue already exists:

```text
https://github.com/openai/codex/issues/33624
```

Because that issue already requests harness-level confirmation, quarantine/recovery, cross-tool enforcement, scope-aware Full Access, and auditing, the best next step is to add the implementation-focused text from `OPENAI_CODEX_COMMENT.md` there. Do not open a duplicate issue unless a maintainer asks for a separate RFC thread.

Recommended sequence:

1. Make the repository's GitHub Actions matrix green.
2. Add the About description, homepage, and topics from `REPOSITORY_METADATA.md`.
3. Create a `v0.2.3` GitHub release after CI passes.
4. Post `OPENAI_CODEX_COMMENT.md` on the related upstream issue.
5. Link the successful CI run and `docs/ONE_PAGE.md`.
6. Use `TIBO_REPLY.md` for the concise public response.
7. Submit implementation code upstream only if maintainers invite a defined contribution under the current contribution policy.

## Private reporting boundary

Use the product's current private security-reporting route instead of a public issue when you have a concrete, validated, nonpublic sandbox, authorization, or host-write bypass whose disclosure could put users at risk. Do not publish credentials, personal paths, private source, raw rollouts, or exploit details merely to promote the architecture.

## Accurate positioning

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
