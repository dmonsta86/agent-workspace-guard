# Review of the Supplied Shell-Safety Packet

## Overall assessment

The packet identified real and useful failure themes:

- reserved/system environment variables should not be repurposed as scratch state;
- nested shell quoting can change variable expansion behavior;
- broad recursive deletion deserves stronger review;
- shell-dialect collisions can create surprising files or targets;
- structured findings and replay tests are preferable to prose-only guidance.

Those ideas should be retained as model instructions, command-routing heuristics, and evaluation cases.

The packet was **not safe to present as an impermeable or deterministic prevention boundary**. Its Python, TypeScript, and PowerShell implementations mainly perform line-oriented pattern matching. That cannot establish the runtime target of arbitrary code, and the three independent versions create policy drift.

## Claims that should be removed

- “Zero runtime latency” and “less than 2 ms” without benchmark methodology, hardware, corpus, percentiles, and payload limits.
- “Deterministic guarantees” when many destructive mechanisms and evaluated-path states are outside the parser.
- “Impermeable boundary” for a component that does not control OS filesystem authority.
- “AST validation” as a general description when major paths are regular expressions and the Python/TypeScript versions do not parse full shell grammars.

A deterministic program can deterministically miss an input. Determinism of execution is not completeness of protection.

## Concrete gaps found during audit

The supplied Python validator reported the following as safe even though they can be destructive:

| Shape | Why it matters |
|---|---|
| `rm -rf "${TARGET:-/}"` | runtime default expansion can produce root |
| `find "$HOME" -mindepth 1 -delete` | deletion through another utility |
| `git clean -fdx` | removes untracked and ignored files |
| inline Python `shutil.rmtree(...)` | arbitrary interpreter API |
| `rsync --delete ... "$HOME"/` | deletion through synchronization semantics |
| PowerShell `Remove-Item -LiteralPath $HOME\* -Recurse -Force` | parameter form not matched |
| PowerShell `Remove-Item $HOME -Recurse -Force` | positional target form not matched |
| Cmd `rd /s /q %USERPROFILE%` | nested Cmd/profile form not matched |

The new replay corpus includes these cases, but AWG does not rely on perfect recall. With correct sandboxing, every one of them is confined to the transaction.

## Structural limitations

### Runtime evaluation

Shell ASTs do not reveal the final target of arbitrary programs. Variables, command substitution, configuration, symlinks, current directory, mount state, and other processes can change meaning between inspection and execution.

### Alternate deletion and overwrite paths

A denylist must continuously discover shell utilities, language APIs, package scripts, native binaries, direct syscalls, truncation, rename-overwrite, synchronization flags, and platform-specific commands.

### TOCTOU and symlink races

The packet checks text before execution; it does not bind a verified filesystem object to the actual mutation.

### No authority separation

The same shell that is being inspected still has the power to mutate user files if the filter misses. There is no kernel-enforced distinction between task scratch and host state.

### No provenance for temporary roots

A path is trusted because its text looks temporary, not because a broker created it fresh and issued a capability receipt.

### No exact plan or recovery

Approval is attached to a command rather than the evaluated diff. There is no signed plan fingerprint, quarantine, rollback journal, or drift-safe restore.

### Policy duplication

Python, TypeScript, and PowerShell patterns already differ. A production policy should have one semantic core and platform parsers/adapters, with shared replay fixtures.

## Recommended reuse

Keep the original packet only as source material for:

- model instructions against reserved variable reuse;
- shell syntax diagnostics;
- a command-inspection defense layer;
- cross-platform replay/evaluation cases;
- user-facing remediation messages.

Do not submit it as the primary fix. Submit the transactional architecture and reference implementation in this repository, with the packet review as rationale.
