# Why Command Filters Are Not Filesystem Safety Boundaries

## The category error

A command filter answers a useful but limited question:

> Does this payload contain a command shape we know how to classify?

The required host-safety question is different:

> What concrete filesystem objects can the executing process mutate, and what exact result will be persisted?

The first question can improve routing and feedback. It cannot, by itself, establish the second for arbitrary code.

## Deterministic does not mean complete

A regex engine, parser, or policy evaluator may be perfectly deterministic while its model of the world is incomplete. Missing one execution path is enough when the inspected process still holds write authority over user files.

Deletion and overwrite can be reached through:

- shell built-ins, aliases, functions, continuations, substitutions, and nested shells;
- `find -delete`, synchronization tools, VCS cleanup, archive extraction, and package lifecycle hooks;
- Python, Node, Ruby, PowerShell, .NET, Rust, C/C++, or native binaries;
- direct system calls, rename-overwrite, truncation, hard links, symlinks, junctions, and reparse points;
- configuration files or environment state that change the target at runtime;
- a tool or API absent from the classifier's training and rule set.

Even a full shell AST normally cannot reveal the final path touched by an arbitrary child program.

## Runtime identity matters

Textual checks do not bind a verified object to the eventual mutation. Between inspection and use:

- variables can expand differently;
- cwd can change;
- a symlink or mount can be replaced;
- another process can alter the tree;
- case folding or Unicode normalization can change path identity;
- a path that looked empty or temporary can become occupied.

A production broker must resolve normalized relative components beneath opened root handles, reject no-follow/mount violations, and operate on immutable or frozen generations.

## Command approval is not result approval

The same command prefix can produce different effects under a different:

- current directory;
- environment;
- repository state;
- configuration file;
- program version;
- symlink/mount layout;
- input data.

A reusable approval for `tool clean ...` is therefore not equivalent to approval of “delete these 12 exact paths from this exact baseline.” AWG binds approval to the latter.

## Appropriate use of command inspection

Command inspection remains a worthwhile layer for:

- denying explicit root, home/profile, privilege, mount, filesystem-format, or ACL intent;
- preventing the model from reassigning broker-owned home/temp identities;
- preserving progress inside the disposable transaction;
- triggering a checkpoint or exact-diff review;
- giving the model actionable remediation;
- collecting targeted replay/evaluation labels.

The included inspector intentionally returns `allow`, `require_approval`, or `deny` as routing outcomes and states that it is not the security boundary. Its telemetry contains a command hash and length rather than the raw payload.

## The safer composition

```text
model instructions
      +
command/AST heuristics
      +
execution policy and approval routing
      +
OS sandbox: agent cannot write host workspace/home
      +
exact staged-result plan
      +
digest-bound approval
      +
quarantine-first commit broker
      +
replay and filesystem-state evaluations
```

The upper layers reduce incidents and improve UX. The lower authority and persistence layers provide the property that a missed syntax pattern cannot directly destroy host files.

## Representative replay shapes

The shared corpus includes variants such as:

- default expansion to root: `rm -rf "${TARGET:-/}"`;
- absolute executable and long options: `/usr/bin/rm -rf /`, `rm --recursive --force /`;
- braced home/profile targets;
- `find ... -delete`, `git clean`, `rsync --delete`;
- inline language deletion APIs;
- PowerShell positional and `-LiteralPath` forms;
- Cmd recursive directory removal;
- shell line continuations;
- safe controls such as a local PowerShell `$path` variable, `PATH` customization, and `2>&1` stream redirection.

Passing this corpus improves the advisory layer. The stronger evaluation remains: **did the real workspace and real home remain unchanged until an exact approved plan committed?**
