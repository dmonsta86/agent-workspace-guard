# Contributing

Changes should preserve the primary invariant: an untrusted agent has no direct authority to mutate the real workspace, and persistence occurs only through an exact signed plan.

Before submitting changes:

```bash
./scripts/verify.sh
```

Add replay cases for every new command heuristic and filesystem-state tests for every broker invariant. Avoid claims such as “complete,” “zero latency,” “impermeable,” or “guaranteed” unless the claim has an explicit threat model, proof, and platform validation.
