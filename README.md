# litmus

Owner-side qualification tooling: an evidence-bundle packager and
verifier, plus the gate that qualifies them.

This repository holds a small set of Python tools and carries no
application code. CI runs lint, formatting, type checks, staging
regression tests, and packager and recorder checks on pull requests and
pushes to main. The disk-heavy R10 check remains local.

## Contents

- `packager.py` - builds an evidence bundle (evidence files plus a
  manifest) and publishes it atomically. The producer emits evidence and
  a manifest only; it never emits a verdict.
- `verifier.py` - validates a published bundle and emits the verdict.
  Only the verifier emits verdicts, and each verdict binds the
  manifest-declared bundle name, the bundle's absolute path, and the
  bundle's manifest sha256.
- `checks.py` - the qualification gate: 16 checks over the packager and
  verifier, using real mechanisms (real kills, real OS write errors, a
  real second filesystem).
- `recorder.py` - records one observed run (commit, exact argv, start and
  end, exit, timeout, runtime, output hashes) as a receipt in one schema
  for every suite.
- `recorder-checks.py` - the recorder's qualification gate: 10 checks,
  using real mechanisms (a real git work tree, a real timeout with a real
  SIGKILL).
- `docs/qualification-contract.txt` - the packager/verifier technical
  contract: components, guarantees, non-claims, usage, check definitions,
  and the dated qualification runs.
- `docs/run-receipt-contract.txt` - the recorder's technical contract:
  receipt fields, guarantees, non-claims, usage, check definitions, and
  the dated qualification runs.

## Requirements

- Python 3, standard library only.
- git, for the recorder to read HEAD and worktree state.
- Linux on x86-64 with a 64-bit Python process. The packager's publish
  uses the renameat2(RENAME_NOREPLACE) syscall for atomic, no-overwrite
  visibility; the recorder publishes with two no-overwrite hard links
  instead. Any other platform, architecture, process width, or a kernel
  without renameat2 fails closed for the packager: publish is refused.
  The contracts state the exact boundaries.

## Use

Re-qualify the tools against their contract:

    python3 checks.py

Package evidence and verify a bundle:

    python3 packager.py EVIDENCE_DIR OUT_PARENT BUNDLE_NAME
    python3 verifier.py BUNDLE_PATH

Record a run as a receipt:

    python3 recorder.py RECEIPT_PATH [--timeout SECONDS] [--cwd DIR] [--commit COMMIT] -- COMMAND [ARG...]

Re-qualify the recorder against its contract:

    python3 recorder-checks.py

After any edit to the tool files, re-run the matching gate.

## Scope

- The guarantees are atomic visibility and no overwrite of an existing
  target. Power-loss durability is untested, and staging cleanup on
  interruption is not guaranteed; unpublished staging can never
  masquerade as complete because only the exact published path with a
  complete manifest is trusted.
- Verdicts bind evidence bytes and bundle identity. They are not
  signatures and do not prove authorship.
- Receipts record single observed runs. They are not minimum-runtime
  proofs, not benchmarks, and do not replace CI.
- The tools can be run by hand; CI also runs the checks listed above.
