#!/usr/bin/env python3
"""Qualification checks for the run receipt recorder.

Real mechanisms only: a real git work tree, real subprocesses, a real
timeout with a real SIGKILL of the run's process group, and real existing
files for the no-overwrite refusals. Each check returns a detail string;
the driver prints one line per check and exits nonzero if any fail. This
gate qualifies the recorder's own behavior ONLY; it certifies nothing
about any run the recorder records.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import recorder

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDER = os.path.join(HERE, "recorder.py")
sys.path.insert(0, HERE)


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *cmd], capture_output=True, text=True)


def git(cwd: str, *args: str) -> str:
    r = subprocess.run(["git", "-C", cwd, *list(args)], capture_output=True, text=True)
    assert r.returncode == 0, f"git {args} failed: {r.stderr}"
    return r.stdout.strip()


def make_repo(root: str) -> str:
    repo = os.path.join(root, "repo")
    os.makedirs(repo)
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "gate@example.invalid")
    git(repo, "config", "user.name", "Gate")
    with open(os.path.join(repo, "tracked.txt"), "w") as f:
        f.write("tracked\n")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def read_receipt(path: str) -> "tuple[recorder.Receipt, bytes]":
    with open(path, "rb") as f:
        raw = f.read()
    receipt: recorder.Receipt = json.loads(raw.decode("utf-8"))
    return receipt, raw


def check(name: str) -> Callable[[Callable[[str], str]], Callable[[str], str]]:
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        CHECKS.append((name, fn))
        return fn

    return deco


CHECKS: list[tuple[str, Callable[[str], str]]] = []


@check("R1 passing run recorded exactly")
def r1(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "pass.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('hello-run\\n')",
        ]
    )
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    assert set(receipt) == recorder.RECEIPT_FIELDS, sorted(receipt)
    assert receipt["version"] == 1
    assert receipt["commit"] == git(repo, "rev-parse", "HEAD")
    assert receipt["worktree_clean"] is True
    assert receipt["argv"] == [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('hello-run\\n')",
    ]
    assert receipt["cwd"] == repo
    assert receipt["exit"] == 0
    assert receipt["timed_out"] is False
    assert receipt["signal"] is None
    assert receipt["timeout_seconds"] is None
    assert receipt["runtime_seconds"] > 0
    out = receipt["output"]
    assert set(out) == recorder.OUTPUT_FIELDS
    log = os.path.join(t, "pass.json.log")
    with open(log, "rb") as f:
        log_bytes = f.read()
    assert b"hello-run" in log_bytes
    assert out["bytes"] == len(log_bytes)
    import hashlib

    assert out["sha256"] == hashlib.sha256(log_bytes).hexdigest()
    return "commit, argv, exit 0 and output hash recorded exactly"


@check("R2 failing exit code recorded and propagated")
def r2(t: str) -> str:
    repo = make_repo(t)
    rp = os.path.join(t, "fail.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            "import sys; sys.exit(3)",
        ]
    )
    assert r.returncode == 3, (r.returncode, r.stderr)
    receipt, _ = read_receipt(rp)
    assert receipt["exit"] == 3
    assert receipt["timed_out"] is False
    assert receipt["signal"] is None
    return "exit 3 recorded; recorder exits 3"


@check("R3 timeout kills the run's process group with a real SIGKILL")
def r3(t: str) -> str:
    repo = make_repo(t)
    rp = os.path.join(t, "slow.json")
    pidfile = os.path.join(t, "child.pid")
    child = (
        "import os,time; "
        f"open({pidfile!r},'w').write(str(os.getpid())); "
        "print('before-sleep', flush=True); time.sleep(60)"
    )
    t0 = time.monotonic()
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--timeout",
            "1",
            "--",
            sys.executable,
            "-c",
            child,
        ]
    )
    wall = time.monotonic() - t0
    assert r.returncode == 124, (r.returncode, r.stderr)
    assert wall < 20, f"kill did not return promptly: {wall:.1f}s"
    receipt, _ = read_receipt(rp)
    assert receipt["timed_out"] is True
    assert receipt["exit"] is None
    assert receipt["signal"] == 9
    assert receipt["timeout_seconds"] == 1.0
    with open(pidfile) as f:
        pid = int(f.read())
    try:
        os.kill(pid, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    assert not alive, f"child process {pid} survived the timeout"
    log = os.path.join(t, "slow.json.log")
    with open(log, "rb") as f:
        assert b"before-sleep" in f.read()
    return "timed_out, null exit, signal 9; child really dead"


@check("R4 existing receipt or log refuses before the command starts")
def r4(t: str) -> str:
    repo = make_repo(t)
    rp = os.path.join(t, "taken.json")
    r = run([RECORDER, rp, "--cwd", repo, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 0, r.stderr
    _, original = read_receipt(rp)
    marker = os.path.join(t, "should-not-exist")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            f"open({marker!r},'w').write('x')",
        ]
    )
    assert r.returncode == 1
    assert not os.path.exists(marker), "command ran despite refusal"
    _, after = read_receipt(rp)
    assert original == after, "existing receipt changed"
    orphan = os.path.join(t, "orphan.json")
    with open(orphan + ".log", "w") as f:
        f.write("orphan log\n")
    r = run(
        [
            RECORDER,
            orphan,
            "--cwd",
            repo,
            "--",
            sys.executable,
            "-c",
            f"open({marker!r},'w').write('x')",
        ]
    )
    assert r.returncode == 1
    assert not os.path.exists(marker)
    assert not os.path.exists(orphan), "receipt written over orphan log"
    return "receipt and log collisions refuse before launch"


@check("R5 commit resolution fails closed outside a work tree")
def r5(t: str) -> str:
    rp = os.path.join(t, "nogit.json")
    r = run([RECORDER, rp, "--cwd", t, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 1
    assert not os.path.exists(rp), "receipt written without a commit"
    commit = "d" * 40
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            t,
            "--commit",
            commit,
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    assert receipt["commit"] == commit
    assert receipt["worktree_clean"] is None
    r = run(
        [
            RECORDER,
            os.path.join(t, "bad.json"),
            "--cwd",
            t,
            "--commit",
            "nothex",
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )
    assert r.returncode == 1
    return "no HEAD and no --commit: no receipt; override recorded"


@check("R6 dirty worktree is recorded, not hidden")
def r6(t: str) -> str:
    repo = make_repo(t)
    with open(os.path.join(repo, "tracked.txt"), "a") as f:
        f.write("dirty\n")
    rp = os.path.join(t, "dirty.json")
    r = run([RECORDER, rp, "--cwd", repo, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    assert receipt["worktree_clean"] is False
    assert receipt["commit"] == git(repo, "rev-parse", "HEAD")
    return "worktree_clean false with uncommitted changes"


@check("R7 receipt framing is exact and timestamps parse")
def r7(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "framing.json")
    r = run([RECORDER, rp, "--cwd", repo, "--", sys.executable, "-c", "pass"])
    assert r.returncode == 0, r.stderr
    receipt, _raw = read_receipt(rp)
    assert set(receipt) == recorder.RECEIPT_FIELDS
    assert set(receipt["output"]) == recorder.OUTPUT_FIELDS
    from datetime import datetime

    started = datetime.fromisoformat(receipt["started"])
    ended = datetime.fromisoformat(receipt["ended"])
    assert started.tzinfo is not None and ended.tzinfo is not None
    assert ended >= started
    assert receipt["runtime_seconds"] >= 0
    assert receipt["output"]["path"] == "framing.json.log"
    stdout_receipt = json.loads(r.stdout)
    assert stdout_receipt == receipt, "stdout differs from published file"
    return "exact field set, UTC timestamps, stdout equals file"


@check(
    "R8 published log frozen: a background descendant's later write never changes it"
)
def r8(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "freeze.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--",
            "sh",
            "-c",
            "printf hello; (sleep 2; printf LATE-OUTPUT) &",
        ]
    )
    assert r.returncode == 0, r.stderr
    receipt, _ = read_receipt(rp)
    time.sleep(3)  # let the descendant's late write land (or be lost)
    with open(rp + ".log", "rb") as f:
        log = f.read()
    assert log == b"hello", f"published log changed after publish: {log!r}"
    assert receipt["output"]["sha256"] == recorder._sha256_file(rp + ".log")
    assert receipt["output"]["bytes"] == len(log)
    return "late background output absent from the published log; hash still matches"


@check("R9 timeout with a setsid-escaped writer: log frozen, exit 124")
def r9(t: str) -> str:
    import recorder

    repo = make_repo(t)
    rp = os.path.join(t, "freeze-timeout.json")
    r = run(
        [
            RECORDER,
            rp,
            "--cwd",
            repo,
            "--timeout",
            "1",
            "--",
            "sh",
            "-c",
            "setsid " + sys.executable + ' -c "import time; time.sleep(2); print(42)"'
            " & sleep 30",
        ]
    )
    assert r.returncode == 124, r.stderr
    receipt, _ = read_receipt(rp)
    assert receipt["timed_out"] is True
    time.sleep(3)  # past the escaped writer's 2s write
    with open(rp + ".log", "rb") as f:
        log = f.read()
    assert b"42" not in log, "escaped writer's output reached the published log"
    assert receipt["output"]["sha256"] == recorder._sha256_file(rp + ".log")
    return "escaped writer's post-kill output not captured; hash still matches"


@check("R10 runaway writer after child exit: bounded snapshot, recorder terminates")
def r10(t: str) -> str:
    import recorder

    repo = make_repo(t)
    writer = os.path.join(t, "flood-writer.py")
    with open(writer, "w") as f:
        f.write(
            "import os, time\n"
            "t0 = time.monotonic()\n"
            "while time.monotonic() - t0 < 10:\n"
            "    os.write(1, b'x' * 1048576)\n"
        )
    launcher = os.path.join(t, "flood-launcher.py")
    with open(launcher, "w") as f:
        f.write(
            "import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, {writer!r}], stdout=1)\n"
            "time.sleep(0.5)  # let the flood get underway before exiting\n"
        )
    rp = os.path.join(t, "runaway.json")
    proc = subprocess.Popen(
        [sys.executable, RECORDER, rp, "--cwd", repo, "--", sys.executable, launcher],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    t0 = time.monotonic()
    try:
        proc.communicate(timeout=8)
    except subprocess.TimeoutExpired as e:
        proc.kill()
        proc.communicate()
        raise AssertionError(
            "recorder did not terminate within 8s (unbounded read of a growing log)"
        ) from e
    dt = time.monotonic() - t0
    assert proc.returncode == 0, proc.stderr
    receipt, _ = read_receipt(rp)
    size = os.path.getsize(rp + ".log")
    assert receipt["output"]["sha256"] == recorder._sha256_file(rp + ".log")
    assert receipt["output"]["bytes"] == size
    os.unlink(rp)
    os.unlink(rp + ".log")  # large snapshot; do not litter it
    return f"terminated in {dt:.1f}s with a bounded {size}-byte snapshot; hash matches"


SKIP_ENV = "RECORDER_CHECKS_SKIP"
SKIPPABLE = "R10"  # the one check CI excludes; every other check must run


def main() -> int:
    raw = os.environ.get(SKIP_ENV)
    if raw is not None and raw.strip() != SKIPPABLE:
        print(
            f"REFUSED: {SKIP_ENV} accepts only {SKIPPABLE!r}; got {raw!r}. "
            "Every other check must run.",
            file=sys.stderr,
        )
        return 2
    skip = raw is not None
    failures = 0
    skipped = 0
    for name, fn in CHECKS:
        if skip and name.startswith(SKIPPABLE + " "):
            skipped += 1
            print(f"SKIP {name}: skipped by {SKIP_ENV}; no qualification claimed")
            continue
        t = tempfile.mkdtemp(prefix="recorder-check-")
        try:
            detail = fn(t)
            print(f"PASS {name}: {detail}")
        except Exception as e:
            failures += 1
            print(f"FAIL {name}: {e}")
    print(f"{len(CHECKS)} checks, {failures} failures, {skipped} skipped")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
