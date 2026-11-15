#!/usr/bin/env python3
"""Qualification checks for the packager/verifier.

Real mechanisms only: kills are real SIGKILLs of a real subprocess, the
write error is a real OS error (staging made read-only mid-run), the
cross-filesystem case uses a real second filesystem. Each check returns a
detail string; the driver prints one line per check and exits nonzero if
any fail. This gate qualifies the packager/verifier behavior ONLY; it
certifies nothing about any other system, suite, or property.
"""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGER = os.path.join(HERE, "packager.py")
VERIFIER = os.path.join(HERE, "verifier.py")
sys.path.insert(0, HERE)

SECOND_FS = (
    "/dev/shm"
    if (
        os.path.isdir("/dev/shm")
        and os.stat("/dev/shm").st_dev != os.stat(tempfile.gettempdir()).st_dev
    )
    else None
)


def source_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for f in ("packager.py", "verifier.py", "checks.py"):
        with open(os.path.join(HERE, f), "rb") as fh:
            pins[f] = hashlib.sha256(fh.read()).hexdigest()
    return pins


def run(
    cmd: list[str], env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, *cmd], capture_output=True, text=True, env=env
    )


def launch_paused(out_parent: str, name: str, point: str) -> subprocess.Popen[str]:
    """Start the packager paused at a point; return (proc, ready_file)."""
    env = dict(os.environ, C1C2_PAUSE_AT=point)
    proc = subprocess.Popen(
        [
            sys.executable,
            PACKAGER,
            os.path.join(out_parent, "evidence"),
            out_parent,
            name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    ready = os.path.join(out_parent, f".sync-{name}-{point}.ready")
    deadline = time.time() + 30
    while not os.path.exists(ready):
        if proc.poll() is not None:
            raise AssertionError(f"packager exited before pause point {point}")
        if time.time() > deadline:
            proc.kill()
            raise AssertionError(f"timeout waiting for pause point {point}")
        time.sleep(0.02)
    return proc


def resume(out_parent: str, name: str) -> None:
    open(os.path.join(out_parent, f".sync-{name}.resume"), "w").close()


def make_evidence(root: str, n: int = 6) -> str:
    ed = os.path.join(root, "evidence")
    os.makedirs(ed)
    for i in range(n):
        with open(os.path.join(ed, f"evidence-{i}.log"), "w") as f:
            f.write(f"fixture evidence leg {i}\n")
    os.makedirs(os.path.join(ed, "sub"))
    with open(os.path.join(ed, "sub", "summary.txt"), "w") as f:
        f.write("fixture summary\n")
    return ed


def check(name: str) -> Callable[[Callable[[str], str]], Callable[[str], str]]:
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        CHECKS.append((name, fn))
        return fn

    return deco


CHECKS: list[tuple[str, Callable[[str], str]]] = []


@check("F1 pack publishes complete bundle; producer output has no verdict")
def f1(t: str) -> str:
    make_evidence(t)
    r = run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-f1"])
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert "verdict" not in out, "producer emitted a verdict"
    v = run([VERIFIER, os.path.join(t, "bundle-f1")])
    assert v.returncode == 0, v.stdout
    return f"pack ok, producer fields: {sorted(out)}"


@check("F2 verdict VALID, bound to bundle identity and manifest sha256")
def f2(t: str) -> str:
    make_evidence(t)
    run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-f2"])
    bp = os.path.join(t, "bundle-f2")
    v = json.loads(run([VERIFIER, bp]).stdout)
    mb = open(os.path.join(bp, "manifest.json"), "rb").read()
    assert v["verdict"] == "VALID"
    assert v["manifest_sha256"] == hashlib.sha256(mb).hexdigest()
    assert v["bundle"] == "bundle-f2"
    assert v["bundle_path"] == os.path.abspath(bp)
    return "verdict binds name, path and manifest sha256"


@check("F3 republish over an existing bundle is refused, no overwrite")
def f3(t: str) -> str:
    make_evidence(t)
    run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-f3"])
    marker = os.path.join(t, "bundle-f3", "evidence-0.log")
    before = open(marker).read()
    r = run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-f3"])
    assert r.returncode == 1
    assert open(marker).read() == before
    return "refused, existing bundle untouched"


@check("F4 no-overwrite race: EMPTY target appearing mid-run is never replaced")
def f4(t: str) -> str:
    make_evidence(t)
    # Control: plain os.rename DOES replace an empty directory, so this
    # test distinguishes NOREPLACE from a plain rename.
    ctl_src = os.path.join(t, "ctl-src")
    ctl_dst = os.path.join(t, "ctl-dst")
    os.mkdir(ctl_src)
    os.mkdir(ctl_dst)
    os.rename(ctl_src, ctl_dst)
    assert os.path.isdir(ctl_dst) and not os.path.exists(ctl_src)
    os.rmdir(ctl_dst)
    # Real race: an EMPTY competitor directory appears before publish.
    proc = launch_paused(t, "bundle-f4", "after_manifest")
    target = os.path.join(t, "bundle-f4")
    os.mkdir(target)
    resume(t, "bundle-f4")
    out, err = proc.communicate(timeout=30)
    assert proc.returncode == 1, (proc.returncode, out, err)
    assert "File exists" in err or "EEXIST" in err, err
    assert os.path.isdir(target) and os.listdir(target) == [], (
        "empty competitor was replaced or merged"
    )
    import platform as _p

    assert _p.system() == "Linux" and _p.machine() == "x86_64"
    return (
        "demonstrated for an empty target appearing mid-run: control "
        "plain rename replaced an empty dir, packager refused with "
        f"EEXIST at publish path {target}; the full no-overwrite race "
        "guarantee rests on renameat2 NOREPLACE syscall semantics, "
        "not on this empirical window"
    )


@check("C1-a real SIGKILL mid-stage: no publish, no verdict, residue rejected")
def c1a(t: str) -> str:
    make_evidence(t)
    proc = launch_paused(t, "bundle-c1a", "mid_copy")
    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=30)
    assert proc.returncode == -signal.SIGKILL, proc.returncode
    assert not os.path.exists(os.path.join(t, "bundle-c1a"))
    v = run([VERIFIER, os.path.join(t, "bundle-c1a")])
    assert v.returncode == 1
    residue = [f for f in os.listdir(t) if f.startswith(".staging-")]
    if residue:
        v2 = run([VERIFIER, os.path.join(t, residue[0])])
        assert v2.returncode == 1, "staging residue verified as a bundle"
    return f"real SIGKILL (rc=-9); no publish; residue present={bool(residue)} rejected"


@check("C1-b real OS write error: nothing published, nonzero exit, no verdict")
def c1b(t: str) -> str:
    make_evidence(t)
    proc = launch_paused(t, "bundle-c1b", "after_staging_created")
    staging = [f for f in os.listdir(t) if f.startswith(".staging-")]
    assert len(staging) == 1
    sp = os.path.join(t, staging[0])
    os.chmod(sp, 0o555)  # read-only: the copy gets a real OS write error
    resume(t, "bundle-c1b")
    out, err = proc.communicate(timeout=30)
    os.chmod(sp, 0o755)
    assert proc.returncode == 1, (proc.returncode, out, err)
    assert "Permission denied" in err or "Errno 13" in err, (
        f"expected a real EACCES from the OS, got: {err}"
    )
    assert not os.path.exists(os.path.join(t, "bundle-c1b"))
    assert "verdict" not in out
    return (
        "real OS write error asserted (EACCES on read-only staging); "
        "abandoned before publish"
    )


@check(
    "C1-c real SIGKILL at every point: nothing partial before rename; complete after"
)
def c1c(t: str) -> str:
    make_evidence(t)
    for i, point in enumerate(["after_staging_created", "mid_copy", "after_manifest"]):
        name = f"bundle-c1c-{i}"
        proc = launch_paused(t, name, point)
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=30)
        assert not os.path.exists(os.path.join(t, name)), point
    proc = launch_paused(t, "bundle-c1c-post", "after_publish")
    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=30)
    v = run([VERIFIER, os.path.join(t, "bundle-c1c-post")])
    assert v.returncode == 0, "post-publish bundle must be complete+valid"
    return (
        "real SIGKILLs; pre-rename: nothing published; post-rename: "
        "complete valid bundle (stated)"
    )


@check("C1-d path abuse names rejected before staging")
def c1d(t: str) -> str:
    make_evidence(t)
    for bad in [".", "..", "", "a/b", ".staging-x", " ", "../x"]:
        r = run([PACKAGER, os.path.join(t, "evidence"), t, bad])
        assert r.returncode == 1, repr(bad)
    assert not [f for f in os.listdir(t) if f.startswith(".staging-")]
    return "7 abusive names rejected, no staging created"


@check("C1-e cross-filesystem staging rejected on a real second filesystem")
def c1e(t: str) -> str:
    import packager

    make_evidence(t)
    if SECOND_FS is None:
        raise AssertionError("no second filesystem in this environment")
    try:
        packager.pack(
            os.path.join(t, "evidence"), t, "bundle-c1e", staging_parent=SECOND_FS
        )
        raise AssertionError("cross-fs staging accepted")
    except ValueError as e:
        assert "cross-filesystem" in str(e)
    assert not os.path.exists(os.path.join(t, "bundle-c1e"))
    leftover = [
        f for f in os.listdir(SECOND_FS) if f.startswith(".staging-bundle-c1e-")
    ]
    for f in leftover:
        shutil.rmtree(os.path.join(SECOND_FS, f), ignore_errors=True)
    return (
        f"real cross-device attempt ({SECOND_FS} vs /tmp) rejected before any "
        "evidence CONTENT write; the empty staging dir on the wrong "
        "device was created, refused, and removed"
    )


@check("C1-f consumer fail-closed: absent/missing/incomplete/mismatch/unknown-framing")
def c1f(t: str) -> str:
    import verifier

    make_evidence(t)
    run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-c1f"])
    bp = os.path.join(t, "bundle-c1f")
    cases: list[tuple[str, bool]] = []
    cases.append(
        (
            "absent",
            verifier.verify(os.path.join(t, "no-such-bundle"))["verdict"] == "INVALID",
        )
    )
    t2 = os.path.join(t, "c1f-missing")
    shutil.copytree(bp, t2)
    os.remove(os.path.join(t2, "manifest.json"))
    cases.append(("missing-manifest", verifier.verify(t2)["verdict"] == "INVALID"))
    t3 = os.path.join(t, "c1f-incomplete")
    shutil.copytree(bp, t3)
    os.remove(os.path.join(t3, "evidence-0.log"))
    cases.append(("incomplete", verifier.verify(t3)["verdict"] == "INVALID"))
    t4 = os.path.join(t, "c1f-mismatch")
    shutil.copytree(bp, t4)
    with open(os.path.join(t4, "evidence-1.log"), "a") as f:
        f.write("tampered\n")
    cases.append(("hash-mismatch", verifier.verify(t4)["verdict"] == "INVALID"))
    t5 = os.path.join(t, "c1f-framing")
    shutil.copytree(bp, t5)
    mp = os.path.join(t5, "manifest.json")
    m = json.load(open(mp))
    m["verdict"] = "VALID"
    json.dump(m, open(mp, "w"))
    cases.append(("unknown-framing", verifier.verify(t5)["verdict"] == "INVALID"))
    failed = [n for n, ok in cases if not ok]
    assert not failed, failed
    return "5 classes all INVALID"


@check(
    "C1-g stale/foreign/moved/repacked verdict rejected against current bytes"
    " and identity"
)
def c1g(t: str) -> str:
    import verifier

    make_evidence(t)
    run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-c1g"])
    bp = os.path.join(t, "bundle-c1g")
    vp = os.path.join(t, "verdict.json")
    good = run([VERIFIER, bp])
    assert good.returncode == 0
    open(vp, "w").write(good.stdout)
    ok, reasons = verifier.check_verdict(bp, vp)
    assert ok, reasons  # fresh verdict for unchanged bundle is accepted

    def decided_by(field: str, path: str) -> None:
        # The bundle validates and every other bound field matches, so only
        # this field's binding can reject the stored verdict.
        assert verifier.verify(path)["verdict"] == "VALID"
        ok, reasons = verifier.check_verdict(path, vp)
        assert not ok, f"verdict accepted with only {field} differing"
        assert len(reasons) == 1 and reasons[0].startswith(f"{field} mismatch"), reasons

    # moved: the unchanged bundle, same name, another directory
    moved = os.path.join(t, "elsewhere", "bundle-c1g")
    os.makedirs(os.path.dirname(moved))
    os.rename(bp, moved)
    decided_by("bundle_path", moved)
    os.rename(moved, bp)
    # changed: a same-name repack at the same path with different evidence
    shutil.rmtree(bp)
    changed = make_evidence(os.path.join(t, "changed"))
    with open(os.path.join(changed, "added.log"), "w") as f:
        f.write("evidence the verdict never saw\n")
    r = run([PACKAGER, changed, t, "bundle-c1g"])
    assert r.returncode == 0, r.stderr
    decided_by("manifest_sha256", bp)
    # evidence changed while the manifest is untouched: hash mismatch AND
    # the stored verdict is now stale
    with open(os.path.join(bp, "evidence-2.log"), "a") as f:
        f.write("changed after verdict\n")
    assert verifier.verify(bp)["verdict"] == "INVALID"
    ok, reasons = verifier.check_verdict(bp, vp)
    assert not ok, "stale verdict accepted after evidence changed"
    # moved/renamed bundle: identity no longer matches the verdict
    shutil.rmtree(bp)
    run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-c1g-b"])
    bp2 = os.path.join(t, "bundle-c1g-b")
    ok, reasons = verifier.check_verdict(bp2, vp)
    assert not ok, "foreign verdict accepted for a different bundle"
    return (
        "fresh verdict accepted; a moved bundle rejected by the path binding "
        "alone and a same-name repack by the manifest-hash binding alone; "
        "stale (changed evidence) and foreign (different bundle) verdicts "
        "rejected"
    )


@check("C1-h evidence file named manifest.json rejected (input collision)")
def c1h(t: str) -> str:
    ed = make_evidence(t)
    with open(os.path.join(ed, "manifest.json"), "w") as f:
        f.write('{"verdict": "VALID"}\n')
    r = run([PACKAGER, ed, t, "bundle-c1h"])
    assert r.returncode == 1
    assert not os.path.exists(os.path.join(t, "bundle-c1h"))
    return "reserved-name input refused before staging"


@check("C2-a fixture legs carry evidence fields only; no verdict field exists")
def c2a(t: str) -> str:
    make_evidence(t)
    r = run([PACKAGER, os.path.join(t, "evidence"), t, "bundle-c2a"])
    out = json.loads(r.stdout)
    assert set(out) == {"bundle", "published", "manifest_sha256", "file_count"}
    m = json.load(open(os.path.join(t, "bundle-c2a", "manifest.json")))
    assert "verdict" not in m
    for entry in m["files"].values():
        assert set(entry) == {"sha256", "size"}
    return "producer schema has no verdict field anywhere"


@check(
    "C3-a sweep skips live staging: a sweep during a pack publishes a complete bundle"
)
def c3a(t: str) -> str:
    import verifier

    make_evidence(t)
    proc = launch_paused(t, "bundle-c3a", "after_manifest")
    try:
        r = run([PACKAGER, "--recover-sweep", t])
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        removed = out.get("recovered_staging", [])
        skipped = out.get("skipped_staging", [])
        assert any(fn.startswith(".staging-bundle-c3a-") for fn in skipped), out
        assert not any(fn.startswith(".staging-bundle-c3a-") for fn in removed), out
        resume(t, "bundle-c3a")
        _pout, perr = proc.communicate(timeout=60)
        assert proc.returncode == 0, perr
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    bp = os.path.join(t, "bundle-c3a")
    v = verifier.verify(bp)
    assert v["verdict"] == "VALID", v
    n = sum(len(files) for _, _, files in os.walk(bp))
    assert n == 8, f"bundle incomplete after sweep during pack: {n} files"
    return (
        "sweep skipped the locked live staging; the pack published a "
        "complete VALID bundle (7 evidence files + manifest)"
    )


@check(
    "C3-b sweep reports truthfully: symlinked staging skipped, not removed, not claimed"
)
def c3b(t: str) -> str:
    os.makedirs(os.path.join(t, "real-target"))
    link = os.path.join(t, ".staging-evil")
    os.symlink(os.path.join(t, "real-target"), link)
    r = run([PACKAGER, "--recover-sweep", t])
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert ".staging-evil" not in out.get("recovered_staging", []), out
    assert ".staging-evil" in out.get("skipped_staging", []), out
    assert os.path.islink(link), "symlinked staging was removed"
    return "symlinked staging skipped and reported skipped; left in place"


@check("C3-c sweep on a missing OUT_PARENT refuses cleanly")
def c3c(t: str) -> str:
    r = run([PACKAGER, "--recover-sweep", os.path.join(t, "nonexistent")])
    assert r.returncode == 1, r
    assert "Traceback" not in r.stderr, r.stderr
    err = json.loads(r.stderr)
    assert "error" in err
    return "clean JSON error, exit 1: {}".format(err["error"])


def main() -> int:
    pins = source_pins()
    print("source pins (bytes under test):")
    for f, h in sorted(pins.items()):
        print(f"  sha256 {h}  {f}")
    print("---")
    failures: list[str] = []
    for name, fn in CHECKS:
        t = tempfile.mkdtemp(prefix="c1c2-check-")
        try:
            detail = fn(t)
            print(f"PASS {name} -- {detail}")
        except Exception as e:
            failures.append(name)
            print(f"FAIL {name} -- {e}")
        finally:
            shutil.rmtree(t, ignore_errors=True)
    print("---")
    print(
        f"checks {len(CHECKS)}, pass {len(CHECKS) - len(failures)}, "
        f"fail {len(failures)}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
