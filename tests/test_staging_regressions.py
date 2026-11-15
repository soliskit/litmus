"""Focused regressions for sweep inspection and the staging-name lock window.

Run from the repository root:
    python3 -m unittest discover -s tests -p test_staging_regressions.py

Linux directory flock and an unprivileged account are required. These are
controlled scheduling tests, not a measurement of ordinary race frequency.
"""

import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import packager


class StagingRegressions(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("unprivileged account required")
        self.temp = tempfile.TemporaryDirectory(prefix="litmus-regression-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_unreadable_entry_does_not_erase_earlier_or_later_results(self) -> None:
        for name in (".staging-a", ".staging-b", ".staging-c"):
            path = self.root / name
            path.mkdir()
            (path / "payload").write_bytes(name.encode())
        blocked = self.root / ".staging-b"
        before = blocked.stat()
        blocked.chmod(0)
        try:
            try:
                fd = os.open(blocked, os.O_RDONLY)
            except PermissionError as error:
                self.assertEqual(error.errno, errno.EACCES)
            else:
                os.close(fd)
                self.skipTest("account can bypass mode000 permissions")
            self.assertEqual(
                packager.recover_sweep(str(self.root)),
                ([".staging-a", ".staging-c"], [".staging-b"]),
            )
            after = blocked.stat()
            self.assertEqual(
                (before.st_dev, before.st_ino), (after.st_dev, after.st_ino)
            )
            self.assertEqual(stat.S_IMODE(after.st_mode), 0)
        finally:
            blocked.chmod(0o700)
        self.assertEqual((blocked / "payload").read_bytes(), b".staging-b")

    def test_staging_name_already_holds_lock_at_creation_hook(self) -> None:
        evidence, output = self.root / "evidence", self.root / "output"
        evidence.mkdir()
        output.mkdir()
        (evidence / "payload").write_bytes(b"evidence")
        witnesses: list[str] = []

        def pause(point: str, parent: str, name: str) -> None:
            if point != "after_staging_created":
                return
            staging = [p for p in output.iterdir() if p.name.startswith(".staging-")]
            self.assertEqual(len(staging), 1)
            target = staging[0]
            before = target.stat()
            fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    self.assertIn(error.errno, (errno.EAGAIN, errno.EACCES))
                else:
                    self.fail("staging name was visible before its producer lock")
            finally:
                os.close(fd)
            self.assertEqual(packager.recover_sweep(str(output)), ([], [target.name]))
            after = target.stat()
            self.assertEqual(
                (before.st_dev, before.st_ino), (after.st_dev, after.st_ino)
            )
            witnesses.append(target.name)

        with patch.object(packager, "_pause", pause):
            result = packager.pack(str(evidence), str(output), "bundle")
        self.assertEqual(len(witnesses), 1)
        self.assertEqual((output / "bundle" / "payload").read_bytes(), b"evidence")
        self.assertEqual(result["file_count"], 1)

    def test_reservations_are_reported_without_being_opened(self) -> None:
        reservation = self.root / ".reserve-protected"
        reservation.mkdir()
        (reservation / "payload").write_bytes(b"reservation")
        before = reservation.stat()
        original = os.open
        attempts: list[str] = []

        def observed(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if os.fspath(path) == str(reservation):
                attempts.append(os.fsdecode(path))
            return original(path, flags, mode, dir_fd=dir_fd)

        with patch.object(os, "open", observed):
            self.assertEqual(
                packager.recover_sweep(str(self.root)), ([], [reservation.name])
            )
        self.assertEqual(attempts, [])
        after = reservation.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual((reservation / "payload").read_bytes(), b"reservation")


if __name__ == "__main__":
    unittest.main()


def _load_recorder_checks() -> Any:
    spec = importlib.util.spec_from_file_location(
        "recorder_checks",
        Path(__file__).resolve().parent.parent / "recorder-checks.py",
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _stub_checks(rc: Any, ran: list[str], fail: set[str] | None = None) -> None:
    def make(label: str) -> Callable[[str], str]:
        def run(t: str) -> str:
            os.rmdir(t)
            ran.append(label)
            if fail and label in fail:
                raise RuntimeError(f"{label} stub failure")
            return "stub"

        return run

    rc.CHECKS[:] = [
        ("R1 stub one", make("R1")),
        ("R10 stub ten", make("R10")),
        ("R3 stub three", make("R3")),
    ]


class RecorderSkipRegressions(unittest.TestCase):
    """Pin RECORDER_CHECKS_SKIP, CI's R10-only exclusion mechanism."""

    def test_unknown_skip_name_refuses_the_run(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        err = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R1O"}):
            with contextlib.redirect_stderr(err):
                result = rc.main()
        self.assertEqual(result, 2)
        self.assertIn("REFUSED", err.getvalue())
        self.assertIn("R1O", err.getvalue())
        self.assertEqual(ran, [])

    def test_known_non_r10_skip_name_refuses_the_run(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        err = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R1"}):
            with contextlib.redirect_stderr(err):
                result = rc.main()
        self.assertEqual(result, 2)
        self.assertIn("REFUSED", err.getvalue())
        self.assertIn("R1", err.getvalue())
        self.assertEqual(ran, [])

    def test_r10_skip_excludes_only_r10_without_running_it(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        out = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R10"}):
            with contextlib.redirect_stdout(out):
                result = rc.main()
        self.assertEqual(result, 0)
        self.assertEqual(ran, ["R1", "R3"])
        self.assertIn(
            "SKIP R10 stub ten: skipped by RECORDER_CHECKS_SKIP", out.getvalue()
        )
        self.assertIn("no qualification claimed", out.getvalue())
        self.assertIn("3 checks, 0 failures, 1 skipped", out.getvalue())

    def test_unset_variable_runs_every_check_full_default(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran)
        out = io.StringIO()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RECORDER_CHECKS_SKIP", None)
            with contextlib.redirect_stdout(out):
                result = rc.main()
        self.assertEqual(result, 0)
        self.assertEqual(ran, ["R1", "R10", "R3"])
        self.assertIn("3 checks, 0 failures, 0 skipped", out.getvalue())

    def test_real_failures_propagate_with_r10_skipped(self) -> None:
        rc = _load_recorder_checks()
        ran: list[str] = []
        _stub_checks(rc, ran, fail={"R3"})
        out = io.StringIO()
        with patch.dict(os.environ, {"RECORDER_CHECKS_SKIP": "R10"}):
            with contextlib.redirect_stdout(out):
                result = rc.main()
        self.assertEqual(result, 1)
        self.assertEqual(ran, ["R1", "R3"])
        self.assertIn("FAIL R3 stub three: R3 stub failure", out.getvalue())
        self.assertIn("3 checks, 1 failures, 1 skipped", out.getvalue())


class PublishedPathRegressions(unittest.TestCase):
    """Only the exact published directory validates."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="litmus-regression-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        (self.evidence / "a.txt").write_bytes(b"alpha\n")

    def test_complete_staging_from_a_failed_publish_and_its_verdict_are_refused(
        self,
    ) -> None:
        import verifier

        output = self.root / "output"
        output.mkdir()
        (output / "bundle-x").symlink_to("/nonexistent-target")
        with self.assertRaises(FileExistsError):
            packager.pack(str(self.evidence), str(output), "bundle-x")
        staging = [p for p in output.iterdir() if p.name.startswith(".staging-")]
        self.assertEqual(len(staging), 1)
        self.assertTrue((staging[0] / "manifest.json").is_file())
        result = verifier.verify(str(staging[0]))
        self.assertEqual(result["verdict"], "INVALID")
        self.assertIn("not the declared bundle name", "; ".join(result["reasons"]))
        # A verdict as the unfixed verifier issued it for this staging.
        manifest = (staging[0] / "manifest.json").read_bytes()
        stored = verifier._verdict(
            "VALID",
            "bundle-x",
            str(staging[0]),
            hashlib.sha256(manifest).hexdigest(),
            [],
        )
        verdict_path = self.root / "verdict.json"
        verdict_path.write_text(json.dumps(stored))
        accepted, reasons = verifier.check_verdict(str(staging[0]), str(verdict_path))
        self.assertFalse(accepted)
        self.assertIn("bundle no longer validates", "; ".join(reasons))

    def test_the_published_bundle_still_validates_and_its_verdict_is_accepted(
        self,
    ) -> None:
        import verifier

        output = self.root / "output"
        output.mkdir()
        packager.pack(str(self.evidence), str(output), "bundle-x")
        published = str(output / "bundle-x")
        result = verifier.verify(published)
        self.assertEqual(result["verdict"], "VALID", result["reasons"])
        verdict_path = self.root / "verdict.json"
        verdict_path.write_text(json.dumps(result))
        self.assertEqual(
            verifier.check_verdict(published, str(verdict_path)), (True, [])
        )
