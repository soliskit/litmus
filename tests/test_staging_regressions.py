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
import signal
import stat
import subprocess
import sys
import tempfile
import time
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

    def test_complete_staging_from_a_crash_and_its_verdict_are_refused(
        self,
    ) -> None:
        import verifier

        output = self.root / "output"
        output.mkdir()
        proc = subprocess.Popen(
            [
                sys.executable,
                packager.__file__,
                str(self.evidence),
                str(output),
                "bundle-x",
            ],
            env=dict(os.environ, C1C2_PAUSE_AT="after_manifest"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            ready = output / ".sync-bundle-x-after_manifest.ready"
            deadline = time.monotonic() + 30
            while not ready.exists():
                self.assertIsNone(
                    proc.poll(), "producer exited before complete staging"
                )
                self.assertLess(time.monotonic(), deadline, "producer pause timed out")
                time.sleep(0.02)
            proc.kill()
            proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, -signal.SIGKILL)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=30)
        self.assertFalse((output / "bundle-x").exists())
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


class OwnStagingRegressions(unittest.TestCase):
    """Synthetic per-attempt faults; real crash/write-error witnesses stay separate."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="litmus-own-stage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.output = self.root / "output"
        self.evidence.mkdir()
        self.output.mkdir()
        (self.evidence / "payload").write_bytes(b"source")
        self.original = OSError(errno.EIO, "original write failure")

    def pack(self) -> dict[str, object]:
        return packager.pack(str(self.evidence), str(self.output), "bundle")

    def stage(self) -> Path:
        paths = list(self.output.glob(".staging-*"))
        self.assertEqual(len(paths), 1)
        return paths[0]

    def test_invalid_input_allocates_nothing(self) -> None:
        (self.evidence / "manifest.json").write_text("reserved")
        with patch.object(
            packager, "_locked_staging", wraps=packager._locked_staging
        ) as allocation:
            with self.assertRaisesRegex(ValueError, "reserved name"):
                self.pack()
        allocation.assert_not_called()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_normal_failure_removes_only_own_stage_under_lock(self) -> None:
        for name in (".staging-other", ".reserve-other", "unrelated"):
            directory = self.output / name
            directory.mkdir()
            (directory / "payload").write_bytes(b"keep")
        real_remove = __import__("shutil").rmtree
        other_fd = os.open(self.output / ".staging-other", os.O_RDONLY)
        self.addCleanup(os.close, other_fd)
        fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        witnessed: list[str] = []

        def remove(path: str) -> None:
            fd = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            witnessed.append(path)
            real_remove(path)

        with (
            patch.object(packager, "_write_sync", side_effect=self.original),
            patch("shutil.rmtree", side_effect=remove),
        ):
            with self.assertRaises(OSError) as caught:
                self.pack()
        self.assertIs(caught.exception, self.original)
        self.assertEqual(len(witnessed), 1)
        for name in (".staging-other", ".reserve-other", "unrelated"):
            self.assertEqual((self.output / name / "payload").read_bytes(), b"keep")
        self.assertEqual((self.evidence / "payload").read_bytes(), b"source")
        self.assertEqual(len(list(self.output.iterdir())), 3)

    def test_partial_cleanup_failure_keeps_original_data_mode_and_reason(self) -> None:
        errors = io.StringIO()
        remaining: list[Path] = []

        def write(path: str, data: bytes) -> None:
            stage = Path(path).parent
            (stage / "removed").write_bytes(b"partial")
            (stage / "remaining").write_bytes(b"keep")
            stage.chmod(0o700)
            raise self.original

        def partial(path: str) -> None:
            stage = Path(path)
            (stage / "removed").unlink()
            remaining.append(stage)
            raise PermissionError(errno.EACCES, "controlled removal obstacle")

        with (
            patch.object(packager, "_write_sync", side_effect=write),
            patch("shutil.rmtree", side_effect=partial),
            contextlib.redirect_stderr(errors),
        ):
            with self.assertRaises(OSError) as caught:
                self.pack()
        self.assertIs(caught.exception, self.original)
        self.assertEqual((remaining[0] / "remaining").read_bytes(), b"keep")
        self.assertFalse((remaining[0] / "removed").exists())
        self.assertEqual(stat.S_IMODE(remaining[0].stat().st_mode), 0o700)
        self.assertIn("files may remain", errors.getvalue())
        self.assertIn("controlled removal obstacle", errors.getvalue())

    def test_cleanup_diagnostic_and_close_errors_do_not_replace_original(self) -> None:
        original_close = os.close

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("controlled close failure")

        def fail_write(path: str, data: bytes) -> None:
            # Allocation is complete, so this fault affects only final lock close.
            os.close = close
            raise self.original

        try:
            with (
                patch.object(packager, "_write_sync", side_effect=fail_write),
                patch("shutil.rmtree", side_effect=OSError("cleanup failure")),
                patch("builtins.print", side_effect=OSError("diagnostic failure")),
            ):
                with self.assertRaises(OSError) as caught:
                    self.pack()
            self.assertIs(caught.exception, self.original)
        finally:
            os.close = original_close

    def test_identity_change_or_symlink_refuses_cleanup(self) -> None:
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                moved: list[Path] = []

                def replace(
                    path: str,
                    data: bytes,
                    symlink: bool = symlink,
                    moved: list[Path] = moved,
                ) -> None:
                    stage = self.stage()
                    saved = self.root / ("held-link" if symlink else "held-dir")
                    stage.rename(saved)
                    moved.append(saved)
                    if symlink:
                        stage.symlink_to(saved, target_is_directory=True)
                    else:
                        stage.mkdir()
                        (stage / "replacement").write_bytes(b"keep")
                    raise self.original

                with (
                    patch.object(packager, "_write_sync", side_effect=replace),
                    patch("shutil.rmtree") as remove,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(OSError) as caught:
                        self.pack()
                self.assertIs(caught.exception, self.original)
                remove.assert_not_called()
                stage = self.stage()
                if symlink:
                    self.assertTrue(stage.is_symlink())
                    stage.unlink()
                else:
                    self.assertEqual((stage / "replacement").read_bytes(), b"keep")
                    (stage / "replacement").unlink()
                    stage.rmdir()
                moved[0].rmdir()

    def test_interrupt_and_system_exit_do_not_attempt_removal(self) -> None:
        for exception in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(exception=type(exception).__name__):
                with (
                    patch.object(packager, "_write_sync", side_effect=exception),
                    patch("shutil.rmtree") as remove,
                ):
                    with self.assertRaises(type(exception)):
                        self.pack()
                remove.assert_not_called()
                self.stage().rmdir()

    def test_success_and_postpublish_close_error_never_remove_published(self) -> None:
        self.pack()
        self.assertEqual((self.output / "bundle" / "payload").read_bytes(), b"source")
        original_close = os.close
        original_rename = packager._rename_noreplace
        changed = False

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("postpublish close failure")

        def rename(src: str, dst: str) -> None:
            nonlocal changed
            original_rename(src, dst)
            os.close = close
            changed = True

        try:
            with (
                patch.object(packager, "_rename_noreplace", side_effect=rename),
                patch("shutil.rmtree") as remove,
            ):
                with self.assertRaisesRegex(OSError, "postpublish close failure"):
                    packager.pack(str(self.evidence), str(self.output), "bundle-two")
            self.assertTrue(changed)
            remove.assert_not_called()
            self.assertEqual(
                (self.output / "bundle-two" / "payload").read_bytes(), b"source"
            )
        finally:
            os.close = original_close

    def test_inspection_refusal_and_allocation_failure_do_not_remove(self) -> None:
        with (
            patch.object(
                packager, "_locked_staging", side_effect=OSError("allocation failure")
            ),
            patch("shutil.rmtree") as remove,
        ):
            with self.assertRaisesRegex(OSError, "allocation failure"):
                self.pack()
        remove.assert_not_called()
        original_fstat = os.fstat

        def write(path: str, data: bytes) -> None:
            os.fstat = lambda fd: (_ for _ in ()).throw(OSError("inspection failure"))
            raise self.original

        try:
            with (
                patch.object(packager, "_write_sync", side_effect=write),
                patch("shutil.rmtree") as remove,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(OSError) as caught:
                    self.pack()
            self.assertIs(caught.exception, self.original)
            remove.assert_not_called()
            self.assertTrue(self.stage().is_dir())
        finally:
            os.fstat = original_fstat

    def test_postpublish_fsync_warning_and_manual_result_unchanged(self) -> None:
        original = packager._fsync_dir

        def fsync(path: str) -> None:
            if path == str(self.output):
                raise OSError("postpublish fsync failure")
            original(path)

        with (
            patch.object(packager, "_fsync_dir", side_effect=fsync),
            patch("shutil.rmtree") as remove,
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            result = self.pack()
        remove.assert_not_called()
        self.assertEqual(result["bundle"], "bundle")
        self.assertEqual((self.output / "bundle" / "payload").read_bytes(), b"source")
        self.assertIn("post-publish fsync failed", errors.getvalue())
        (self.output / ".staging-residue").mkdir()
        (self.output / ".reserve-protected").mkdir()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = packager.main(["packager.py", "--recover-sweep", str(self.output)])
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "recovered_staging": [".staging-residue"],
                "skipped_staging": [".reserve-protected"],
            },
        )
        self.assertIn("protected reservation", stderr.getvalue())

    def test_unprintable_cleanup_and_close_errors_keep_original(self) -> None:
        class UnprintableError(Exception):
            def __str__(self) -> str:
                raise RuntimeError("controlled formatting failure")

        original_close = os.close

        def close(fd: int) -> None:
            original_close(fd)
            raise UnprintableError()

        def write(path: str, data: bytes) -> None:
            os.close = close
            raise self.original

        try:
            with (
                patch.object(packager, "_write_sync", side_effect=write),
                patch("shutil.rmtree", side_effect=UnprintableError()),
            ):
                with self.assertRaises(OSError) as caught:
                    self.pack()
            self.assertIs(caught.exception, self.original)
        finally:
            os.close = original_close

    def test_callers_active_exception_does_not_hide_postpublish_close_error(
        self,
    ) -> None:
        original_close = os.close
        original_rename = packager._rename_noreplace

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("postpublish close failure")

        def rename(src: str, dst: str) -> None:
            original_rename(src, dst)
            os.close = close

        try:
            try:
                raise ValueError("caller's handled exception")
            except ValueError:
                with (
                    patch.object(packager, "_rename_noreplace", side_effect=rename),
                    patch("shutil.rmtree") as remove,
                ):
                    with self.assertRaisesRegex(OSError, "postpublish close failure"):
                        self.pack()
                remove.assert_not_called()
                self.assertEqual(
                    (self.output / "bundle" / "payload").read_bytes(), b"source"
                )
        finally:
            os.close = original_close

    def test_interrupts_win_over_secondary_close_error_without_cleanup(self) -> None:
        original_close = os.close

        def close(fd: int) -> None:
            original_close(fd)
            raise OSError("secondary close failure")

        for exception in (KeyboardInterrupt(), SystemExit(3)):

            def write(
                path: str, data: bytes, exception: BaseException = exception
            ) -> None:
                os.close = close
                raise exception

            try:
                with (
                    patch.object(packager, "_write_sync", side_effect=write),
                    patch("shutil.rmtree") as remove,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(type(exception)) as caught:
                        self.pack()
                self.assertIs(caught.exception, exception)
                remove.assert_not_called()
                self.stage().rmdir()
            finally:
                os.close = original_close
