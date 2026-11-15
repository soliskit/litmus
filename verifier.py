#!/usr/bin/env python3
"""Evidence bundle verifier (owner-side qualification tooling).

The verifier is the only component that emits a verdict. A verdict exists
only after complete validation of the exact bundle it names. It binds the
manifest-DECLARED bundle name, the bundle's absolute path and the
bundle's manifest sha256, so a verdict for an absent, moved, renamed or
changed bundle is invalid on its face (source binding, stale-verdict
avoidance). The name binding is to the name declared inside the manifest;
the path binding is to the directory the verdict was issued for.

--check-verdict re-validates an existing verdict file against the current
bytes of the bundle it claims to cover: the verdict is accepted only when
the bundle still validates AND every bound field matches. Anything else is
a stale or foreign verdict and is rejected. The path/name binding detects
a moved, renamed or swapped bundle against a stored verdict; it is not a
signature and proves nothing about who produced the verdict.

Fail-closed: absent path, missing/incomplete manifest, hash or size
mismatch, unexpected extra files, or unknown manifest framing all produce
INVALID. Never emits a verdict for a bundle it could not fully read.

Python 3 standard library only.
"""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import TypedDict

MANIFEST_VERSION = 1
MANIFEST_FIELDS = {"version", "bundle", "created", "files"}
VERDICT_FIELDS = {
    "verdict",
    "bundle",
    "bundle_path",
    "manifest_sha256",
    "run_id",
    "checked_at",
    "reasons",
}


class Verdict(TypedDict):
    verdict: str
    bundle: str | None
    bundle_path: str
    manifest_sha256: str | None
    run_id: str
    checked_at: str
    reasons: list[str]


def verify(bundle_path: str) -> Verdict:
    reasons: list[str] = []
    manifest_sha256: str | None = None
    bundle_name: str | None = None

    if not os.path.isdir(bundle_path):
        reasons.append("bundle path absent or not a directory")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    manifest_path = os.path.join(bundle_path, "manifest.json")
    if not os.path.isfile(manifest_path):
        reasons.append("manifest.json missing")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    try:
        with open(manifest_path, "rb") as f:
            manifest_bytes = f.read()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as e:
        reasons.append(f"manifest unreadable: {e}")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    if not isinstance(manifest, dict):
        reasons.append("manifest is not an object")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)
    unknown = set(manifest) - MANIFEST_FIELDS
    if unknown:
        reasons.append(f"unknown manifest framing fields: {sorted(unknown)}")
    missing = MANIFEST_FIELDS - set(manifest)
    if missing:
        reasons.append(f"manifest missing fields: {sorted(missing)}")
    if manifest.get("version") != MANIFEST_VERSION:
        reasons.append(
            "unsupported manifest version: {!r}".format(manifest.get("version"))
        )
    if isinstance(manifest.get("bundle"), str):
        bundle_name = manifest["bundle"]
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        reasons.append("manifest files map missing or empty")
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)
    if reasons:
        return _verdict("INVALID", bundle_name, bundle_path, manifest_sha256, reasons)

    listed = set(files)
    on_disk = set()
    for root, dirs, fns in os.walk(bundle_path):
        dirs.sort()
        for fn in sorted(fns):
            rel = os.path.relpath(os.path.join(root, fn), bundle_path)
            if rel == "manifest.json":
                continue
            on_disk.add(rel)

    for rel in sorted(listed - on_disk):
        reasons.append(f"listed file absent: {rel}")
    for rel in sorted(on_disk - listed):
        reasons.append(f"unexpected file not in manifest: {rel}")

    for rel in sorted(listed & on_disk):
        ap = os.path.join(bundle_path, rel)
        entry = files[rel]
        if os.path.islink(ap) or not os.path.isfile(ap):
            reasons.append(f"listed file not regular: {rel}")
            continue
        h = hashlib.sha256()
        size = 0
        with open(ap, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
                size += len(chunk)
        if not isinstance(entry, dict) or entry.get("sha256") != h.hexdigest():
            reasons.append(f"hash mismatch: {rel}")
        elif entry.get("size") != size:
            reasons.append(f"size mismatch: {rel}")

    return _verdict(
        "VALID" if not reasons else "INVALID",
        bundle_name,
        bundle_path,
        manifest_sha256,
        reasons,
    )


def _verdict(
    status: str,
    bundle_name: str | None,
    bundle_path: str,
    manifest_sha256: str | None,
    reasons: list[str],
) -> Verdict:
    return {
        "verdict": status,
        "bundle": bundle_name,
        "bundle_path": os.path.abspath(bundle_path),
        "manifest_sha256": manifest_sha256,
        "run_id": str(uuid.uuid4()),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "reasons": reasons,
    }


def check_verdict(bundle_path: str, verdict_path: str) -> tuple[bool, list[str]]:
    """Re-validate an existing verdict file against the bundle's current
    bytes. Returns (accepted, reasons)."""
    reasons = []
    try:
        with open(verdict_path, "rb") as f:
            old = json.loads(f.read().decode("utf-8"))
    except Exception as e:
        return False, [f"verdict file unreadable: {e}"]
    if not isinstance(old, dict):
        return False, ["verdict file is not an object"]
    unknown = set(old) - VERDICT_FIELDS
    if unknown:
        reasons.append(f"unknown verdict fields: {sorted(unknown)}")
    if old.get("verdict") != "VALID":
        reasons.append("verdict is not VALID")
    current = verify(bundle_path)
    if current["verdict"] != "VALID":
        reasons.append(
            "bundle no longer validates: {}".format("; ".join(current["reasons"]))
        )
    for field in ("bundle", "bundle_path", "manifest_sha256"):
        if old.get(field) != current.get(field):
            reasons.append(
                f"{field} mismatch: verdict names {old.get(field)!r}, bundle has {current.get(field)!r}"
            )
    return (not reasons), reasons


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "--check-verdict":
        accepted, reasons = check_verdict(argv[2], argv[3])
        print(
            json.dumps(
                {"verdict_accepted": accepted, "reasons": reasons},
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if accepted else 1
    if len(argv) != 2:
        print(
            "usage: verifier.py BUNDLE_PATH\n"
            "       verifier.py --check-verdict BUNDLE_PATH VERDICT_PATH",
            file=sys.stderr,
        )
        return 2
    result = verify(argv[1])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "VALID" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
