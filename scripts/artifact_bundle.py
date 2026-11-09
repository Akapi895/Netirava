#!/usr/bin/env python
"""Build, install and check the external artifact bundle (docs/reproduction.md, section 3).

Checkpoints, derived streams and replay runs are outside Git. The bundle holds exactly the files
needed by the README flow: tests with the ToN contract check, CIC and ToN UI, ui-check and ton-report.
It contains no raw datasets and no model fitting inputs. Standard library only.

    python scripts/artifact_bundle.py build   --output ../netirava-artifacts-v1.zip
    python scripts/artifact_bundle.py install netirava-artifacts-v1.zip
    python scripts/artifact_bundle.py check
"""

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "BUNDLE_MANIFEST.json"
INSTALLED_MANIFEST = "artifacts/BUNDLE_MANIFEST.json"
CHUNK = 1 << 20

FILES = [
    "artifacts/cic18_causal_demo_v1/manifest.json",
    "artifacts/cic18_causal_demo_v1/stream.parquet",
    "artifacts/models/pilot_cns/s0/a0.cbm",
    "artifacts/models/pilot_cns/s0/a0_meta.json",
    "artifacts/models/pilot_cns/s0/drift_reference.json",
    "artifacts/ton_iot_v1/manifest.json",
    "artifacts/ton_iot_v1/stream.parquet",
    "artifacts/ton_iot_v1/truth.parquet",
    "artifacts/ton_iot_v1/FROZEN_PLAN.json",
    "artifacts/ton_iot_v1/RAW_MANIFEST_before.json",
    "artifacts/ton_iot_v1/RAW_MANIFEST_after.json",
    "artifacts/ton_iot_v1/SPLIT_AUDIT.json",
    "artifacts/ton_iot_v1/models/a0/a0.cbm",
    "artifacts/ton_iot_v1/models/a0/a0_meta.json",
    "artifacts/ton_iot_v1/models/a0/drift_reference.json",
    "artifacts/ton_iot_v1/models/a0/FIT_STARTED.json",
    "artifacts/ton_iot_v1/models/a0/MODEL_CARD.md",
]
TREES = ["runs/20261108T190143_a0_fast", "runs/ton_iot", "artifacts/documentation_originals"]
EXCLUDED_NAMES = {"catboost_info", "__pycache__"}
EXCLUDED_SUFFIXES = (".log", "-wal", "-shm", "-journal")
EXCLUDED_PATHS = {"artifacts/documentation_originals/CLAUDE.md"}  # local agent notes, not evidence
MUTABLE_NAMES = {"alerts.db"}  # the UI appends feedback; never overwritten or flagged by check


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def excluded(rel):
    return (rel in EXCLUDED_PATHS or rel.endswith(EXCLUDED_SUFFIXES)
            or any(part in EXCLUDED_NAMES for part in rel.split("/")))


def collect(root):
    rels, missing = set(), []
    for rel in FILES:
        (rels.add(rel) if (root / rel).is_file() else missing.append(rel))
    for tree in TREES:
        base = root / tree
        if not base.is_dir():
            missing.append(tree)
            continue
        rels.update(r for p in base.rglob("*") if p.is_file()
                    and not excluded(r := p.relative_to(root).as_posix()))
    if missing:
        raise SystemExit("missing required artifacts:\n  " + "\n  ".join(missing))
    return sorted(rels)


def safe_target(root, rel):
    p = PurePosixPath(rel)
    if p.is_absolute() or ".." in p.parts or "\\" in rel or ":" in rel:
        raise SystemExit(f"unsafe path in bundle: {rel}")
    return root.joinpath(*p.parts)


def git_commit(root):
    try:
        return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def build(args):
    root, out = Path(args.root).resolve(), Path(args.output).resolve()
    rels = collect(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    with zipfile.ZipFile(out, "w", allowZip64=True) as zf:
        for rel in rels:
            src = root / rel
            info = zipfile.ZipInfo.from_file(src, rel)
            info.compress_type = zipfile.ZIP_DEFLATED
            h, size = hashlib.sha256(), 0
            with src.open("rb") as fi, zf.open(info, "w") as fo:
                for chunk in iter(lambda: fi.read(CHUNK), b""):
                    h.update(chunk)
                    size += len(chunk)
                    fo.write(chunk)
            entries.append({"path": rel, "size": size, "sha256": h.hexdigest(),
                            **({"mutable": True} if Path(rel).name in MUTABLE_NAMES else {})})
        manifest = {"format": 1, "name": "netirava-artifacts", "repo_commit": git_commit(root),
                    "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "files": entries}
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))
    out.with_name(out.name + ".sha256").write_text(f"{sha256_file(out)}  {out.name}\n", encoding="utf-8")
    print(f"built {out} ({out.stat().st_size / 1e6:,.0f} MB, {len(entries)} files)")


def install(args):
    root = Path(args.root).resolve()
    with zipfile.ZipFile(args.bundle) as zf:
        manifest = json.loads(zf.read(MANIFEST_NAME))
        plan, conflicts, present = [], [], 0
        for e in manifest["files"]:
            dst = safe_target(root, e["path"])
            if dst.exists() and not args.force:
                if e.get("mutable") or (dst.stat().st_size == e["size"] and sha256_file(dst) == e["sha256"]):
                    present += 1
                else:
                    conflicts.append(e["path"])
                continue
            plan.append((e, dst))
        if conflicts:
            raise SystemExit("refusing to overwrite files that differ from the bundle (use --force):\n  "
                             + "\n  ".join(conflicts))
        for e, dst in plan:
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".part")
            h = hashlib.sha256()
            with zf.open(e["path"]) as fi, tmp.open("wb") as fo:
                for chunk in iter(lambda: fi.read(CHUNK), b""):
                    h.update(chunk)
                    fo.write(chunk)
            if h.hexdigest() != e["sha256"]:
                tmp.unlink()
                raise SystemExit(f"checksum mismatch, bundle is corrupt: {e['path']}")
            tmp.replace(dst)
    marker = root / INSTALLED_MANIFEST
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"installed {len(plan)} files into {root}; {present} already present")


def check(args):
    root = Path(args.root).resolve()
    marker = root / INSTALLED_MANIFEST
    if not marker.exists():
        raise SystemExit(f"{INSTALLED_MANIFEST} not found: run `install` first")
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    bad = []
    for e in manifest["files"]:
        dst = safe_target(root, e["path"])
        if not dst.is_file():
            bad.append(f"missing   {e['path']}")
        elif not e.get("mutable") and (dst.stat().st_size != e["size"] or sha256_file(dst) != e["sha256"]):
            bad.append(f"modified  {e['path']}")
    if bad:
        print("\n".join(bad))
        print(f"FAILED: {len(bad)} of {len(manifest['files'])} files")
        return 1
    print(f"OK: {len(manifest['files'])} files match the bundle manifest")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(ROOT), help="repository root (default: this repository)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="pack the artifacts of this checkout into a zip")
    b.add_argument("--output", required=True)
    b.set_defaults(fn=build)
    i = sub.add_parser("install", help="verify and extract a bundle into the repository root")
    i.add_argument("bundle")
    i.add_argument("--force", action="store_true", help="overwrite differing files")
    i.set_defaults(fn=install)
    c = sub.add_parser("check", help="verify installed artifacts against the bundle manifest")
    c.set_defaults(fn=check)
    args = ap.parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
