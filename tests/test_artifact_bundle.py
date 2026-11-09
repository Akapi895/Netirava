"""Artifact bundle: build/install/check on a tiny fake tree; no real artifacts are read."""

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "artifact_bundle.py"


@pytest.fixture
def ab(monkeypatch):
    spec = importlib.util.spec_from_file_location("artifact_bundle", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "FILES", ["artifacts/m/a0.cbm"])
    monkeypatch.setattr(mod, "TREES", ["runs/r1"])
    monkeypatch.setattr(mod, "EXCLUDED_PATHS", {"runs/r1/private.md"})
    return mod


def make_tree(root):
    for rel, data in {"artifacts/m/a0.cbm": b"model", "runs/r1/detections.parquet": b"scores",
                      "runs/r1/alerts.db": b"db", "runs/r1/run.log": b"local path", "runs/r1/private.md": b"x",
                      "runs/r1/catboost_info/x.tsv": b"x", "other/not_bundled.txt": b"x"}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def test_build_install_check_roundtrip(ab, tmp_path):
    src, dst, out = tmp_path / "src", tmp_path / "dst", tmp_path / "b.zip"
    make_tree(src)
    ab.main(["--root", str(src), "build", "--output", str(out)])
    names = set(zipfile.ZipFile(out).namelist())
    assert names == {"artifacts/m/a0.cbm", "runs/r1/detections.parquet", "runs/r1/alerts.db", ab.MANIFEST_NAME}
    assert out.with_name("b.zip.sha256").read_text().split()[1] == "b.zip"

    ab.main(["--root", str(dst), "install", str(out)])
    assert (dst / "runs/r1/detections.parquet").read_bytes() == b"scores"
    assert ab.main(["--root", str(dst), "check"]) == 0

    (dst / "runs/r1/alerts.db").write_bytes(b"db plus feedback")  # append-only UI state is allowed
    assert ab.main(["--root", str(dst), "check"]) == 0
    (dst / "artifacts/m/a0.cbm").write_bytes(b"tampered")
    assert ab.main(["--root", str(dst), "check"]) == 1


def test_install_refuses_to_overwrite_differing_files_but_keeps_feedback(ab, tmp_path):
    src, dst, out = tmp_path / "src", tmp_path / "dst", tmp_path / "b.zip"
    make_tree(src)
    ab.main(["--root", str(src), "build", "--output", str(out)])
    ab.main(["--root", str(dst), "install", str(out)])
    (dst / "runs/r1/alerts.db").write_bytes(b"feedback")
    ab.main(["--root", str(dst), "install", str(out)])  # idempotent; feedback database untouched
    assert (dst / "runs/r1/alerts.db").read_bytes() == b"feedback"
    (dst / "artifacts/m/a0.cbm").write_bytes(b"other model")
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        ab.main(["--root", str(dst), "install", str(out)])
    assert (dst / "artifacts/m/a0.cbm").read_bytes() == b"other model"
    ab.main(["--root", str(dst), "install", str(out), "--force"])
    assert (dst / "artifacts/m/a0.cbm").read_bytes() == b"model"


def test_build_fails_when_a_required_artifact_is_missing(ab, tmp_path):
    make_tree(tmp_path / "src")
    (tmp_path / "src/artifacts/m/a0.cbm").unlink()
    with pytest.raises(SystemExit, match="missing required artifacts"):
        ab.main(["--root", str(tmp_path / "src"), "build", "--output", str(tmp_path / "b.zip")])


@pytest.mark.parametrize("bad", ["../escape.txt", "/abs.txt", "a/../../x", "C:/x.txt", "a\\b.txt"])
def test_install_rejects_unsafe_paths_and_detects_corruption(ab, tmp_path, bad):
    out = tmp_path / "evil.zip"
    manifest = {"format": 1, "files": [{"path": bad, "size": 1, "sha256": "0" * 64}]}
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr(ab.MANIFEST_NAME, json.dumps(manifest))
        zf.writestr("payload", b"x")
    with pytest.raises(SystemExit, match="unsafe path"):
        ab.main(["--root", str(tmp_path / "dst"), "install", str(out)])
    assert not (tmp_path / "escape.txt").exists()


def test_install_detects_corrupt_member(ab, tmp_path):
    src, out = tmp_path / "src", tmp_path / "b.zip"
    make_tree(src)
    ab.main(["--root", str(src), "build", "--output", str(out)])
    with zipfile.ZipFile(out) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    man = json.loads(members[ab.MANIFEST_NAME])
    man["files"][0]["sha256"] = "0" * 64  # manifest no longer matches the stored bytes
    members[ab.MANIFEST_NAME] = json.dumps(man).encode()
    with zipfile.ZipFile(out, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    with pytest.raises(SystemExit, match="checksum mismatch"):
        ab.main(["--root", str(tmp_path / "dst"), "install", str(out)])
    assert not list((tmp_path / "dst").rglob("*.part"))
