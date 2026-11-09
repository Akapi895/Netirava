"""Submission reporting checks use saved decisions only; no model is fitted."""

import json

import pandas as pd
import pytest

from netirava import config as K
from netirava import features as F
from netirava.cli import build_parser
from netirava.ton_reporting import build_report, gated_metrics, host_novelty, replay_test


def test_gate_metrics_count_missed_attacks_and_remove_rejected_predictions():
    r = gated_metrics(
        ["Benign", "Benign", "ransomware", "ransomware", "mitm"],
        ["ransomware", "ransomware", "ransomware", "Benign", "ransomware"],
        [0.2, 0.4, 0.99, 0.1, 0.98], 0.95, ["Benign", "ransomware", "mitm"],
    )
    assert r["binary_recall"] == pytest.approx(2 / 3)
    assert r["benign_fpr"] == 0
    fine = r["per_class_after_gate_before_family_abstention"]
    assert fine["ransomware"]["precision"] == 0.5
    assert fine["ransomware"]["recall"] == 0.5
    assert fine["ransomware"]["f1"] == 0.5
    assert fine["mitm"]["precision"] is None
    assert fine["mitm"]["recall"] == 0


def test_host_novelty_includes_other_classes_benign_and_both_endpoints():
    attacks = pd.DataFrame({F.LABEL: ["xss"] * 4, F.SRC: ["a", "b", "c", "d"]})
    r = host_novelty(attacks, {"a", "b"}, {"a", "b", "c"}, {"xss": {"a"}})["xss"]
    assert r["not_seen_as_source_in_same_class"]["share"] == 0.75
    assert r["not_seen_as_source_in_any_train_class"]["share"] == 0.5
    assert r["not_seen_as_either_endpoint_in_any_train_class"]["share"] == 0.25


@pytest.fixture
def saved_report_run(tmp_path):
    derived, model, runs = tmp_path / "derived", tmp_path / "models/a0", tmp_path / "runs"
    derived.mkdir()
    model.mkdir(parents=True)
    run = runs / "saved"
    run.mkdir(parents=True)
    stream = pd.DataFrame({"flow_id": [1, 2, 3, 4], "role": ["train", "train", "replay", "replay"],
                           F.SRC: ["benign-train", "attack-train", "new", "benign-train"],
                           F.DST: ["victim"] * 4})
    truth = stream[["flow_id", "role"]].assign(
        segment=["T1", "T1", "X1", "X1"], Attack=["Benign", "xss", "xss", "Benign"])
    stream.to_parquet(derived / "stream.parquet")
    truth.to_parquet(derived / "truth.parquet")
    manifest = {"stream_sha1": K.sha1_file(derived / "stream.parquet"),
                "truth_sha1": K.sha1_file(derived / "truth.parquet")}
    (derived / "manifest.json").write_text(json.dumps(manifest))
    (model / "a0.cbm").write_bytes(b"checkpoint fixture, never loaded for inference")
    model_sha = K.sha1_file(model / "a0.cbm")
    meta = {"model_sha1": model_sha, "model_hash": model_sha[:12], "features": F.FEATURES,
            "feature_schema_hash": F.schema_hash(), "classes": ["Benign", "xss"], "threshold": {"value": 0.9}}
    (model / "a0_meta.json").write_text(json.dumps(meta))
    runmeta = {"a0": {"model_hash": meta["model_hash"], "threshold": 0.9},
               "stream_sha1": manifest["stream_sha1"]}
    (run / "run.json").write_text(json.dumps(runmeta))
    pd.DataFrame({"flow_id": [3, 4], "segment": ["X1", "X1"], "a0_pred": ["xss", "xss"],
                  "a0_score": [0.95, 0.4], "a0_candidate": [True, False]}).to_parquet(run / "detections.parquet")
    cfg = {"paths": {"derived": str(derived), "models": str(model.parent), "runs": str(runs)},
           "dataset": {"name": "fixture"}, "_sha1": "fixture-config"}
    return cfg, run


def test_report_reads_saved_decisions_and_checks_complete_test(saved_report_run):
    cfg, _ = saved_report_run
    r = build_report(cfg, ["saved"])
    assert r["test_coverage_exactly_once"]
    assert r["pooled"]["binary_recall"] == 1
    assert r["pooled"]["binary_precision"] == 1
    assert r["source_host_novelty"]["saved"]["xss"]["not_seen_as_source_in_any_train_class"]["share"] == 1


@pytest.mark.parametrize("problem", ["partial", "wrong-model", "wrong-gate", "non-test"])
def test_report_rejects_invalid_saved_evidence(saved_report_run, problem):
    cfg, run = saved_report_run
    if problem == "wrong-model":
        meta = json.loads((run / "run.json").read_text())
        meta["a0"]["model_hash"] = "wrong"
        (run / "run.json").write_text(json.dumps(meta))
    else:
        d = pd.read_parquet(run / "detections.parquet")
        if problem == "partial":
            d = d.iloc[:1]
        elif problem == "wrong-gate":
            d["a0_candidate"] = False
        else:
            d.loc[0, "flow_id"] = 1
        d.to_parquet(run / "detections.parquet")
    with pytest.raises(ValueError):
        build_report(cfg, ["saved"])
    assert not (run.parent / "SUBMISSION_TON.json").exists()


def test_replay_refuses_existing_run_before_starting_any_window(tmp_path):
    (tmp_path / "ton_X1").mkdir()
    cfg = {"paths": {"runs": str(tmp_path)}, "windows": [
        {"id": "X1", "role": "replay", "start_utc": "2019-01-01 00:00", "end_utc": "2019-01-01 01:00"}]}
    with pytest.raises(FileExistsError, match="already exist"):
        replay_test(cfg)


def test_ton_commands_default_to_ton_config_and_do_not_execute():
    parser = build_parser()
    for name in ("ton-audit", "ton-prepare", "ton-split-audit", "ton-train", "ton-replay",
                 "ton-evaluate", "ton-sensitivity", "ton-report"):
        assert parser.parse_args([name]).config == "configs/ton_iot.yaml"
    assert parser.parse_args(["replay", "--run-id", "fresh"]).run_id == "fresh"


def test_missing_external_recipe_uses_portable_snapshot(tmp_path):
    from netirava.detectors import reference_recipe
    r = reference_recipe({"a0": {"reference_config": str(tmp_path / "missing.yaml"), "seed": 0}})
    assert r["source"].endswith("a0_reference.yaml")
    assert r["device"] == "GPU" and r["lr_rule"] == "cpu_auto_probe"
    assert r["base"]["border_count"] == 254


def test_registry_writes_generated_inventory_beside_runs_not_into_docs(tmp_path):
    from netirava.registry import build
    cfg = {"paths": {"runs": str(tmp_path / "runs"), "models": str(tmp_path / "models")}}
    result = build(cfg)
    assert result["runs"] == 0 and result["models"] == 0
    assert (tmp_path / "runs" / "registry.json").exists()
    assert result["file"] == str(tmp_path / "runs" / "registry.md")
    assert "curated experiment history" in (tmp_path / "runs" / "registry.md").read_text()
