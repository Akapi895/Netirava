"""Post-fit ToN-IoT workflow: replay frozen checkpoints and report saved decisions.

No training lives in this module. ``build_report`` reads stored scores, truth and
identifiers, verifies their provenance, and writes an additive submission report.
The original evaluator outputs and the pre-fit config/protocol are preserved.
"""

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from netirava import config as K
from netirava import features as F
from netirava.dataset import window_bounds


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def test_run_ids(cfg, prefix="ton"):
    """Stable replay ids for the windows already declared as test in the config."""
    return [f"{prefix}_{w['id']}" for w in window_bounds(cfg) if w["role"] == "replay"]


def replay_test(cfg, prefix="ton"):
    """Replay the frozen test windows without fitting; never overwrite old runs."""
    from netirava import drift
    from netirava.replay import run

    ids = test_run_ids(cfg, prefix)
    existing = [rid for rid in ids if (K.path(cfg, "runs") / rid).exists()]
    if existing:
        raise FileExistsError(f"Replay runs already exist: {existing}. Use a new --prefix.")
    model = cfg.get("final_system", {}).get("model_dir", "a0")
    reference_path = K.path(cfg, "models") / model / "drift_reference.json"
    if reference_path.exists():
        ref = drift.load_reference(cfg, model)
    else:
        ref = drift.build_reference(cfg, model)
    meta = _read_json(K.path(cfg, "models") / model / "a0_meta.json")
    alpha = str(float(cfg["a0"]["target_fpr"]))
    if (ref["model_hash"] != meta["model_hash"]
            or abs(ref["levels"][alpha]["t"] - meta["threshold"]["value"]) > 1e-9):
        raise ValueError("Drift reference does not match the frozen model/threshold")

    steps = []
    windows = [w for w in window_bounds(cfg) if w["role"] == "replay"]
    for w, rid in zip(windows, ids):
        started = time.perf_counter()
        result = run(cfg, mode="a0", segments=[w["id"]], run_id=rid, model=model)
        replay_end = time.perf_counter()
        drift.monitor_run(cfg, rid)
        steps.append({
            "run_id": rid, "events": result["events"],
            "active_decisions_sha1": result["active_decisions_sha1"],
            "replay_s": replay_end - started,
            "monitor_s": time.perf_counter() - replay_end,
        })
    result = {"config_sha1": cfg["_sha1"], "model_hash": meta["model_hash"], "steps": steps}
    _write_json(K.path(cfg, "runs") / f"PIPELINE_{prefix}.json", result)
    return result


def gated_metrics(labels, predictions, scores, threshold, classes, benign="Benign"):
    """Detection and argmax P/R/F1 *after* the gate; no probability inference.

    A fine-class prediction exists here only when score >= threshold. Unalerted
    attacks remain false negatives. This is before family-label abstention.
    Undefined precision is null rather than a fabricated perfect score.
    """
    y, pred, score = np.asarray(labels), np.asarray(predictions), np.asarray(scores)
    if y.shape != pred.shape or y.shape != score.shape:
        raise ValueError("Labels, predictions and scores must have the same shape")
    alert, attack = score >= threshold, y != benign
    tp, fp = int((alert & attack).sum()), int((alert & ~attack).sum())
    n_attack, n_benign = int(attack.sum()), int((~attack).sum())
    result = {
        "n": len(y), "attack_support": n_attack, "benign_support": n_benign,
        "alerted_flows": int(alert.sum()), "true_positive_flows": tp,
        "false_positive_flows": fp,
        "binary_recall": tp / n_attack if n_attack else None,
        "binary_precision": tp / int(alert.sum()) if alert.any() else None,
        "benign_fpr": fp / n_benign if n_benign else None,
        "per_class_after_gate_before_family_abstention": {},
    }
    for c in classes:
        if c == benign:
            continue
        actual, emitted = y == c, alert & (pred == c)
        support, predicted = int(actual.sum()), int(emitted.sum())
        hits = int((actual & emitted).sum())
        result["per_class_after_gate_before_family_abstention"][c] = {
            "support": support, "predicted_alerts": predicted, "true_positives": hits,
            "precision": hits / predicted if predicted else None,
            "recall": hits / support if support else None,
            "f1": 2 * hits / (predicted + support) if predicted + support else None,
        }
    return result


def host_novelty(attacks, train_sources, train_endpoints, train_sources_by_class):
    """Distinguish source novelty within a class from novelty in all training."""
    result = {}
    for label, g in attacks.groupby(F.LABEL):
        src = g[F.SRC]
        n = len(g)
        result[label] = {"test_attack_flows": n, "source_hosts": int(src.nunique())}
        references = {
            "not_seen_as_source_in_same_class": train_sources_by_class.get(label, set()),
            "not_seen_as_source_in_any_train_class": train_sources,
            "not_seen_as_either_endpoint_in_any_train_class": train_endpoints,
        }
        for name, seen in references.items():
            unseen = ~src.isin(seen)
            result[label][name] = {
                "flows": int(unseen.sum()), "share": float(unseen.mean()),
                "source_hosts": int(src[unseen].nunique()),
            }
    return result


def _training_hosts(stream, truth):
    sources, endpoints, by_class = set(), set(), {}
    cols = ["flow_id", "role", F.SRC, F.DST]
    for batch in pq.ParquetFile(stream).iter_batches(batch_size=250_000, columns=cols):
        d = batch.to_pandas()
        d = d[d.role == "train"].copy()
        sources.update(d[F.SRC])
        endpoints.update(d[F.SRC])
        endpoints.update(d[F.DST])
        d[F.LABEL] = d.flow_id.map(truth[F.LABEL])
        for label, g in d.groupby(F.LABEL):
            by_class.setdefault(label, set()).update(g[F.SRC])
    return sources, endpoints, by_class


def build_report(cfg, run_ids=None, output=None):
    """Summarize the complete locked test from saved scores; never score or fit.

    Missing, duplicated, wrong-model, wrong-stream and partial-test inputs fail
    before the report is written. Source novelty includes benign training rows.
    """
    from netirava.storage import RunStore

    ids = list(test_run_ids(cfg) if run_ids is None else run_ids)
    if not ids or len(set(ids)) != len(ids):
        raise ValueError("Provide a nonempty list of distinct test runs")
    derived = K.path(cfg, "derived")
    model = cfg.get("final_system", {}).get("model_dir", "a0")
    meta_path = K.path(cfg, "models") / model / "a0_meta.json"
    meta = _read_json(meta_path)
    manifest = _read_json(derived / "manifest.json")
    if (K.sha1_file(meta_path.parent / "a0.cbm") != meta["model_sha1"]
            or meta["features"] != F.FEATURES or meta["feature_schema_hash"] != F.schema_hash()):
        raise ValueError("Model checkpoint or feature contract does not match metadata")
    for filename, key in (("stream.parquet", "stream_sha1"), ("truth.parquet", "truth_sha1")):
        if K.sha1_file(derived / filename) != manifest[key]:
            raise ValueError(f"Derived input checksum mismatch: {filename}")
    truth = pd.read_parquet(derived / "truth.parquet", columns=["flow_id", F.LABEL, "role", "segment"])
    if not truth.flow_id.is_unique:
        raise ValueError("Truth flow ids are not unique")
    truth = truth.set_index("flow_id")
    expected = truth.index[truth.role == "replay"]
    hosts = _training_hosts(derived / "stream.parquet", truth)
    seen = set()
    frames, novelty, runs = [], {}, {}
    threshold = meta["threshold"]["value"]
    for rid in ids:
        store = RunStore(cfg, rid)
        rm = store.meta()
        if (rm["a0"]["model_hash"] != meta["model_hash"]
                or rm["stream_sha1"] != manifest["stream_sha1"]
                or abs(rm["a0"]["threshold"] - threshold) > 1e-12):
            raise ValueError(f"Run provenance mismatch: {rid}")
        d = store.detections(columns=["flow_id", "segment", "a0_pred", "a0_score", "a0_candidate"])
        if not d.flow_id.is_unique or seen.intersection(d.flow_id):
            raise ValueError(f"Duplicate test flow ids: {rid}")
        seen.update(d.flow_id)
        t = truth.reindex(d.flow_id)
        if t.role.isna().any() or not (t.role == "replay").all():
            raise ValueError(f"Run contains unknown or non-test flows: {rid}")
        if not np.array_equal(t.segment.to_numpy(), d.segment.to_numpy()):
            raise ValueError(f"Segment mismatch: {rid}")
        if not np.array_equal(d.a0_candidate, d.a0_score >= threshold):
            raise ValueError(f"Stored gate differs from threshold: {rid}")
        d[F.LABEL] = t[F.LABEL].to_numpy()
        runs[rid] = gated_metrics(d[F.LABEL], d.a0_pred, d.a0_score, threshold, meta["classes"])
        attack_ids = d.loc[d[F.LABEL] != "Benign", "flow_id"]
        src = pq.read_table(derived / "stream.parquet", columns=["flow_id", F.SRC],
                            filters=[("flow_id", "in", attack_ids.tolist())]).to_pandas()
        attacks = d[["flow_id", F.LABEL]].merge(src, on="flow_id", validate="one_to_one")
        novelty[rid] = host_novelty(attacks, *hosts)
        frames.append(d)
    if len(seen) != len(expected) or not expected.isin(seen).all():
        raise ValueError("Runs do not cover the declared test exactly once")
    all_flows = pd.concat(frames, ignore_index=True)
    result = {
        "dataset": cfg["dataset"]["name"], "model_hash": meta["model_hash"],
        "threshold": threshold, "config_sha1": cfg["_sha1"],
        "training_config_sha1": meta.get("config_sha1"),
        "configuration_note": "Current config may have documentation-only edits; training hash is preserved separately.",
        "stream_sha1": manifest["stream_sha1"], "truth_sha1": manifest["truth_sha1"],
        "analysis": "post-fit reporting correction, saved decisions only; no model selection",
        "fine_metric_scope": "threshold + argmax, before family abstention",
        "pooled": gated_metrics(all_flows[F.LABEL], all_flows.a0_pred, all_flows.a0_score,
                                 threshold, meta["classes"]),
        "runs": runs, "source_host_novelty": novelty,
        "test_coverage_exactly_once": True,
    }
    path = Path(output) if output else K.path(cfg, "runs") / "SUBMISSION_TON.json"
    _write_json(path, result)
    return result
