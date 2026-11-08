import json
import sqlite3

import numpy as np
import pandas as pd
import pytest

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, load_truth, training_frame
from netirava.detectors import A0, apply_smote, smote_plan, train_a0
from netirava.policy import Policy
from netirava.replay import run
from netirava.storage import RunStore

ACTIVE = ["flow_id", "segment", "available_at", "decision_at", "a0_pred", "a0_score", "a0_candidate",
          "active_action", "active_reason", "incident_id"]


def test_stream_has_no_labels_and_contract_rejects_them(synth):
    s = load_stream(synth)
    assert F.LABEL not in s.columns and F.LABEL_BIN not in s.columns
    F.flow_event_batch(s.drop(columns=["role"]))
    with pytest.raises(ValueError):
        F.flow_event_batch(s)                       # 'role' is evaluator-only
    assert not set(F.FEATURES) & set(F.NEVER_INPUT)


def test_roles_disjoint_available_at_and_order(synth):
    s = load_stream(synth)
    t = load_truth(synth)
    assert s.row_id.is_unique and set(s.row_id) == set(t.row_id)
    assert s.groupby("row_id").role.nunique().max() == 1
    assert (s.available_at == s[F.TS_END] + synth["replay"]["export_delay_ms"]).all()
    key = list(zip(s.available_at, s.row_id))
    assert key == sorted(key)
    assert set(t.loc[t.role == "train", F.LABEL]) <= set(synth["a0"]["known_classes"])


def test_training_frame_refuses_replay_roles(synth):
    with pytest.raises(AssertionError):
        training_frame(synth, ["replay"])




def test_threshold_and_model_independent_of_replay_labels(tmp_path, synth):
    from conftest import make_csv, make_cfg
    from netirava.dataset import prepare
    csv = tmp_path / "flipped.csv"
    make_csv(csv, flip_replay_labels=True)
    cfg2 = make_cfg(tmp_path, csv)
    prepare(cfg2)
    train_a0(cfg2)
    m1 = json.loads((K.path(synth, "models") / "a0" / "a0_meta.json").read_text(encoding="utf-8"))
    m2 = json.loads((K.path(cfg2, "models") / "a0" / "a0_meta.json").read_text(encoding="utf-8"))
    assert m1["threshold"]["value"] == m2["threshold"]["value"]
    assert m1["train_counts"] == m2["train_counts"]
    X = F.matrix(load_stream(synth, roles=["replay"]))
    p1 = A0.load(K.path(synth, "models") / "a0").score(X)[1]
    p2 = A0.load(K.path(cfg2, "models") / "a0").score(X)[1]
    assert np.allclose(p1, p2)


def test_prefix_invariance_and_chunking(synth):
    full = RunStore(synth, run(synth, mode="a0-shadow", run_id="full")["run_id"]).detections()
    k = len(full) // 2
    pre = RunStore(synth, run(synth, mode="a0-shadow", max_events=k, run_id="prefix")["run_id"]).detections()
    cols = ACTIVE + ["an_score", "an_would_alert", "shadow_incident_id"]
    pd.testing.assert_frame_equal(full[cols].iloc[:k].reset_index(drop=True), pre[cols].reset_index(drop=True))
    cfg = dict(synth, replay=dict(synth["replay"], chunk_events=7))
    small = RunStore(synth, run(cfg, mode="a0-shadow", run_id="chunk7")["run_id"]).detections()
    pd.testing.assert_frame_equal(full[cols], small[cols])


def test_shadow_on_off_and_failure_do_not_change_active(synth, monkeypatch):
    a = run(synth, mode="a0", run_id="a0only")
    b = run(synth, mode="a0-shadow", run_id="withshadow")
    assert a["active_decisions_sha1"] == b["active_decisions_sha1"]
    from netirava import detectors
    monkeypatch.setattr(detectors.Anomaly, "score", lambda self, X: (_ for _ in ()).throw(RuntimeError("boom")))
    c = run(synth, mode="a0-shadow", run_id="broken")
    assert c["degraded"] and c["shadow_status_counts"]["missing"] == c["events"]
    assert c["active_decisions_sha1"] == a["active_decisions_sha1"]


def test_paced_mode_same_decisions(synth):
    f = run(synth, mode="a0", run_id="fast2")
    p = run(synth, mode="a0", pace="paced", speed=1e9, run_id="paced")
    assert f["active_decisions_sha1"] == p["active_decisions_sha1"]


def test_policy_cooldown_budget_and_reset():
    pol = Policy(cooldown_ms=10_000, budget_per_hour=1)
    d1 = pol.step(0, "a", 1, "S")
    d2 = pol.step(5_000, "a", 2, "S")              # within cooldown -> same incident
    d3 = pol.step(30_000, "a", 3, "S")             # cooldown expired -> new incident, budget used
    d4 = pol.step(3_600_000, "b", 4, "S")          # next simulated hour -> budget available
    assert (d1.action, d2.reason, d2.incident_id) == ("notify", "cooldown_dedup", d1.incident_id)
    assert d3.new_incident and d3.reason == "budget_exceeded" and d3.action == "suppressed"
    assert d4.action == "notify"
    pol.reset()
    assert pol.step(3_600_001, "b", 5, "T").new_incident     # state dropped at a segment boundary


def test_feedback_append_only(synth):
    r = run(synth, mode="a0", run_id="fb")
    st = RunStore(synth, r["run_id"])
    with sqlite3.connect(st.db) as c:
        aid = c.execute("SELECT alert_id FROM alerts LIMIT 1").fetchone()[0]
    f1 = st.add_feedback(aid, "false_positive", "analyst", "tester")
    f2 = st.add_feedback(aid, "true_positive", "analyst", "tester", attack_label="Bot", corrects=f1["feedback_id"])
    assert f2["corrects"] == f1["feedback_id"] and len(st.feedback()) == 2
    with sqlite3.connect(st.db) as c, pytest.raises(sqlite3.DatabaseError):
        c.execute("UPDATE feedback SET status='uncertain'")
    with pytest.raises(ValueError):
        st.add_feedback(999999, "uncertain", "analyst", "tester")


def test_model_persist_load_equivalence(synth):
    det = RunStore(synth, "full").detections()
    m = A0.load(K.path(synth, "models") / "a0")
    s = load_stream(synth)
    s = s.set_index("flow_id").loc[det.flow_id].reset_index()
    P, att, _ = m.score(F.matrix(s))
    assert np.allclose(att, det.a0_score.to_numpy())


def test_smote_plan_and_categorical_guard():
    plan, small = smote_plan([5000, 120, 1, 0], lt=1000, k=5)
    assert plan == {1: 1000} and small == []
    plan, small = smote_plan([5000, 4], lt=1000, k=5)
    assert small == [1]
    rng = np.random.default_rng(0)
    X = rng.integers(0, 50, (1200, len(F.FEATURES))).astype(float)
    y = np.r_[np.zeros(1100, int), np.ones(100, int)]
    rec = {"smote_lt": 1000, "smote_k": 5, "seed": 0}
    Xr, yr, info = apply_smote(X, y, rec, ["Benign", "X"])
    assert info["applied"] and (yr == 1).sum() == 1000
    j = F.FEATURES.index("PROTOCOL")
    assert set(Xr[:, j]) <= set(X[:, j])          # categorical codes copied, not interpolated




def test_evaluate_runs(synth):
    from netirava.evaluation import evaluate
    s = evaluate(synth, "withshadow")
    assert "unknown-bot" in s and "known-within-episode" in s
