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


def test_decision_layer_calibration_and_causal_evidence(synth):
    from netirava.decision import score_calibration, calibrate, apply, entity_evidence
    cal = score_calibration(synth)
    for alpha in (0.01, 0.05):
        t = calibrate(cal, alpha, 300000, 0.05)
        for name, al in apply(cal, t).items():
            assert al[cal.is_benign.to_numpy()].mean() <= alpha + 1e-12, name
    # evidence of a prefix does not depend on later flows
    d = cal.sort_values("decision_at").reset_index(drop=True)
    flag = d.an_score.to_numpy() >= np.quantile(d.an_score, 0.9)
    full = entity_evidence(d, flag, 300000)
    da = d.decision_at.to_numpy()
    k = int(np.searchsorted(da, da[len(d) // 2], side='right'))   # cut at a tick boundary
    pre = entity_evidence(d.iloc[:k].reset_index(drop=True), flag[:k], 300000)
    assert (full[:k] == pre).all()


def test_family_aware_keeps_probabilities_and_binary_alerts():
    from netirava.family import render, UNCERTAIN
    rng = np.random.default_rng(0)
    classes = ["Benign", "A", "X", "S"]
    P = rng.dirichlet(np.ones(4), 5000)
    P0 = P.copy()
    thr = 0.5
    alert_before = (1 - P[:, 0]) >= thr
    lab = render(P, classes, {"Web": ["X", "S"]}, tau=0.8)
    assert np.array_equal(P, P0)                                  # probabilities untouched
    assert np.array_equal((1 - P[:, 0]) >= thr, alert_before)     # binary decision unchanged
    am = np.asarray(classes, dtype=object)[P.argmax(1)]
    outside = ~np.isin(am, ["X", "S"])
    assert (lab[outside] == am[outside]).all()                    # only family argmax rows re-rendered
    unc = lab == UNCERTAIN.format(fam="Web")
    share = P[np.arange(len(P)), P.argmax(1)] / P[:, [2, 3]].sum(1)
    assert (share[unc] < 0.8).all() and np.isin(am[unc], ["X", "S"]).all()


def test_relabel_rules_basic():
    import pandas as pd
    from netirava.relabel import relabel, UTC
    rows = [  # (start, src, dst, proto, dport, sport, in_pkts, in_bytes, label)
        (UTC("2018-02-28 15:00"), "172.31.69.24", "172.31.69.15", 6, 445, 50000, 1, 44, "Benign"),
        (UTC("2018-02-28 15:00"), "172.31.69.24", "172.31.69.15", 17, 67, 68, 1, 300, "Benign"),
        (UTC("2018-02-22 18:00"), "18.218.115.60", "172.31.69.28", 6, 80, 50001, 30, 9000, "SQL_Injection"),
        (UTC("2018-02-22 18:00"), "52.14.77.172", "172.31.69.28", 17, 500, 500, 6, 3168, "Brute_Force_-XSS"),
        (UTC("2018-02-22 18:00"), "5.188.11.188", "172.31.69.28", 6, 445, 40000, 2, 100, "Brute_Force_-Web"),
        (UTC("2018-02-14 15:00"), "1.2.3.4", "172.31.69.28", 6, 21, 40000, 2, 100, "FTP-BruteForce"),
    ]
    df = pd.DataFrame(rows, columns=["FLOW_START_MILLISECONDS", "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "PROTOCOL",
                                     "L4_DST_PORT", "L4_SRC_PORT", "IN_PKTS", "IN_BYTES", "label_original"])
    df["flow_id"] = range(len(df))
    a = relabel(df)
    assert list(a.label_corrected) == ["Portscan", "Benign", "Brute_Force_-XSS", "Benign", "Indeterminate", "FTP-BruteForce"]
    assert list(a.status) == ["confirmed", "unchanged", "confirmed", "background", "indeterminate", "not_audited"]
    assert list(a.label_original) == list(df.label_original)       # original labels kept


def test_family_annotate_fields_and_scope():
    from netirava.family import annotate, incident_labels
    classes = ["Benign", "FTP", "Web", "XSS", "SQLi"]
    P = np.array([[0.90, 0.05, 0.02, 0.02, 0.01],    # benign
                  [0.05, 0.85, 0.05, 0.03, 0.02],    # outside the family
                  [0.05, 0.02, 0.03, 0.50, 0.40],    # XSS share 0.54 -> uncertain
                  [0.05, 0.02, 0.01, 0.90, 0.02]])   # XSS share 0.97 -> fine
    P0 = P.copy()
    a = annotate(P, classes, {"Web": ["Web", "XSS", "SQLi"]}, {"FTP": "BruteForce"}, 0.8)
    assert np.array_equal(P, P0)
    assert list(a["fine_label_status"]) == ["benign", "fine", "uncertain", "fine"]
    assert list(a["predicted_family"]) == ["Benign", "BruteForce", "Web", "Web"]
    assert a["fine_label"][0] == "Benign" and a["fine_label"][1] == "FTP" and a["fine_label"][3] == "XSS"
    assert np.isclose(a["family_mass"][2], 0.93) and a["uncertainty_reason"][2]
    df = pd.DataFrame({"incident_id": [1, 1, 2, 3], **{k: a[k] for k in ("predicted_family", "fine_label", "fine_label_status")}})
    il = incident_labels(df)
    assert il.loc[2, "fine_label_status"] == "uncertain" and il.loc[3, "fine_label"] == "XSS"


def test_replay_family_columns_do_not_change_active_decisions(synth):
    import copy
    lo = copy.deepcopy(synth); lo["family"] = {"ambiguous": {"Atk": ["FTP-BruteForce"]}, "tau": 0.05}
    hi = copy.deepcopy(synth); hi["family"] = {"ambiguous": {"Atk": ["FTP-BruteForce"]}, "tau": 0.99}
    a = run(lo, mode="a0", run_id="fam_lo")
    b = run(hi, mode="a0", run_id="fam_hi")
    assert a["active_decisions_sha1"] == b["active_decisions_sha1"] and a["active"] == b["active"]
    d = RunStore(synth, "fam_lo").detections()
    for col in ("predicted_family", "fine_label", "fine_label_status", "fine_confidence", "family_mass"):
        assert col in d.columns


def test_flow_table_backward_compatible_with_old_runs(synth):
    from netirava.triage import flow_table, incident_table, export
    run(synth, mode="a0", run_id="oldstyle")
    st = RunStore(synth, "oldstyle")
    d = st.detections().drop(columns=["predicted_family", "fine_label", "fine_label_status", "fine_confidence",
                                      "family_mass", "uncertainty_reason"])
    st.write_detections(d)                                   # a run recorded before the integration
    meta, ft = flow_table(synth, "oldstyle")
    assert "fine_label" in ft.columns
    meta, inc, _ = incident_table(synth, "oldstyle")
    assert len(inc) == meta["active"]["incidents"]
    assert export(synth, "oldstyle")["incidents"] == len(inc)
