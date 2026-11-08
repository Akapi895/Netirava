"""Ops study: incident correlation (campaign.py), drift monitor (drift.py), evaluator (ops.py), UI smoke.
Invariants pre-registered in docs/OPS_STUDY_PREREG.md §6."""

import copy

import numpy as np
import pandas as pd
import pytest

from netirava import campaign as C
from netirava import drift as D
from netirava import family as FA

H = C.HOUR_MS
MIN = 60_000


def _fl(rows):
    """rows: (t_ms, src_incident, entity, dst, family) -> alerted-flow frame in one segment."""
    d = pd.DataFrame(rows, columns=["decision_at", "src_incident", "entity", "dst", "family"])
    d["segment"] = "S"
    d["available_at"] = d.decision_at
    d["flow_id"] = np.arange(len(d))
    return d


def test_correlator_joins_sources_on_same_target_and_family():
    d = _fl([(0, 1, "a", "V", "DDoS"), (MIN, 2, "b", "V", "DDoS"), (2 * MIN, 3, "c", "V", "DDoS"),
             (3 * MIN, 4, "d", "V", "Web"),                    # other family -> own campaign
             (4 * MIN, 5, "e", "W", "DDoS")])                  # other target -> own campaign
    c = C.assign(d, 15 * MIN)
    assert c[0] == c[1] == c[2] and len({c[0], c[3], c[4]}) == 3
    c2 = C.assign(d, 15 * MIN, key=("dst",))                   # ablation: target only
    assert c2[0] == c2[3] and c2[0] != c2[4]


def test_correlator_cooldown_expiry_no_merge_and_segment_reset():
    d = _fl([(0, 1, "a", "V", "DoS"), (20 * MIN, 2, "b", "V", "DoS")])   # key expired -> new campaign
    c = C.assign(d, 15 * MIN)
    assert c[0] != c[1]
    # two live campaigns are never merged: incident 2 (campaign of W) later hits V (held by campaign of incident 1)
    d = _fl([(0, 1, "a", "V", "DoS"), (MIN, 2, "b", "W", "DoS"), (2 * MIN, 2, "b", "V", "DoS"), (3 * MIN, 3, "c", "W", "DoS")])
    c = C.assign(d, 15 * MIN)
    assert c[0] != c[1] and c[2] == c[1] and c[3] == c[1]
    d = _fl([(0, 1, "a", "V", "DoS"), (MIN, 2, "b", "V", "DoS")])
    d.loc[1, "segment"] = "T"
    d.loc[1, "decision_at"] = d.loc[1, "available_at"] = 10 * H
    c = C.assign(d, 15 * MIN)
    assert c[0] != c[1]


def test_campaign_assignment_is_causal_prefix_invariant():
    rng = np.random.default_rng(0)
    n = 400
    t = np.sort(rng.integers(0, 3 * H, n))
    d = _fl([(int(t[i]), int(rng.integers(1, 40)), "x", f"D{rng.integers(0, 4)}", ["DoS", "Web"][rng.integers(0, 2)])
             for i in range(n)])
    full = C.assign(d, 15 * MIN)
    for k in (50, 200, 333):
        assert (C.assign(d.iloc[:k], 15 * MIN) == full[:k]).all()


def test_review_queue_is_shared_causal_and_budgeted():
    d = _fl([(0, 1, "a", "V", "x")] + [(H + 10 * MIN, 1, "a", "V", "x")] * 50 +     # item 1: 1 flow before review
            [(30 * MIN, 2, "b", "V", "x")] * 3 +                                    # item 2: 3 flows before review
            [(40 * MIN, 3, "c", "V", "x")] * 2)
    d["severity"] = 3
    items, sel = C.review_queue(d, "src_incident", budgets=[1, 2])
    assert items.loc[1, "n_at_review"] == 1 and items.loc[1, "n_total"] == 51   # future flows are not used to rank
    assert sel[("volume", 1)] == {2} and sel[("fifo", 1)] == {1} and sel[("volume", 2)] == {2, 3}
    d.loc[d.src_incident == 3, "severity"] = 5
    _, sel = C.review_queue(d, "src_incident", budgets=[1])
    assert sel[("severity", 1)] == {3}
    d["camp"] = 9                                              # same function, coarser unit
    items, sel = C.review_queue(d, "camp", budgets=[1])
    assert len(items) == 1 and sel[("fifo", 1)] == {9}


def test_uncertain_flow_never_gets_withheld_class_severity():
    cfg = {"triage": {"severity": {"SQL_Injection": 5, "Brute_Force_-XSS": 4, "Benign": 4, "FTP-BruteForce": 3}},
           "family": {"severity": {"Web": 4}}}
    df = pd.DataFrame({"fine_label": ["Web attack — fine class uncertain", "SQL_Injection", "Benign", "FTP-BruteForce"],
                       "fine_label_status": ["uncertain", "fine", "benign", "fine"],
                       "predicted_family": ["Web", "Web", "Benign", "BruteForce"],
                       "a0_pred": ["SQL_Injection", "SQL_Injection", "Benign", "FTP-BruteForce"]})
    sev, src = FA.flow_severity(df, cfg)
    assert list(sev) == [4, 5, 4, 3] and list(src) == ["family", "fine_class", "benign_argmax", "fine_class"]


def test_psi_and_tail_ratio_on_synthetic_shift():
    rng = np.random.default_rng(1)
    x = rng.normal(size=20000)
    spec = D._bin_spec(x, False, 20)
    ref = D._hist(x, spec)
    assert D.psi(D._hist(rng.normal(size=20000), spec), ref) < 0.01
    assert D.psi(D._hist(rng.normal(1.0, 1, 20000), spec), ref) > 0.25
    cat = D._bin_spec(np.r_[np.zeros(900), np.ones(100)], True, 1)
    assert list(D._hist(np.array([0, 0, 1, 7]), cat)) == [2, 2]
    r, p, al = D._ratio_alarm(300, 10000, 0.009, 2.0, 0.001)       # 3% observed vs 0.9% expected
    assert r > 3 and p < 1e-6 and al
    r, p, al = D._ratio_alarm(95, 10000, 0.009, 2.0, 0.001)
    assert not al


@pytest.fixture(scope="module")
def ops_cfg(synth):
    cfg = copy.deepcopy(synth)
    cfg["triage"] = {"severity": {"Benign": 4, "FTP-BruteForce": 3}}
    cfg["family"] = {"ambiguous": {}, "tau": 0.8, "severity": {}}
    cfg["ops"] = {"correlation": {"key": ["dst", "family"], "ablation_keys": [["dst"]], "cooldown_ms": 900000},
                  "queue": {"budgets": [1, 2], "policies": ["fifo", "volume", "severity"], "alphas": [0.01],
                            "primary": {"policy": "severity", "budget": 1, "alpha": 0.01}},
                  "impact_weight": {"Bot": 5}, "go_rules": {"benefit_abs": 0.05, "contamination_max": 0.05, "delay_max_ms": 900000},
                  "drift": {"reference_window": "C1", "window_ms": 900000, "min_flows": 100, "min_benign_eval": 100,
                            "alphas": [0.01, 0.05], "primary_alpha": 0.01, "tail_band_factor": 3, "ratio_alarm": 2.0,
                            "p_alarm": 0.001, "psi_alarm": 0.25, "exceed_factor": 2.0, "cat_top_k": 5,
                            "go_rules": {"spearman_min": 0.5, "recall_min": 0.8, "false_alarm_max": 0.2, "min_events": 5}},
                  "model_rule": {"incident_ratio_max": 1.5, "hoic_recall_margin": 0.05}}
    return cfg


def test_replay_campaigns_do_not_change_active_decisions(synth, ops_cfg):
    from netirava.replay import run
    from netirava.storage import RunStore
    a = run(synth, mode="a0", run_id="ops_off")
    b = run(ops_cfg, mode="a0", run_id="ops_on")
    assert a["active_decisions_sha1"] == b["active_decisions_sha1"] and a["active"] == b["active"]
    d = RunStore(ops_cfg, "ops_on").detections()
    assert ((d.campaign_id > 0) == (d.incident_id > 0)).all()
    # every flow of one source incident belongs to one campaign
    assert (d[d.incident_id > 0].groupby("incident_id").campaign_id.nunique() == 1).all()


def test_monitor_is_label_free(ops_cfg, monkeypatch):
    import netirava.dataset as DS
    from netirava.replay import run
    D.build_reference(ops_cfg, "a0")
    run(ops_cfg, mode="a0", run_id="ops_mon")

    def boom(*a, **k):
        raise AssertionError("monitor read labels")
    monkeypatch.setattr(DS, "load_truth", boom)
    tab = D.monitor_run(ops_cfg, "ops_mon")
    assert len(tab) and {"TR@0.01", "AR@0.01", "S_PSI", "F_PSI_median", "status"} <= set(tab.columns)


def test_ops_study_end_to_end_and_go_report(ops_cfg):
    from netirava.ops import go_report, study
    from netirava.replay import run
    from netirava.triage import campaign_table, export, incident_table
    D.build_reference(ops_cfg, "a0")
    run(ops_cfg, mode="a0", run_id="ops_e2e")
    corr, summ, win = study(ops_cfg, ["ops_e2e"], "t")
    lv = corr["ops_e2e"]["levels"]["0.01"]
    for sc, x in lv.items():
        r = x["original"]
        assert set(r["units"]) == {"source", "campaign", "campaign_dst_only"}
        assert r["units"]["campaign"]["items"] <= r["units"]["source"]["items"]
    assert len(win) and "E" in win.columns
    g = go_report(ops_cfg, "t", benefit_scenario="unknown-bot")
    assert "GO" in g["correlation"]["a0"]["original"]
    meta, inc, det = incident_table(ops_cfg, "ops_e2e")
    assert {"notified", "queue_rank_severity", "severity_source", "campaign_id"} <= set(inc.columns)
    assert len(campaign_table(ops_cfg, "ops_e2e", det)) <= len(inc)
    assert export(ops_cfg, "ops_e2e")["campaigns"] >= 1


def test_triage_ui_smoke(ops_cfg, tmp_path):
    import yaml
    from streamlit.testing.v1 import AppTest
    from netirava.replay import run
    from netirava import app as A
    D.build_reference(ops_cfg, "a0")
    run(ops_cfg, mode="a0", run_id="ops_ui")
    D.monitor_run(ops_cfg, "ops_ui")
    p = tmp_path / "ui.yaml"
    p.write_text(yaml.safe_dump({k: v for k, v in ops_cfg.items() if not k.startswith("_")}))
    at = AppTest.from_file(A.__file__, default_timeout=60)
    at.cli_args = ["--config", str(p), "--run", "ops_ui"] if hasattr(at, "cli_args") else None
    import sys
    old = sys.argv
    sys.argv = ["app", "--config", str(p), "--run", "ops_ui"]
    try:
        at.run()
    finally:
        sys.argv = old
    assert not at.exception, at.exception
    assert any("triage" in t.value for t in at.title)
    at.sidebar.radio[0].set_value("campaign").run()
    assert not at.exception, at.exception
