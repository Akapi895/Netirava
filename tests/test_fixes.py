"""Regression tests for metric, provenance, and UI fixes (docs/cic_evidence.md)."""

import pandas as pd
import pytest

from netirava import family as FA


def test_incident_label_is_a_joint_mode_of_family_and_fine_label():
    # independent modes would give family Web (4 flows) with fine label GoldenEye (3 flows): never observed together
    d = pd.DataFrame({"incident_id": [1] * 7,
                      "predicted_family": ["Web", "Web", "Web", "Web", "DoS", "DoS", "DoS"],
                      "fine_label": ["Brute_Force_-XSS", "Brute_Force_-XSS", "SQL_Injection", "SQL_Injection",
                                     "DoS_attacks-GoldenEye", "DoS_attacks-GoldenEye", "DoS_attacks-GoldenEye"],
                      "fine_label_status": ["fine"] * 7})
    r = FA.incident_labels(d).loc[1]
    assert (r.predicted_family, r.fine_label) == ("DoS", "DoS_attacks-GoldenEye")


def test_feedback_correction_must_target_the_same_alert(synth):
    from netirava.replay import run
    from netirava.storage import RunStore
    run(synth, mode="a0", run_id="fix_fb")
    st = RunStore(synth, "fix_fb")
    ids = [r[0] for r in st.list_incidents(5)]
    assert len(ids) >= 2
    f1 = st.add_feedback(ids[0], "false_positive", "test", "t")["feedback_id"]
    with pytest.raises(ValueError, match="belongs to alert"):
        st.add_feedback(ids[1], "true_positive", "test", "t", corrects=f1)
    st.add_feedback(ids[0], "true_positive", "test", "t", corrects=f1)
    lv = st.latest_verdicts().set_index("alert_id")
    assert lv.loc[ids[0], "verdict"] == "true_positive"


def test_replay_api_default_model_follows_final_system(synth, monkeypatch):
    import copy
    import netirava.replay as R
    seen = []
    real = R.A0.load
    monkeypatch.setattr(R.A0, "load", staticmethod(lambda p: seen.append(str(p)) or real(p)))
    R.run(synth, mode="a0", run_id="fix_default", max_events=200)
    assert seen[-1].replace("\\", "/").endswith("/a0")
    cfg = copy.deepcopy(synth)
    cfg["final_system"] = {"model_dir": "a0"}
    R.run(cfg, mode="a0", run_id="fix_default2", max_events=200)
    assert seen[-1].replace("\\", "/").endswith("/a0")


def test_ui_provenance_guard_detects_wrong_stream(synth):
    from netirava.app import provenance_check
    from netirava.replay import run
    from netirava.storage import RunStore
    run(synth, mode="a0", run_id="fix_prov", max_events=200)
    meta = RunStore(synth, "fix_prov").meta()
    assert provenance_check(synth, meta)[0]
    assert not provenance_check(synth, {**meta, "stream_sha1": "0" * 40})[0]


def test_ui_reports_missing_run_instead_of_crashing(synth, tmp_path):
    import sys
    import yaml
    from streamlit.testing.v1 import AppTest
    from netirava import app as A
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({k: v for k, v in synth.items() if not k.startswith("_")}))
    old = sys.argv
    sys.argv = ["app", "--config", str(p), "--run", "no_such_run"]
    try:
        at = AppTest.from_file(A.__file__, default_timeout=60)
        at.run()
    finally:
        sys.argv = old
    assert not at.exception and any("not found" in e.value for e in at.error)
