"""Alert triage interface (Streamlit).

    .venv\\Scripts\\python.exe -m netirava ui --run <run_id>

Shows the active (A0) incidents of one replay run, grouped by source IP + cooldown
(same rule as the evaluation), ranked by priority = number of alerted flows (hourly
review queue). Analyst-facing: no ground-truth labels are read here. Feedback is
appended to the run's alerts.db (append-only).
"""

import sqlite3
import sys

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import streamlit as st

from netirava import config as K
from netirava import features as F
from netirava.storage import RunStore


FAMILY_TAU = 0.8   # family-aware output: fine web label only if its share of the Web family mass >= tau


def _args():
    a = dict(zip(sys.argv[1::2], sys.argv[2::2]))
    return a.get("--config", "configs/demo.yaml"), a.get("--run")


@st.cache_data(show_spinner=False)
def load(cfg_path, run_id):
    cfg = K.load(cfg_path)
    stx = RunStore(cfg, run_id)
    det = stx.detections()
    det = det[det.incident_id > 0]
    with sqlite3.connect(stx.db) as c:
        inc = pd.read_sql("SELECT * FROM incidents WHERE detector='a0'", c)
        alerts = pd.read_sql("SELECT alert_id, incident_id, status FROM alerts", c)
    meta = stx.meta()
    rare = set(cfg["a0"].get("rare_classes", []))
    from netirava.family import render
    classes = meta["a0"]["classes"]
    P = det[[f"p_{c}" for c in classes]].to_numpy()
    det = det.assign(fa_label=render(P, classes, {"Web": sorted(rare)}, FAMILY_TAU))
    g = det.groupby("incident_id")
    top = g.a0_pred.agg(lambda s: s.value_counts().index[0])
    summ = pd.DataFrame({"n_flows": g.size(), "max_score": g.a0_score.max(), "top_class": top,
                         "label_shown": g.fa_label.agg(lambda s: s.value_counts().index[0]),
                         "first": g.decision_at.min(), "last": g.decision_at.max(),
                         "rare_class": g.a0_pred.agg(lambda s: bool(set(s) & rare))})
    inc = inc.merge(summ, left_on="incident_id", right_index=True).merge(alerts, on="incident_id", how="left")
    inc["opened_utc"] = pd.to_datetime(inc["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:%M:%S")
    inc["duration_min"] = ((inc["last"] - inc["first"]) / 60000).round(1)
    inc["hour"] = pd.to_datetime(inc["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:00")
    sev = cfg.get("triage", {}).get("severity", {})
    inc["severity"] = inc.top_class.map(sev).fillna(4).astype(int)
    inc["priority"] = inc.n_flows
    return cfg, meta, inc.sort_values(["priority", "max_score"], ascending=False), det


def flows_of(cfg, det, incident_id, limit=200):
    ids = det.loc[det.incident_id == incident_id, "flow_id"].to_numpy()[:limit]
    cols = ["flow_id", F.DST, F.DPORT, "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "FLOW_DURATION_MILLISECONDS"]
    s = pq.read_table(K.path(cfg, "derived") / "stream.parquet", columns=cols,
                      filters=[("flow_id", "in", ids.tolist())]).to_pandas()
    d = det[det.flow_id.isin(ids)][["flow_id", "decision_at", "a0_pred", "a0_score", "active_action", "active_reason"]]
    out = d.merge(s, on="flow_id")
    out["time_utc"] = pd.to_datetime(out.decision_at, unit="ms", utc=True).dt.strftime("%H:%M:%S")
    return out.drop(columns=["decision_at"])


def main():
    cfg_path, run_id = _args()
    st.set_page_config(page_title="Netirava triage", layout="wide")
    st.title("Netirava — alert triage")
    if not run_id:
        st.error("start with: python -m netirava ui --run <run_id>")
        return
    cfg, meta, inc, det = load(cfg_path, run_id)
    st.caption(f"run {run_id} · A0 {meta['a0']['model_hash']} · threshold {meta['a0']['threshold']:.4g} · "
               f"policy {meta['policy']['version']} (source IP, cooldown {meta['policy']['cooldown_ms']//60000} min, "
               f"budget {meta['policy']['budget_per_hour']}/h) · completed-flow replay, simulated response")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerted flows", f"{int(inc.n_flows.sum()):,}")
    c2.metric("Incidents", f"{len(inc):,}")
    c3.metric("Flows per incident", f"{inc.n_flows.sum() / max(len(inc), 1):,.0f}")
    c4.metric("Rare-class incidents", f"{int(inc.rare_class.sum()):,}")
    with st.sidebar:
        seg = st.multiselect("Segment", sorted(inc.segment.unique()), default=sorted(inc.segment.unique()))
        cls = st.multiselect("Predicted class", sorted(inc.top_class.unique()), default=sorted(inc.top_class.unique()))
        rare_only = st.checkbox("Rare classes only")
        B = st.number_input("Review budget (incidents / hour)", 1, 500, 10)
        policy = st.radio("Queue order", ["severity", "volume"], help="severity = class severity, then alerted flows (pre-declared)")
        per_hour = st.checkbox("Show only top-B per hour (review queue)", value=True)
    v = inc[inc.segment.isin(seg) & inc.top_class.isin(cls)]
    if rare_only:
        v = v[v.rare_class]
    keys = ["severity", "priority"] if policy == "severity" else ["priority", "max_score"]
    if per_hour:
        v = v.sort_values(["hour"] + keys, ascending=[True, False, False]).groupby("hour").head(int(B))
    v = v.sort_values(keys, ascending=False)
    show = ["alert_id", "severity", "priority", "entity", "label_shown", "rare_class", "max_score", "opened_utc",
            "duration_min", "segment", "status"]
    st.subheader(f"Queue ({len(v):,} incidents)")
    st.dataframe(v[show], width="stretch", hide_index=True, height=360)
    if v.empty:
        return
    aid = st.selectbox("Open incident (alert_id)", v.alert_id.astype(int).tolist())
    row = v[v.alert_id == aid].iloc[0]
    st.subheader(f"Incident {int(row.incident_id)} — {row.entity} · {row.top_class} · {int(row.n_flows):,} flows")
    fl = flows_of(cfg, det, int(row.incident_id))
    a, b = st.columns([2, 1])
    a.dataframe(fl, width="stretch", hide_index=True, height=300)
    b.write("**Predicted classes**")
    b.bar_chart(fl.a0_pred.value_counts())
    b.write(f"**Destinations:** {fl[F.DST].nunique()} · **dst ports:** {fl[F.DPORT].nunique()}")
    b.caption("Evidence = flow facts and policy reasons; scores are decision scores, not calibrated probabilities.")
    with st.form("fb"):
        stt = st.radio("Verdict", ["true_positive", "false_positive", "uncertain"], horizontal=True)
        lab = st.text_input("Attack label (optional)")
        who = st.text_input("Confirmed by", "analyst")
        if st.form_submit_button("Save feedback (append-only)"):
            r = RunStore(cfg, run_id).add_feedback(int(aid), stt, "triage-ui", who, lab or None)
            st.success(f"feedback {r['feedback_id']} saved")
    fb = RunStore(cfg, run_id).feedback()
    if len(fb):
        st.caption("Feedback log")
        st.dataframe(fb.tail(20), width="stretch", hide_index=True)


if __name__ == "__main__":
    main()
