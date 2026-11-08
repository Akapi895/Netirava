"""Alert triage interface (Streamlit).

    .venv\\Scripts\\python.exe -m netirava ui --run <run_id>

Tab "Review queue": active (A0) alerts of one replay run as review items. The unit is either a
source incident (source IP + 15-min cooldown, same rule as the evaluation) or a campaign (source
incidents linked by target host + predicted family, docs/protocols/ops_study_prereg.md §3). Items are ranked
per hour (top-B review queue) by family-aware severity or volume. `notified` is the runtime FIFO
budget decision and is shown apart from the queue rank.
Tab "Threshold reliability": the label-free drift monitor (docs/protocols/ops_study_prereg.md §4).
Analyst-facing: no ground-truth label is read here. Feedback is appended to alerts.db (append-only).
"""

import sys

import pandas as pd
import pyarrow.parquet as pq
import streamlit as st

from netirava import config as K
from netirava import features as F
from netirava.storage import RunStore
from netirava.triage import campaign_table, incident_table


def _args():
    a = dict(zip(sys.argv[1::2], sys.argv[2::2]))
    return a.get("--config", "configs/demo.yaml"), a.get("--run")


@st.cache_data(show_spinner=False)
def load(cfg_path, run_id):
    cfg = K.load(cfg_path)
    meta, inc, det = incident_table(cfg, run_id)
    camp = campaign_table(cfg, run_id, det)
    return cfg, meta, inc, det, camp


@st.cache_data(show_spinner=False)
def load_monitor(cfg_path, run_id):
    cfg = K.load(cfg_path)
    p = RunStore(cfg, run_id).dir / "DRIFT_MONITOR.parquet"
    return pd.read_parquet(p) if p.exists() else None


def flows_of(cfg, det, col, item_id, upto=None, limit=200):
    """Flows of one review item in decision order. upto (ms): only flows decided up to that time (the
    evidence the review queue saw). Returns (first `limit` rows, summary over ALL selected flows)."""
    sel = det[det[col] == item_id].sort_values("decision_at", kind="stable")
    n_life = len(sel)
    if upto is not None:
        sel = sel[sel.decision_at <= upto]
    summary = {"n_lifetime": n_life, "n_selected": len(sel), "n_shown": min(limit, len(sel)),
               "labels": sel.fine_label.value_counts(), "sources": sel.entity.nunique(), "targets": sel.dst.nunique()}
    ids = sel.flow_id.to_numpy()[:limit]
    cols = ["flow_id", F.DPORT, "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "FLOW_DURATION_MILLISECONDS"]
    s = pq.read_table(K.path(cfg, "derived") / "stream.parquet", columns=cols,
                      filters=[("flow_id", "in", ids.tolist())]).to_pandas()
    d = sel[sel.flow_id.isin(ids)][["flow_id", "decision_at", "entity", "dst", "a0_score", "a0_pred", "fine_label",
                                    "fine_label_status", "fine_confidence", "severity", "severity_source", "incident_id",
                                    "active_action", "active_reason"]]
    out = d.merge(s, on="flow_id").sort_values("decision_at", kind="stable")
    summary["dst_ports"] = out[F.DPORT].nunique()
    out["time_utc"] = pd.to_datetime(out.decision_at, unit="ms", utc=True).dt.strftime("%H:%M:%S")
    return out.drop(columns=["decision_at"]), summary


def provenance_check(cfg, meta):
    """The run must have been replayed on the derived data the opened config points to."""
    import json
    man = json.loads((K.path(cfg, "derived") / "manifest.json").read_text(encoding="utf-8"))
    return man.get("stream_sha1") == meta.get("stream_sha1"), man.get("stream_sha1"), meta.get("stream_sha1")


def queue_tab(cfg, run_id, meta, inc, det, camp):
    default_unit = cfg.get("ops", {}).get("ui_default_unit", "source incident")
    units = ["source incident", "campaign"]
    with st.sidebar:
        unit = st.radio("Review unit", units, index=units.index(default_unit),
                        help="campaign = source incidents hitting the same target with the same predicted family "
                             "within 15 min (causal). " + cfg.get("ops", {}).get("ui_campaign_note", ""))
        B = st.number_input("Review budget (items / hour)", 1, 500, 10)
        policy = st.radio("Queue order", ["severity", "volume", "fifo"],
                          help="severity = family-aware severity, then alerted flows (pre-declared)")
        per_hour = st.checkbox("Show only top-B per hour (review queue)", value=True)
    tab = inc if unit == "source incident" else camp
    if tab.empty:
        st.info("No alerted items in this run.")
        return
    seg = st.sidebar.multiselect("Segment", sorted(tab.segment.unique()), default=sorted(tab.segment.unique()))
    v = tab[tab.segment.isin(seg)]
    rank = f"queue_rank_{policy}"
    if per_hour:
        v = v[v[rank] <= int(B)]
    v = v.sort_values(["hour", rank])
    if unit == "source incident":
        show = ["alert_id", rank, "review_utc", "severity_at_review", "n_at_review", "severity", "n_flows", "severity_source",
                "entity", "n_targets", "predicted_family", "fine_label", "fine_label_status", "campaign_id", "campaign_size",
                "max_score", "opened_utc", "duration_min", "segment", "notified", "verdict"]
        st.caption("Rank uses only flows decided up to `review_utc` (`n_at_review`, `severity_at_review`); `n_flows` and "
                   "`severity` are lifetime totals. `notified` = runtime notification under the FIFO budget; it can differ "
                   "from the review rank. `verdict` = latest feedback entry.")
    else:
        show = ["update_id", "campaign_id", rank, "review_utc", "severity_at_review", "n_at_review", "severity", "n_flows", "n_sources", "n_source_incidents",
                "campaign_sources_total", "campaign_opened_utc", "n_targets", "top_target", "family", "fine_label", "sources",
                "max_score", "opened_utc", "duration_min", "segment"]
        st.caption("One row = a campaign update: the source incidents that joined one campaign in this hour. "
                   "A new source that joins an old campaign is reviewed in the hour it appears.")
    st.subheader(f"Queue ({len(v):,} {unit}s)")
    st.dataframe(v[[c for c in show if c in v.columns]], width="stretch", hide_index=True, height=360)
    if v.empty:
        return
    key = "alert_id" if unit == "source incident" else "update_id"
    sel = st.selectbox(f"Open {unit} ({key})", v[key].astype(int).tolist())
    row = v[v[key] == sel].iloc[0]
    col = "incident_id" if unit == "source incident" else "update_id"
    item = int(row.incident_id) if unit == "source incident" else int(sel)
    title = (f"Incident {item} — {row.entity} · {row.fine_label} · {int(row.n_flows):,} flows" if unit == "source incident"
             else f"Campaign {int(row.campaign_id)} update {item} — {int(row.n_sources)} new sources this hour "
                  f"({int(row.campaign_sources_total)} in campaign) → {row.top_target} · {row.family} · {int(row.n_flows):,} flows")
    st.subheader(title)
    if row.fine_label_status == "uncertain":
        st.info(f"Fine class withheld (top web class below tau = {cfg.get('family', {}).get('tau', 0.8)} of the Web family "
                f"mass). Severity uses the family, not the withheld class. Alert decision is unaffected.")
    at_review = st.toggle("Evidence at review time only", value=True,
                          help=f"Only flows decided up to {row.review_utc} UTC, i.e. what the queue ranked on.")
    fl, sm = flows_of(cfg, det, col, item, upto=int(row.review_at) if at_review else None)
    a, b = st.columns([2, 1])
    scope = "up to review time; " if at_review else ""
    a.caption(f"Showing the first {sm['n_shown']:,} of {sm['n_selected']:,} flows in decision order "
              f"({scope}{sm['n_lifetime']:,} over the lifetime of the item). Label counts, sources and targets on the "
              "right use all selected flows, not only the rows shown.")
    a.dataframe(fl, width="stretch", hide_index=True, height=300)
    b.write("**Family-aware labels**")
    b.bar_chart(sm["labels"])
    b.write(f"**Sources:** {sm['sources']} · **targets:** {sm['targets']} · **dst ports (shown rows):** {sm['dst_ports']}")
    b.caption("Evidence = flow facts and policy reasons; scores are decision scores, not calibrated probabilities.")
    alert_ids = (inc.loc[inc.incident_id.isin(det.loc[det.update_id == item, "incident_id"].unique()), "alert_id"]
                 .astype(int).tolist() if unit == "campaign" else [int(row.alert_id)])
    with st.form("fb"):
        stt = st.radio("Verdict", ["true_positive", "false_positive", "uncertain"], horizontal=True)
        lab = st.text_input("Attack label (optional)")
        who = st.text_input("Confirmed by", "analyst")
        if st.form_submit_button(f"Save feedback for {len(alert_ids)} alert(s) (append-only)"):
            store = RunStore(cfg, run_id)
            ids = [store.add_feedback(a_id, stt, "triage-ui:" + unit, who, lab or None)["feedback_id"] for a_id in alert_ids]
            st.success(f"feedback {ids[0]}–{ids[-1]} saved")
    fb = RunStore(cfg, run_id).feedback()
    if len(fb):
        st.caption("Feedback log (append-only; who, when, source). Feedback is stored for audit; it does not retrain "
                   "the model or change thresholds.")
        st.dataframe(fb.tail(20), width="stretch", hide_index=True)


def monitor_tab(cfg, run_id, meta):
    mon = load_monitor(cfg.get("_path"), run_id)
    a = str(cfg.get("ops", {}).get("drift", {}).get("primary_alpha", 0.001))
    st.caption(cfg.get("ops", {}).get("ui_monitor_note",
               "Label-free indicator: compares each 15-min window with the calibration window on which the alert "
               "threshold was locked. It never changes an alert. A warning means the threshold may not hold its target "
               "false-positive rate here; it is not proof of an attack or of false positives."))
    if mon is None:
        st.info(f"No monitor table for this run. Compute it with: python -m netirava drift-monitor --run {run_id}")
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Windows", len(mon))
    c2.metric("Threshold-reliability warnings", int(mon[f"TR_alarm@{a}"].sum()))
    c3.metric("Distribution-drift flags", int((mon.S_PSI_alarm | mon.F_PSI_alarm).sum()))
    seg = st.selectbox("Segment", sorted(mon.segment.unique()))
    m = mon[mon.segment == seg]
    st.line_chart(m.set_index("window_utc")[[f"TR@{a}", f"AR@{a}"]])
    st.dataframe(m[["window_utc", "status", "n_flows", f"alerts@{a}", f"AR@{a}", f"TR@{a}", f"FPR_est@{a}", "S_PSI",
                    "F_PSI_median", "F_PSI_n_major", "F_PSI_top"]], width="stretch", hide_index=True)
    st.caption("TR = flows just below the threshold vs the calibration window (ratio); AR = alerted flows vs alpha; "
               "S_PSI / F_PSI = score / feature distribution change (PSI). FPR_est = alpha x TR, NOT validated as an FPR "
               "estimate (docs/07_drift_monitoring.md). Alarms fire mostly on windows that contain attacks.")


def main():
    cfg_path, run_id = _args()
    st.set_page_config(page_title="Netirava triage", layout="wide")
    st.title("Netirava — alert triage")
    if not run_id:
        st.error("start with: python -m netirava ui --run <run_id>")
        return
    cfg, meta, inc, det, camp = load(cfg_path, run_id)
    ok, cfg_sha, run_sha = provenance_check(cfg, meta)
    if not ok:
        st.error(f"Provenance mismatch: run {run_id} was replayed on stream {str(run_sha)[:12]}, but the opened config "
                 f"({cfg_path}) points to stream {str(cfg_sha)[:12]}. Open the run with the config it was replayed with "
                 "(e.g. configs/ops_holdout.yaml for H5-H9 runs).")
        return
    st.caption(f"run {run_id} · A0 {meta['a0']['model_hash']} ({meta['a0'].get('model_dir') or 'a0'}) · threshold "
               f"{meta['a0']['threshold']:.4g} · policy {meta['policy']['version']} (source IP, cooldown "
               f"{meta['policy']['cooldown_ms']//60000} min, budget {meta['policy']['budget_per_hour']}/h) · "
               f"completed-flow replay, simulated response")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Alerted flows", f"{int(inc.n_flows.sum()):,}")
    c2.metric("Source incidents", f"{len(inc):,}")
    c3.metric("Campaigns (updates)", f"{camp.campaign_id.nunique() if len(camp) else 0:,} ({len(camp):,})")
    c4.metric("Flows per incident", f"{inc.n_flows.sum() / max(len(inc), 1):,.0f}")
    c5.metric("Rare-class incidents", f"{int(inc.rare_class.sum()):,}")
    t1, t2 = st.tabs(["Review queue", "Threshold reliability"])
    with t1:
        queue_tab(cfg, run_id, meta, inc, det, camp)
    with t2:
        monitor_tab(cfg, run_id, meta)


if __name__ == "__main__":
    main()
