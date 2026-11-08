"""Flow- and incident-level views of a replay run, shared by the triage UI and the export.

flow_table:     every alerted flow (or all flows) with score, alert flag, A0 argmax and the
                family-aware fields (stored in detections.parquet since the family-aware
                integration; computed with the same netirava.family code for older runs).
incident_table: active (A0) incidents from alerts.db with the family-aware incident label,
                severity and priority. Incident ids, grouping and notification budget come
                from the replay policy and are not recomputed here.
No ground-truth label is read.
"""

import sqlite3

import numpy as np
import pandas as pd

from netirava import family as FA
from netirava.storage import RunStore


def flow_table(cfg, run_id, alerted_only=True):
    st = RunStore(cfg, run_id)
    meta = st.meta()
    det = st.detections()
    if alerted_only:
        det = det[det.incident_id > 0].copy()
    if "fine_label" not in det.columns:                          # runs recorded before the integration
        det = det.join(FA.annotate_frame(det, meta["a0"]["classes"], cfg))
        det.attrs["family_fields"] = "computed at load (run predates family-aware integration)"
    det["alert"] = det.a0_candidate if "a0_candidate" in det else det.a0_score >= meta["a0"]["threshold"]
    return meta, det


def incident_table(cfg, run_id):
    meta, det = flow_table(cfg, run_id)
    st = RunStore(cfg, run_id)
    with sqlite3.connect(st.db) as c:
        inc = pd.read_sql("SELECT * FROM incidents WHERE detector='a0'", c)
        alerts = pd.read_sql("SELECT alert_id, incident_id, status FROM alerts", c)
    rare = set(cfg["a0"].get("rare_classes", []))
    g = det.groupby("incident_id")
    summ = pd.DataFrame({"n_flows": g.size(), "max_score": g.a0_score.max(),
                         "top_class": g.a0_pred.agg(lambda s: s.value_counts().index[0]),
                         "first": g.decision_at.min(), "last": g.decision_at.max(),
                         "rare_class": g.a0_pred.agg(lambda s: bool(set(s) & rare))})
    summ = summ.join(FA.incident_labels(det))
    inc = inc.merge(summ, left_on="incident_id", right_index=True).merge(alerts, on="incident_id", how="left")
    inc["opened_utc"] = pd.to_datetime(inc["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:%M:%S")
    inc["duration_min"] = ((inc["last"] - inc["first"]) / 60000).round(1)
    inc["hour"] = pd.to_datetime(inc["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:00")
    sev = cfg.get("triage", {}).get("severity", {})
    inc["severity"] = inc.top_class.map(sev).fillna(4).astype(int)
    inc["priority"] = inc.n_flows
    return meta, inc.sort_values(["priority", "max_score"], ascending=False).reset_index(drop=True), det


def export(cfg, run_id):
    """Write runs/<run_id>/export/{flows_alerted.parquet, incidents.csv}."""
    meta, inc, det = incident_table(cfg, run_id)
    out = RunStore(cfg, run_id).dir / "export"
    out.mkdir(exist_ok=True)
    cols = ["flow_id", "segment", "entity", "available_at", "decision_at", "a0_score", "alert", "a0_pred",
            "incident_id"] + FA.FIELDS
    det[cols].to_parquet(out / "flows_alerted.parquet", index=False)
    inc.to_csv(out / "incidents.csv", index=False)
    return {"flows_alerted": len(det), "incidents": len(inc), "dir": str(out),
            "fine_label_status_flows": det.fine_label_status.value_counts().to_dict(),
            "fine_label_status_incidents": inc.fine_label_status.value_counts().to_dict()}
