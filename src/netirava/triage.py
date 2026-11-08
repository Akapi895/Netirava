"""Flow-, incident- and campaign-level views of a replay run, shared by the triage UI and the export.

flow_table:     every alerted flow (or all flows) with score, alert flag, A0 argmax, the family-aware
                fields, family-aware severity and campaign id (computed with the same code at load for
                runs recorded before those fields existed).
incident_table: active (A0) source incidents from alerts.db (source IP + cooldown; ids, grouping and the
                runtime FIFO notification budget come from the replay policy) with the family-aware label,
                family-aware severity (+ its source), campaign id and the hourly review-queue ranks.
campaign_table: campaign updates (source incidents linked by target host + family, netirava.campaign;
                one review item = the source incidents that joined one campaign in one hour).
`notified` = runtime FIFO budget decision; `queue_rank_<policy>` = position in the hourly review queue.
They are different things and are shown separately. No ground-truth label is read.
"""

import sqlite3

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from netirava import campaign as C
from netirava import config as K
from netirava import family as FA
from netirava import features as F
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
    det["severity"], det["severity_source"] = FA.flow_severity(det, cfg)
    det["family"] = C.flow_family(det.predicted_family, det.fine_label_status)
    if "dst" not in det.columns:
        d = pq.read_table(K.path(cfg, "derived") / "stream.parquet", columns=["flow_id", F.DST],
                          filters=[("flow_id", "in", det.flow_id.tolist())] if alerted_only else None).to_pandas()
        det = det.merge(d.rename(columns={F.DST: "dst"}), on="flow_id", how="left")
    if "campaign_id" not in det.columns and "ops" in cfg:       # runs recorded before campaign correlation
        oc = cfg["ops"]["correlation"]
        m = det.incident_id > 0
        cid = np.zeros(len(det), np.int64)
        cid[m.to_numpy()] = C.assign(det[m].assign(src_incident=det.incident_id[m]), oc["cooldown_ms"], tuple(oc["key"]))
        det["campaign_id"] = cid
    det["src_incident"] = det.incident_id
    if "campaign_id" in det.columns:
        upd = np.zeros(len(det), np.int64)
        m = (det.campaign_id > 0).to_numpy()
        upd[m] = C.update_items(det[m], "campaign_id")
        det["update_id"] = upd
    return meta, det


def _queue_ranks(det, unit, budgets=(10,)):
    items, _ = C.review_queue(det[det[unit] > 0], unit, list(budgets))
    return items


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
                         "rare_class": g.a0_pred.agg(lambda s: bool(set(s) & rare)),
                         "severity": g.severity.max(),
                         "n_targets": g.dst.nunique(),
                         "campaign_id": g.campaign_id.first() if "campaign_id" in det else 0})
    # severity source of the flow that sets the incident severity (fine class / family / benign argmax)
    top = det.sort_values("severity", ascending=False, kind="stable").groupby("incident_id").severity_source.first()
    summ["severity_source"] = top
    summ = summ.join(FA.incident_labels(det))
    inc = inc.merge(summ, left_on="incident_id", right_index=True).merge(alerts, on="incident_id", how="left")
    inc["notified"] = inc.notified.astype(bool)
    inc["opened_utc"] = pd.to_datetime(inc["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:%M:%S")
    inc["duration_min"] = ((inc["last"] - inc["first"]) / 60000).round(1)
    inc["hour"] = pd.to_datetime(inc["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:00")
    items = _queue_ranks(det, "incident_id")
    for p in ("fifo", "volume", "severity"):
        inc[f"queue_rank_{p}"] = inc.incident_id.map(items[f"rank_{p}"]).astype("Int64")
    inc["priority"] = inc.n_flows
    if "campaign_id" in inc:
        sizes = det.groupby("campaign_id").incident_id.nunique()
        inc["campaign_size"] = inc.campaign_id.map(sizes).fillna(1).astype(int)
    return meta, inc.sort_values(["priority", "max_score"], ascending=False).reset_index(drop=True), det


def campaign_table(cfg, run_id, det=None):
    """Campaign updates of a run (one row = the source incidents that joined one campaign in one hour),
    ranked by the same review queue as source incidents (label-free)."""
    if det is None:
        _, det = flow_table(cfg, run_id)
    if "update_id" not in det.columns:
        return pd.DataFrame()
    d = det[det.update_id > 0]
    if d.empty:
        return pd.DataFrame()
    tab = C.campaign_table(d, "update_id")
    g = d.groupby("update_id")
    tab["campaign_id"] = g.campaign_id.first()
    cg = d.groupby("campaign_id")
    tab["campaign_sources_total"] = tab.campaign_id.map(cg.entity.nunique())
    tab["campaign_flows_total"] = tab.campaign_id.map(cg.size())
    tab["campaign_opened_utc"] = tab.campaign_id.map(cg.decision_at.min()).pipe(
        lambda x: pd.to_datetime(x, unit="ms", utc=True).dt.strftime("%m-%d %H:%M"))
    items = _queue_ranks(d, "update_id")
    for p in ("fifo", "volume", "severity"):
        tab[f"queue_rank_{p}"] = items[f"rank_{p}"]
    tab["severity"] = g.severity.max()
    tab["opened_utc"] = pd.to_datetime(tab["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:%M:%S")
    tab["hour"] = pd.to_datetime(tab["first"], unit="ms", utc=True).dt.strftime("%m-%d %H:00")
    tab["duration_min"] = ((tab["last"] - tab["first"]) / 60000).round(1)
    tab = tab.join(FA.incident_labels(d, "update_id")[["fine_label", "fine_label_status"]])
    return tab.reset_index().sort_values(["severity", "n_flows"], ascending=False).reset_index(drop=True)


def export(cfg, run_id):
    """Write runs/<run_id>/export/{flows_alerted.parquet, incidents.csv, campaigns.csv}."""
    meta, inc, det = incident_table(cfg, run_id)
    out = RunStore(cfg, run_id).dir / "export"
    out.mkdir(exist_ok=True)
    cols = ["flow_id", "segment", "entity", "dst", "available_at", "decision_at", "a0_score", "alert", "a0_pred",
            "incident_id", "campaign_id", "update_id", "severity", "severity_source"] + FA.FIELDS
    det[[c for c in cols if c in det.columns]].to_parquet(out / "flows_alerted.parquet", index=False)
    inc.to_csv(out / "incidents.csv", index=False)
    camp = campaign_table(cfg, run_id, det)
    camp.to_csv(out / "campaigns.csv", index=False)
    return {"flows_alerted": len(det), "incidents": len(inc), "campaigns": len(camp), "dir": str(out),
            "fine_label_status_flows": det.fine_label_status.value_counts().to_dict(),
            "fine_label_status_incidents": inc.fine_label_status.value_counts().to_dict(),
            "severity_source_incidents": inc.severity_source.value_counts().to_dict()}
