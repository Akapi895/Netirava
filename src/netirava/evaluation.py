"""Evaluator (the only module that joins runtime outputs with labels).

Scenarios are reported separately (never pooled):
  known-within-episode  closed-set metrics on known classes + binary metrics
  unknown-bot / unknown-web  held-out-class detection at the frozen threshold
  stress-infiltration   flagged labels, reported apart from claims
Episodes are PROXY episodes: same raw label + source IP, split when the gap
between consecutive flows exceeds evaluation.episode_gap_ms.
"""

import json

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, load_truth, window_bounds
from netirava.detectors import wilson
from netirava.storage import RunStore

HOUR = 3_600_000


def _binary(d):
    att = d.is_attack.to_numpy()
    cand = d.a0_candidate.to_numpy()
    nb, na = int((~att).sum()), int(att.sum())
    fp, tp = int((cand & ~att).sum()), int((cand & att).sum())
    return {"n_benign": nb, "n_attack": na, "attack_recall": tp / na if na else None,
            "attack_recall_wilson95": wilson(tp, na) if na else None,
            "benign_fpr": fp / nb if nb else None, "benign_fpr_wilson95": wilson(fp, nb) if nb else None,
            "candidates": int(cand.sum()), "alert_precision_flows": tp / (tp + fp) if tp + fp else None}


def _known(d, classes):
    kn = d[d[F.LABEL].isin(classes)]
    out = {}
    for c in classes:
        t, p = kn[F.LABEL] == c, kn.a0_pred == c
        tp = int((t & p).sum())
        pr = tp / p.sum() if p.sum() else 0.0
        rc = tp / t.sum() if t.sum() else 0.0
        out[c] = {"support": int(t.sum()), "precision": pr, "recall": rc,
                  "f1": 2 * pr * rc / (pr + rc) if pr + rc else 0.0}
    present = [c for c in classes if out[c]["support"]]
    conf = pd.crosstab(d[F.LABEL], d.a0_pred).to_dict(orient="index")
    return {"per_class": out, "macro_f1_present_classes": float(np.mean([out[c]["f1"] for c in present])),
            "classes_present": present, "confusion_true_by_pred": conf,
            "note": "argmax over known classes; rows whose true label is not a known class are in the confusion only"}


def episodes(d, gap_ms):
    a = d[d.is_attack].sort_values([F.LABEL, F.SRC, "available_at"])
    if a.empty:
        return pd.DataFrame()
    new = (a[F.LABEL] != a[F.LABEL].shift()) | (a[F.SRC] != a[F.SRC].shift()) | (a.available_at.diff() > gap_ms)
    a = a.assign(ep=new.cumsum())
    has_an = "an_would_alert" in a.columns
    rows = []
    for ep, g in a.groupby("ep"):
        c = g[g.a0_candidate]
        r = {"episode": int(ep), "label": g[F.LABEL].iat[0], "src": g[F.SRC].iat[0], "segment": g.segment.iat[0],
             "n_flows": len(g), "start": int(g.available_at.min()), "end": int(g.available_at.max()),
             "a0_detected": len(c) > 0, "a0_flow_recall": float(g.a0_candidate.mean()),
             "a0_ttfa_s": float((c.decision_at.min() - g.available_at.min()) / 1000) if len(c) else None,
             "a0_notified": bool(g.notified.any())}
        if has_an:
            s = g[g.an_would_alert]
            r.update(an_detected=len(s) > 0, an_flow_recall=float(g.an_would_alert.mean()),
                     an_ttfa_s=float((s.decision_at.min() - g.available_at.min()) / 1000) if len(s) else None)
        rows.append(r)
    return pd.DataFrame(rows)


def evaluate(cfg, run_id):
    st = RunStore(cfg, run_id)
    meta = st.meta()
    det = st.detections()
    truth = load_truth(cfg)
    meta_cols = load_stream(cfg)[["flow_id", F.SRC, F.DST]]
    d = det.merge(truth[["flow_id", F.LABEL, "label_quality", "unknown_to_model"]], on="flow_id", how="left",
                  validate="one_to_one").merge(meta_cols, on="flow_id", how="left", validate="one_to_one")
    assert d[F.LABEL].notna().all()
    d["is_attack"] = d[F.LABEL] != "Benign"
    import sqlite3
    with sqlite3.connect(st.db) as c:
        incs = pd.read_sql("SELECT incident_id, notified, open_reason, n_candidates, detector, segment FROM incidents", c)
    notified_ids = set(incs.loc[(incs.detector == "a0") & (incs.notified == 1), "incident_id"])
    d["notified"] = d.incident_id.isin(notified_ids) & (d.incident_id > 0)
    scen = {w["id"]: w["scenario"] for w in window_bounds(cfg)}
    d["scenario"] = d.segment.map(scen)
    classes = meta["a0"]["classes"]
    has_an = "an_would_alert" in d.columns
    rep = {"run_id": run_id, "mode": meta["mode"], "a0_model": meta["a0"]["model_hash"],
           "anomaly_model": (meta["anomaly"] or {}).get("model_hash"), "scenarios": {}}
    gap = int(cfg["evaluation"]["episode_gap_ms"])
    all_eps = []
    for sc_name, g in d.groupby("scenario"):
        r = {"segments": sorted(g.segment.unique().tolist()), "n_flows": len(g),
             "labels": g[F.LABEL].value_counts().to_dict(), "binary": _binary(g)}
        att_src = set(g.loc[g.is_attack, F.SRC])
        ben = g[~g.is_attack]
        same = ben[F.SRC].isin(att_src) | ben[F.DST].isin(att_src)
        r["benign_fpr_same_host"] = {"n": int(same.sum()), "fpr": float(ben.a0_candidate[same].mean()) if same.any() else None,
                                     "wilson95": wilson(int(ben.a0_candidate[same].sum()), int(same.sum())) if same.any() else None,
                                     "definition": "benign flows whose src or dst is a source IP of an attack flow in the same scenario"}
        r["benign_fpr_control_hosts"] = {"n": int((~same).sum()), "fpr": float(ben.a0_candidate[~same].mean()) if (~same).any() else None}
        r["attack_recall_by_label"] = {lab: {"n": int(len(x)), "a0_recall": float(x.a0_candidate.mean()),
                                             "a0_pred_top": x.a0_pred.value_counts().head(3).to_dict(),
                                             **({"an_recall": float(x.an_would_alert.mean())} if has_an else {})}
                                       for lab, x in g[g.is_attack].groupby(F.LABEL)}
        if sc_name.startswith("known"):
            r["known_class"] = _known(g, classes)
        eps = episodes(g, gap)
        if len(eps):
            eps["scenario"] = sc_name
            all_eps.append(eps)
            r["episodes"] = {"n": len(eps), "a0_detected": int(eps.a0_detected.sum()), "a0_notified": int(eps.a0_notified.sum()),
                             "a0_ttfa_s_median": float(eps.a0_ttfa_s.dropna().median()) if eps.a0_detected.any() else None,
                             "by_label": eps.groupby("label").agg(n=("episode", "size"), a0_detected=("a0_detected", "sum"),
                                                                    a0_notified=("a0_notified", "sum")).to_dict(orient="index")}
            if has_an:
                miss = ~eps.a0_detected
                r["episodes"].update(an_detected=int(eps.an_detected.sum()),
                                     missed_by_a0_caught_by_shadow=int((miss & eps.an_detected).sum()),
                                     missed_by_both=int((miss & ~eps.an_detected).sum()))
        if has_an:
            a = g.is_attack.to_numpy()
            c0, c1 = g.a0_candidate.to_numpy(), g.an_would_alert.to_numpy()
            r["shadow"] = {"attack_flows_missed_by_a0_flagged_by_shadow": int((a & ~c0 & c1).sum()),
                           "attack_flows_missed_by_a0": int((a & ~c0).sum()),
                           "benign_shadow_alerts": int((~a & c1).sum()),
                           "benign_shadow_alerts_not_flagged_by_a0": int((~a & c1 & ~c0).sum()),
                           "benign_shadow_fpr": float(c1[~a].mean()) if (~a).any() else None,
                           "overlap_jaccard_attack": _jac(c0[a], c1[a]), "overlap_jaccard_benign": _jac(c0[~a], c1[~a]),
                           "status_counts": g.an_status.value_counts().to_dict()}
        # operations
        hours = (g.decision_at // HOUR)
        n_hours = max(1, hours.nunique())
        gi = incs[(incs.detector == "a0") & (incs.segment.isin(r["segments"]))]
        r["operations"] = {"event_hours_covered": int(n_hours),
                           "candidates_per_hour": float(g.a0_candidate.sum() / n_hours),
                           "incidents": int(len(gi)), "notifications": int(gi.notified.sum()),
                           "notifications_per_hour": float(gi.notified.sum() / n_hours),
                           "suppressed_cooldown_dedup": int((g.active_reason == "cooldown_dedup").sum()),
                           "incidents_suppressed_budget": int((gi.open_reason == "budget_exceeded").sum()),
                           "batching_delay_ms_p50": float(np.percentile(g.batching_delay_ms, 50)),
                           "batching_delay_ms_p95": float(np.percentile(g.batching_delay_ms, 95))}
        if has_an:
            si = incs[(incs.detector == "anomaly") & (incs.segment.isin(r["segments"]))]
            r["operations"]["shadow_incidents_per_hour"] = float(len(si) / n_hours)
        r["label_quality"] = g.label_quality.value_counts().to_dict()
        rep["scenarios"][sc_name] = r
    if all_eps:
        pd.concat(all_eps).to_csv(st.dir / "episodes.csv", index=False)
    rep["runtime"] = {k: meta[k] for k in ("events", "event_time_span_s", "wall_seconds", "throughput_events_per_wall_s",
                                           "a0_compute_us_per_event", "shadow_compute_us_per_event", "peak_rss_mb",
                                           "shadow_status_counts", "degraded", "paced_max_lag_s", "paced_p95_lag_s")}
    rep["feedback_rows"] = len(st.feedback())
    (st.dir / "EVALUATION.json").write_text(json.dumps(rep, indent=2, default=_js))
    return _summary(rep)


def _jac(a, b):
    u = int((a | b).sum())
    return float((a & b).sum() / u) if u else None


def _js(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return str(o)


def _summary(rep):
    s = {"run_id": rep["run_id"], "mode": rep["mode"], "runtime": rep["runtime"]}
    for k, v in rep["scenarios"].items():
        b = v["binary"]
        s[k] = {"flows": v["n_flows"], "attack_recall": b["attack_recall"], "benign_fpr": b["benign_fpr"],
                "alert_precision_flows": b["alert_precision_flows"], "episodes": {x: v.get("episodes", {}).get(x) for x in
                ("n", "a0_detected", "a0_notified", "an_detected", "missed_by_a0_caught_by_shadow")},
                "notifications_per_hour": v["operations"]["notifications_per_hour"]}
        if "known_class" in v:
            s[k]["known_macro_f1"] = v["known_class"]["macro_f1_present_classes"]
        if "shadow" in v:
            s[k]["shadow_benign_fpr"] = v["shadow"]["benign_shadow_fpr"]
    return s


# --------------------------------------------------------------------------- imbalance ablation (output a)
def ablate_imbalance(cfg, variants=("a0", "a1", "a2"), boot_reps=1000, seed=2027):
    """Known-class (within-episode) per-class metrics of the imbalance variants on known_replay flows.
    a0 = deployed recipe (pre-declared); a1/a2 are ablations, NOT selected on this data.
    Thresholds for the binary view are calibrated per variant on C1 benign. Delta of the rare-class
    macro-F1 vs a0 uses a bootstrap over source IPs (attackers and benign hosts)."""
    from netirava.dataset import training_frame
    from netirava.detectors import A0, threshold_at_fpr
    classes = list(cfg["a0"]["known_classes"])
    rare = list(cfg["a0"]["rare_classes"])
    levels = cfg["decision"]["fpr_levels"]
    ev = load_stream(cfg, roles=["known_replay"])
    truth = load_truth(cfg)[["flow_id", F.LABEL]]
    ev = ev.merge(truth, on="flow_id", validate="one_to_one")
    cal = training_frame(cfg, ["calibration"])
    y = ev[F.LABEL].to_numpy()
    X, Xc = F.matrix(ev), F.matrix(cal)
    cb = cal[F.LABEL].to_numpy() == "Benign"
    ent = pd.factorize(ev[F.SRC])[0]
    rep = {"rows": len(ev), "support": ev[F.LABEL].value_counts().to_dict(), "variants": {}}
    preds = {}
    for v in variants:
        m = A0.load(K.path(cfg, "models") / v)
        P, att, pr = m.score(X)
        pred = np.asarray(m.classes, dtype=object)[pr]
        preds[v] = pred
        sc_cal = m.score(Xc)[1]
        r = {"model_hash": m.version, "smote": m.meta["smote"].get("applied"), "variant_config": m.meta.get("variant_config"),
             "per_class": {}, "binary": {}}
        for c in classes:
            t, p = y == c, pred == c
            tp = int((t & p).sum())
            P_, R_ = (tp / p.sum() if p.sum() else 0.0), (tp / t.sum() if t.sum() else 0.0)
            r["per_class"][c] = {"support": int(t.sum()), "precision": P_, "recall": R_,
                                 "f1": 2 * P_ * R_ / (P_ + R_) if P_ + R_ else 0.0, "recall_wilson95_rowiid": wilson(tp, int(t.sum())),
                                 "predicted_as": pd.Series(pred[t]).value_counts().head(3).to_dict() if c in rare else None}
        r["macro_f1_known"] = float(np.mean([r["per_class"][c]["f1"] for c in classes]))
        r["macro_f1_rare"] = float(np.mean([r["per_class"][c]["f1"] for c in rare]))
        for a in levels:
            thr, _ = threshold_at_fpr(sc_cal[cb], a)
            al = att >= thr
            ben = y == "Benign"
            r["binary"][str(a)] = {"threshold": thr, "benign_fpr_known_replay": float(al[ben].mean()),
                                   "attack_recall": float(al[~ben].mean()),
                                   "rare_recall": {c: float(al[y == c].mean()) for c in rare}}
        rep["variants"][v] = r
    # bootstrap over source entities: delta macro-F1 on rare classes vs a0
    def rare_f1(pred, w):
        out = []
        for c in rare:
            t, p = (y == c), (pred == c)
            tp, ps, ts = (w * (t & p)).sum(), (w * p).sum(), (w * t).sum()
            out.append(2 * tp / (ps + ts) if ps + ts else 0.0)
        return np.mean(out)
    rng = np.random.default_rng(seed)
    G = ent.max() + 1
    for v in variants:
        if v == "a0":
            continue
        d = []
        for _ in range(boot_reps):
            w = np.bincount(rng.integers(0, G, G), minlength=G)[ent].astype(float)
            d.append(rare_f1(preds[v], w) - rare_f1(preds["a0"], w))
        rep["variants"][v]["delta_macro_f1_rare_vs_a0"] = {
            "point": rep["variants"][v]["macro_f1_rare"] - rep["variants"]["a0"]["macro_f1_rare"],
            "ci95_source_ip_bootstrap": [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))], "n_sources": int(G)}
    out = K.path(cfg, "runs") / "ablate_imbalance.json"
    out.write_text(json.dumps(rep, indent=2, default=_js), encoding="utf-8")
    return rep
