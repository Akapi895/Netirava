"""Ops study evaluator (docs/OPS_STUDY_PREREG.md): incident correlation (RQ-C), drift monitoring
(RQ-D) and the model comparison on fresh holdouts (RQ-M). This is the only ops module that reads
labels; the runtime parts (campaign.py, drift.py) are label-free.

Label sets: 'original' (NF-v3) and 'corrected' (CNS2022 rules; attempted/indeterminate rows are
excluded, i.e. neither attack nor benign; days outside the audit keep the original label).
"""

import json

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy.stats import spearmanr

from netirava import campaign as C
from netirava import config as K
from netirava import drift as D
from netirava import family as FA
from netirava import features as F
from netirava.dataset import load_truth, window_bounds
from netirava.decision import _episodes, incidents
from netirava.detectors import wilson
from netirava.storage import RunStore

HOUR = C.HOUR_MS
UNITS = ("source", "campaign", "campaign_dst_only")


def _js(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return None if np.isnan(o) else float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, (set, tuple)):
        return list(o)
    return str(o)


def labels(cfg):
    """flow_id -> label per label set (None = excluded)."""
    t = load_truth(cfg).set_index("flow_id")[F.LABEL]
    out = {"original": t}
    p = K.path(cfg, "derived") / "truth_cns2022.parquet"
    if p.exists():
        c = pd.read_parquet(p).set_index("flow_id")
        out["corrected"] = c.label_corrected.where(~c.status.isin(["attempted", "indeterminate"])).reindex(t.index)
    return out


def run_frame(cfg, run_id):
    """All flows of a run with family fields, severity and destination (label-free)."""
    st = RunStore(cfg, run_id)
    meta = st.meta()
    det = st.detections()
    if "fine_label" not in det.columns:
        det = det.join(FA.annotate_frame(det, meta["a0"]["classes"], cfg))
    keep = ["flow_id", "segment", "entity", "available_at", "decision_at", "a0_score", "a0_candidate", "a0_pred",
            "incident_id", "predicted_family", "fine_label", "fine_label_status"]
    det = det[keep].copy()
    dst = pq.read_table(K.path(cfg, "derived") / "stream.parquet", columns=["flow_id", F.DST]).to_pandas()
    det = det.merge(dst.rename(columns={F.DST: "dst"}), on="flow_id", how="left", validate="one_to_one")
    det["severity"], det["severity_source"] = FA.flow_severity(det, cfg)
    det["family"] = C.flow_family(det.predicted_family, det.fine_label_status)
    return meta, det


def thresholds(cfg, meta):
    ref = D.load_reference(cfg, meta["a0"].get("model_dir") or "a0")
    assert ref["model_hash"] == meta["a0"]["model_hash"]
    t = {float(a): lv["t"] for a, lv in ref["levels"].items()}
    locked = float(cfg["a0"]["target_fpr"])
    assert abs(t[locked] - meta["a0"]["threshold"]) < 1e-9, "reference threshold != locked model threshold"
    return t


def alerted(cfg, det, thr, alpha):
    """Alerted flows at level alpha with source incidents (same rule as the runtime policy) and campaigns."""
    oc = cfg["ops"]["correlation"]
    al_mask = det.a0_score.to_numpy() >= thr
    locked = alpha == float(cfg["a0"]["target_fpr"])
    if locked:
        assert (al_mask == det.a0_candidate.to_numpy()).all(), "stored candidates != locked threshold"
    inc = incidents(det, al_mask, int(cfg["policy"]["cooldown_ms"]))
    al = det[al_mask].copy()
    al["src_incident"] = inc[al_mask]
    if locked:   # offline grouping must be the runtime grouping (same partition)
        pairs = al[["src_incident", "incident_id"]].drop_duplicates()
        assert pairs.src_incident.is_unique and pairs.incident_id.is_unique, "offline incidents != runtime incidents"
    al["source"] = al.src_incident
    al["campaign"] = C.assign(al, oc["cooldown_ms"], tuple(oc["key"]))
    al["campaign_dst_only"] = C.assign(al, oc["cooldown_ms"], tuple(oc["ablation_keys"][0]))
    return al


# --------------------------------------------------------------------------- RQ-C
def unit_metrics(al, unit, ctx, budgets, policies):
    items, sel = C.review_queue(al, unit, budgets, policies)
    n_items = len(items)
    has_att = al.groupby(unit).att.any() if n_items else pd.Series(dtype=bool)
    false_item = (~has_att) & al.groupby(unit).ben.any() if n_items else pd.Series(dtype=bool)
    r = {"items": n_items, "items_per_hour": n_items / ctx["hours"],
         "false_items_per_hour": float(false_item.sum() / ctx["hours"]) if n_items else 0.0,
         "flows_per_item": len(al) / n_items if n_items else None,
         "fragmentation_items_per_attack_type": (al[al.att].groupby("atype")[unit].nunique().to_dict() if n_items else {}),
         "queue": {}}
    rev_at = items.review_at if n_items else pd.Series(dtype=float)
    for (p, B), S in sel.items():
        rv = al[al[unit].isin(S)]
        att = rv[rv.att]
        strict = att[att.decision_at.to_numpy() <= att[unit].map(rev_at).to_numpy()]
        q = {"reviewed": len(S), "reviewed_precision": float(has_att.loc[list(S)].mean()) if S else None}
        if ctx["n_ep"]:
            eps_s, eps_c = set(strict.ep[strict.ep >= 0]), set(att.ep[att.ep >= 0])
            q["episode_coverage_strict"] = len(eps_s) / ctx["n_ep"]
            q["episode_coverage_case"] = len(eps_c) / ctx["n_ep"]
            q["risk_weighted_coverage_strict"] = float(ctx["ep_w"].reindex(list(eps_s)).sum() / ctx["ep_w"].sum())
            q["attack_flow_coverage_case"] = len(att) / ctx["n_att"]
            types_s = set(strict.atype)
            q["attack_types_covered_strict"] = sorted(types_s)
            q["attack_type_coverage_strict"] = len(types_s) / len(ctx["types"])
            first_rev = strict.assign(r=strict[unit].map(rev_at)).groupby("atype").r.min()
            q["time_to_review_s"] = {k: float((v - ctx["type_first"][k]) / 1000) for k, v in first_rev.items()}
        r["queue"][f"{p}@{B}"] = q
    return r


def correlation_quality(al):
    src = al.groupby("source").agg(att=("att", "any"), ben=("ben", "any"), camp=("campaign", "first"))
    camp_att = al.groupby("campaign").att.any()
    ben_src = src[~src.att & src.ben]
    absorbed = ben_src.camp.map(camp_att).fillna(False)
    g = al.groupby("campaign")
    n_src = g.entity.nunique()
    lab_n = al[al.att].groupby("campaign").lab.nunique()
    return {"benign_only_source_incidents": int(len(ben_src)),
            "benign_source_incidents_in_attack_campaigns": int(absorbed.sum()),
            "contamination_share": float(absorbed.mean()) if len(ben_src) else 0.0,
            "campaigns": int(g.ngroups), "multi_source_campaigns": int((n_src >= 2).sum()),
            "max_sources_per_campaign": int(n_src.max()) if len(n_src) else 0,
            "multi_source_campaigns_benign_only": int(((n_src >= 2) & ~camp_att.reindex(n_src.index, fill_value=False)).sum()),
            "over_merged_campaigns": int((lab_n >= 2).sum()),
            "benign_alerted_flows_in_attack_items": {
                u: float(al[al.ben & al[u].map(al.groupby(u).att.any())].shape[0] / max(al.ben.sum(), 1)) for u in UNITS}}


def scenario_context(g, lab, cfg):
    """Ground-truth context of one scenario: episodes, attack types, impact weights."""
    w_imp = cfg["ops"]["impact_weight"]
    tax = cfg["labels"]["taxonomy"]
    d = g[["flow_id", "segment", "entity", "decision_at"]].copy()
    d[F.LABEL] = d.flow_id.map(lab)
    d = d[d[F.LABEL].notna()]
    d["is_attack"] = d[F.LABEL] != "Benign"
    ep = _episodes(d, 1_800_000)
    epv = pd.Series(-1, index=d.index)
    epv.loc[ep.index] = ep.values
    d["ep"] = epv
    a = d[d.is_attack]
    ep_lab = a.groupby("ep")[F.LABEL].first()
    ctx = {"hours": max(1, int((g.decision_at // HOUR).nunique())), "n_ep": int(a.ep.nunique()), "n_att": int(len(a)),
           "ep_w": ep_lab.map(lambda l: w_imp.get(tax.get(l, l), 3)).astype(float),
           "types": sorted((a.segment + "|" + a[F.LABEL]).unique().tolist())}
    ctx["type_first"] = a.assign(t=a.segment + "|" + a[F.LABEL]).groupby("t").decision_at.min().to_dict()
    return d.set_index("flow_id")[[F.LABEL, "is_attack", "ep"]], ctx


def correlation_run(cfg, run_id, label_sets=("original", "corrected")):
    oc = cfg["ops"]
    meta, det = run_frame(cfg, run_id)
    thr = thresholds(cfg, meta)
    scen = {w["id"]: w["scenario"] for w in window_bounds(cfg)}
    det["scenario"] = det.segment.map(scen)
    labs = labels(cfg)
    budgets, policies = oc["queue"]["budgets"], oc["queue"]["policies"]
    out = {"run_id": run_id, "model": meta["a0"]["model_hash"], "model_dir": meta["a0"].get("model_dir") or "a0",
           "levels": {}}
    for alpha in oc["queue"]["alphas"]:
        al_all = alerted(cfg, det, thr[alpha], alpha)
        lv = {}
        for sc, g in det.groupby("scenario"):
            al_s = al_all[al_all.scenario == sc]
            res = {}
            for ls in label_sets:
                if ls not in labs:
                    continue
                truth, ctx = scenario_context(g, labs[ls], cfg)
                # left join: the queue never depends on labels; excluded rows are neither attack nor benign
                al = al_s.join(truth, on="flow_id", how="left").rename(columns={F.LABEL: "lab", "is_attack": "att"})
                al["ben"] = al.lab == "Benign"
                al["att"] = al.att.fillna(False).astype(bool)
                al["ep"] = al.ep.fillna(-1).astype(np.int64)
                al["atype"] = np.where(al.att, al.segment + "|" + al.lab.astype(str), None)
                ben_n = int((~truth.is_attack).sum())
                fp = int(al.ben.sum())
                r = {"flow": {"n_benign": ben_n, "fp": fp, "benign_fpr": fp / ben_n if ben_n else None,
                              "benign_fpr_wilson95": wilson(fp, ben_n), "alerted_flows": int(len(al)),
                              "attack_recall_by_label": {k: float(v) for k, v in
                                                         (al[al.att].groupby("lab").size() /
                                                          truth[truth.is_attack].groupby(F.LABEL).size()).fillna(0).items()}},
                     "hours": ctx["hours"], "episodes": ctx["n_ep"], "attack_types": ctx["types"], "units": {}}
                for u in UNITS:
                    r["units"][u] = unit_metrics(al, u, ctx, budgets, policies)
                r["correlation_quality"] = correlation_quality(al) if len(al) else None
                res[ls] = r
            lv[sc] = res
        out["levels"][str(alpha)] = lv
    return out


# --------------------------------------------------------------------------- RQ-D
def drift_windows(cfg, run_id, tab=None):
    """Monitor table of a run joined with the realized benign FPR per window (evaluator)."""
    dc = cfg["ops"]["drift"]
    st = RunStore(cfg, run_id)
    meta = st.meta()
    tab = tab if tab is not None else (pd.read_parquet(st.dir / "DRIFT_MONITOR.parquet")
                                       if (st.dir / "DRIFT_MONITOR.parquet").exists() else D.monitor_run(cfg, run_id))
    ref = D.load_reference(cfg, meta["a0"].get("model_dir") or "a0")
    det = st.detections(columns=["flow_id", "segment", "decision_at", "a0_score"])
    win, _ = D.windows_of(det, int(dc["window_ms"]), int(dc["min_flows"]))
    det["window"] = win
    det = det[det.window.notna()]
    scoped = {w["id"] for w in window_bounds(cfg) if w.get("scope_hosts")}
    rows = []
    for ls, lab in labels(cfg).items():
        d = det.assign(lab=det.flow_id.map(lab))
        d = d[d.lab.notna()]
        ben = d.lab == "Benign"
        for a, lv in ref["levels"].items():
            al = d.a0_score >= lv["t"]
            g = pd.DataFrame({"window": d.window, "ben": ben, "fp": al & ben, "att": ~ben}).groupby("window").sum()
            for w, x in g.iterrows():
                rows.append({"window": w, "label_set": ls, "alpha": float(a), "n_benign": int(x.ben), "fp": int(x.fp),
                             "n_attack": int(x.att), "fpr": x.fp / x.ben if x.ben else np.nan})
    gt = pd.DataFrame(rows)
    sig = []
    for a in ref["levels"]:
        s = tab[["window", "segment", "window_utc", f"AR@{a}", f"TR@{a}", f"FPR_est@{a}", f"AR_alarm@{a}", f"TR_alarm@{a}",
                 "S_PSI", "F_PSI_median", "S_PSI_alarm", "F_PSI_alarm", "F_PSI_top"]].copy()
        s.columns = [c.split("@")[0] for c in s.columns]
        s["alpha"] = float(a)
        sig.append(s)
    sig = pd.concat(sig)
    out = gt.merge(sig, on=["window", "alpha"], how="inner")
    out["run_id"], out["model_dir"] = run_id, meta["a0"].get("model_dir") or "a0"
    out["scope_mismatch"] = out.segment.isin(scoped)
    out["evaluable"] = out.n_benign >= dc["min_benign_eval"]
    out["E"] = out.evaluable & (out.fpr > dc["exceed_factor"] * out.alpha)
    out["window_type"] = np.where(out.n_attack > 0, "attack", "benign_only")
    return out


def _auc(y, s):
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s)) if 0 < y.sum() < len(y) else None


def drift_summary(win, cfg, reps=2000, seed=2027):
    """RQ-D metrics on a pool of windows (evaluable, not scope-mismatched), per label set and alpha."""
    dc = cfg["ops"]["drift"]
    rng = np.random.default_rng(seed)
    out = {}
    for (ls, a), g in win[win.evaluable & ~win.scope_mismatch].groupby(["label_set", "alpha"]):
        fpr_c = (g.fp + 0.5) / g.n_benign
        r = {"windows": int(len(g)), "E_windows": int(g.E.sum()), "benign_only_windows": int((g.window_type == "benign_only").sum()),
             "realized_fpr_range": [float(g.fpr.min()), float(g.fpr.max())], "signals": {}}
        for s in ("TR", "AR", "S_PSI", "F_PSI_median"):
            x = g[s].to_numpy(float)
            rho = spearmanr(x, g.fpr).statistic if len(g) > 2 else np.nan
            boots = []
            for _ in range(reps if len(g) > 3 else 0):
                i = rng.integers(0, len(g), len(g))
                if np.unique(x[i]).size > 1 and np.unique(g.fpr.to_numpy()[i]).size > 1:
                    boots.append(spearmanr(x[i], g.fpr.to_numpy()[i]).statistic)
            alarm_col = {"TR": "TR_alarm", "AR": "AR_alarm", "S_PSI": "S_PSI_alarm", "F_PSI_median": "F_PSI_alarm"}[s]
            al = g[alarm_col].astype(bool)
            nonE = ~g.E
            r["signals"][s] = {
                "spearman": float(rho), "spearman_ci95": [float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))] if boots else None,
                "auroc_E": _auc(g.E.to_numpy(), x),
                "alarm_recall_E": float(al[g.E].mean()) if g.E.any() else None,
                "false_alarm_rate_nonE": float(al[nonE].mean()) if nonE.any() else None,
                "false_alarm_rate_nonE_benign_only": float(al[nonE & (g.window_type == "benign_only")].mean())
                if (nonE & (g.window_type == "benign_only")).any() else None,
                "false_alarm_rate_nonE_attack": float(al[nonE & (g.window_type == "attack")].mean())
                if (nonE & (g.window_type == "attack")).any() else None,
                "alarms": int(al.sum())}
        err = np.abs(np.log10(np.maximum(g.FPR_est, 1e-6)) - np.log10(fpr_c))
        r["fpr_estimate_log10_abs_error_median"] = float(np.median(err))
        r["fpr_estimate_within_2x_share"] = float((err <= np.log10(2)).mean())
        gr = dc["go_rules"]
        tr = r["signals"]["TR"]
        r["go"] = {"spearman_ok": bool(tr["spearman"] >= gr["spearman_min"] and tr["spearman_ci95"] and tr["spearman_ci95"][0] > 0),
                   "alarm_ok": (None if r["E_windows"] < gr["min_events"] else
                                bool((tr["alarm_recall_E"] or 0) >= gr["recall_min"] and (tr["false_alarm_rate_nonE"] or 0) <= gr["false_alarm_max"])),
                   "alarm_status": "INCONCLUSIVE (E windows < %d)" % gr["min_events"] if r["E_windows"] < gr["min_events"] else "evaluated"}
        out[f"{ls}@{a}"] = r
    return out


# --------------------------------------------------------------------------- GO rules
def correlation_go(results, cfg, scenario_benefit, label_set="original"):
    """G1-G4 of the pre-registration on a list of correlation_run results (holdout runs of ONE model)."""
    gr = cfg["ops"]["go_rules"]
    pr = cfg["ops"]["queue"]["primary"]
    B, pol = pr["budget"], pr["policy"]
    g1 = {}
    for res in results:
        for a, lv in res["levels"].items():
            r = lv.get(scenario_benefit, {}).get(label_set)
            if not r or not r["flow"]["alerted_flows"]:
                continue
            s, c = r["units"]["source"]["queue"][f"{pol}@{B}"], r["units"]["campaign"]["queue"][f"{pol}@{B}"]
            g1[a] = {"episode_strict": [s.get("episode_coverage_strict"), c.get("episode_coverage_strict")],
                     "attack_flow_case": [s.get("attack_flow_coverage_case"), c.get("attack_flow_coverage_case")]}
    g1_ok = any((v["episode_strict"][1] or 0) >= (v["episode_strict"][0] or 0) + gr["benefit_abs"] or
                (v["attack_flow_case"][1] or 0) >= (v["attack_flow_case"][0] or 0) + gr["benefit_abs"] for v in g1.values())
    lost, ben, absorbed, delays = [], 0, 0, []
    for res in results:
        lv = res["levels"][str(pr["alpha"])]
        for sc, x in lv.items():
            r = x.get(label_set)
            if not r:
                continue
            for k, s in r["units"]["source"]["queue"].items():
                c = r["units"]["campaign"]["queue"][k]
                miss = set(s.get("attack_types_covered_strict", [])) - set(c.get("attack_types_covered_strict", []))
                lost += [f"{sc}:{k}:{m}" for m in miss]
                if k == f"{pol}@{B}":
                    ts, tc = s.get("time_to_review_s", {}), c.get("time_to_review_s", {})
                    delays += [tc[t] - ts[t] for t in ts if t in tc]
            q = r["correlation_quality"]
            if q:
                ben += q["benign_only_source_incidents"]
                absorbed += q["benign_source_incidents_in_attack_campaigns"]
    cont = absorbed / ben if ben else 0.0
    med = float(np.median(delays)) if delays else 0.0
    rules = {"G1_benefit": {"ok": bool(g1_ok), "by_alpha": g1},
             "G2_no_lost_attack_type": {"ok": not lost, "lost": lost},
             "G3_contamination": {"ok": cont <= gr["contamination_max"], "share": cont, "benign_only_source_incidents": ben,
                                  "absorbed": absorbed},
             "G4_delay": {"ok": med <= gr["delay_max_ms"] / 1000, "median_delta_s": med, "n_types": len(delays)}}
    rules["GO"] = all(v["ok"] for v in rules.values())
    return rules


def model_rule(res_a0, res_pilot, cfg, hoic="holdout-ddos-hoic", hoic_label="DDOS_attack-HOIC"):
    """RQ-M: pooled fresh-holdout benign FPR and false source incidents/hour at alpha 0.1% (corrected labels if present)."""
    mr = cfg["ops"]["model_rule"]
    a_ = str(cfg["ops"]["queue"]["primary"]["alpha"])

    def pooled(res):
        fp = nb = fi = h = 0
        for sc, x in res["levels"][a_].items():
            r = x.get("corrected") or x["original"]
            nb += r["flow"]["n_benign"]
            fp += r["flow"]["fp"]
            fi += r["units"]["source"]["false_items_per_hour"] * r["hours"]
            h += r["hours"]
        x = res["levels"][a_].get(hoic, {})
        rr = (x.get("corrected") or x.get("original") or {}).get("flow", {}).get("attack_recall_by_label", {}).get(hoic_label, 0.0)
        return {"benign_fpr": fp / nb if nb else None, "benign_fpr_wilson95": wilson(fp, nb), "n_benign": nb,
                "false_source_incidents_per_hour": fi / h if h else None, "hoic_recall": rr}
    a, p = pooled(res_a0), pooled(res_pilot)
    ok = (p["benign_fpr"] <= a["benign_fpr"] and
          p["false_source_incidents_per_hour"] <= mr["incident_ratio_max"] * max(a["false_source_incidents_per_hour"], 1e-9) and
          p["hoic_recall"] >= a["hoic_recall"] - mr["hoic_recall_margin"])
    return {"a0_v2": a, "pilot_cns_s0": p, "recommend_pilot": bool(ok)}


def study(cfg, run_ids, tag, out_root=None):
    """Run the whole ops study on a set of runs; write runs/ops_study/<tag>/."""
    out = (out_root or K.path(cfg, "runs") / "ops_study") / tag
    out.mkdir(parents=True, exist_ok=True)
    corr, wins = {}, []
    for rid in run_ids:
        D.monitor_run(cfg, rid)
        corr[rid] = correlation_run(cfg, rid)
        wins.append(drift_windows(cfg, rid))
    win = pd.concat(wins, ignore_index=True)
    win.to_csv(out / "drift_windows.csv", index=False)
    summ = {"tag": tag, "config": cfg["_path"], "config_sha1": cfg["_sha1"], "runs": run_ids, "drift": {}}
    for md, g in win.groupby("model_dir"):
        summ["drift"][md] = drift_summary(g, cfg)
    (out / "CORRELATION.json").write_text(json.dumps(corr, indent=1, default=_js), encoding="utf-8")
    (out / "DRIFT.json").write_text(json.dumps(summ, indent=1, default=_js), encoding="utf-8")
    return corr, summ, win


def go_report(cfg, tag, benefit_scenario="holdout-ddos-hoic"):
    """GO rules of the pre-registration on runs/ops_study/<tag>/: RQ-C per model and label set, RQ-D, RQ-M."""
    d = K.path(cfg, "runs") / "ops_study" / tag
    corr = json.loads((d / "CORRELATION.json").read_text(encoding="utf-8"))
    drift = json.loads((d / "DRIFT.json").read_text(encoding="utf-8"))
    by_model = {}
    for rid, r in corr.items():
        by_model.setdefault(r["model_dir"], []).append(r)
    rep = {"tag": tag, "correlation": {}, "drift": {}}
    for md, rs in by_model.items():
        rep["correlation"][md] = {ls: correlation_go(rs, cfg, benefit_scenario, ls) for ls in ("original", "corrected")}
    for md, x in drift["drift"].items():
        rep["drift"][md] = {k: v["go"] for k, v in x.items() if k.endswith("@%s" % cfg["ops"]["drift"]["primary_alpha"])}
    if "a0" in by_model and "pilot_cns/s0" in by_model and len(by_model["a0"]) == 1 and len(by_model["pilot_cns/s0"]) == 1:
        rep["model_rule"] = model_rule(by_model["a0"][0], by_model["pilot_cns/s0"][0], cfg)
    (d / "GO.json").write_text(json.dumps(rep, indent=1, default=_js), encoding="utf-8")
    return rep
