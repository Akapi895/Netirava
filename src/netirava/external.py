"""External evaluation on NF-UNSW-NB15-v3 (docs/protocols/external_evaluation.md).

E1: frozen CIC models (pilot_cns/s0, A0 v2), thresholds locked on CIC C1, no recalibration; per capture day,
    exact duplicates removed (raw counts reported).
E2: label/host/time-only gate for the last training run (G1-G6); no model is fitted here.
"""

import json

import numpy as np
import pandas as pd
import pyarrow.csv as pacsv

from netirava import config as K
from netirava import features as F
from netirava.detectors import A0, threshold_at_fpr, wilson

CSV = K.ROOT.parent / "GraphIDS" / "data" / "NF-UNSW-NB15-v3" / "NF-UNSW-NB15-v3.csv"
EXACT_KEY = [F.TS_START, F.TS_END, F.SRC, F.DST] + F.FEATURES
MODELS = {"final: pilot_cns/s0": "pilot_cns/s0", "baseline: A0 v2": "a0"}
NP_V1_PERIODS = {"2015-01-22": "NP-v1 period A (evaluation)", "2015-02-18": "NP-v1 period B (development)"}
GAP_MS = 1_800_000


def load():
    df = pacsv.read_csv(CSV).to_pandas()
    df["row_id"] = np.arange(len(df))
    df["dup"] = df.duplicated(EXACT_KEY, keep="first")
    df["day"] = pd.to_datetime(df[F.TS_START], unit="ms", utc=True).dt.strftime("%Y-%m-%d")
    return df


def episodes(a):
    a = a.sort_values([F.LABEL, F.SRC, F.DST, F.TS_START])
    new = (a[F.LABEL] != a[F.LABEL].shift()) | (a[F.SRC] != a[F.SRC].shift()) | (a[F.DST] != a[F.DST].shift()) | \
          (a[F.TS_START].diff() > GAP_MS)
    return pd.Series(new.cumsum().to_numpy(), index=a.index)


def calib_scores(cfg, model):
    from netirava.dataset import training_frame
    m = A0.load(K.path(cfg, "models") / model)
    cal = training_frame(cfg, ["calibration"])
    s = m.score(F.matrix(cal))[1][(cal[F.LABEL] == "Benign").to_numpy()]
    return m, s


def evaluate(df, cfg, alphas=(0.001, 0.01)):
    from sklearn.metrics import roc_auc_score
    d = df[~df.dup].reset_index(drop=True)
    ep = episodes(d[d[F.LABEL] != "Benign"])
    d["ep"] = -1
    d.loc[ep.index, "ep"] = ep.to_numpy()
    out = {"rows_raw": int(len(df)), "rows_dedup": int(len(d)), "exact_duplicates": int(df.dup.sum()),
           "days": sorted(df.day.unique()), "models": {}}
    X = F.matrix(d)
    for name, mdir in MODELS.items():
        m, cs = calib_scores(cfg, mdir)
        P, score, pr = m.score(X)
        pred = np.asarray(m.classes, dtype=object)[pr]
        thr = {a: threshold_at_fpr(cs, a)[0] for a in alphas}
        assert abs(thr[0.001] - m.threshold) < 1e-9
        res = {"model_hash": m.version, "thresholds_locked_on_cic_c1": thr, "days": {}}
        for day, g in d.groupby("day"):
            idx = g.index.to_numpy()
            ben = (g[F.LABEL] == "Benign").to_numpy()
            r = {"n_benign": int(ben.sum()), "alphas": {}, "classes": {}}
            for a, t in thr.items():
                al = score[idx] >= t
                k, n = int((al & ben).sum()), int(ben.sum())
                r["alphas"][str(a)] = {"fp": k, "benign_fpr": k / n if n else None, "benign_fpr_wilson95": wilson(k, n) if n else None,
                                       "fpr_held_2x": bool(n and k / n <= 2 * a)}
            for lab, x in g[~ben].groupby(F.LABEL):
                xi = x.index.to_numpy()
                c = {"flows": int(len(x)), "src_hosts": int(x[F.SRC].nunique()), "dst_hosts": int(x[F.DST].nunique()),
                     "episodes": int(x.ep.nunique()), "cic_argmax": pd.Series(pred[xi]).value_counts().head(3).to_dict()}
                yb = np.r_[np.zeros(ben.sum()), np.ones(len(xi))]
                c["auroc_vs_benign"] = float(roc_auc_score(yb, np.r_[score[idx][ben], score[xi]])) if ben.any() else None
                for a, t in thr.items():
                    al = score[xi] >= t
                    det_ep = x.ep[al].nunique()
                    c[f"recall@{a}"] = float(al.mean())
                    c[f"recall_wilson95@{a}"] = wilson(int(al.sum()), len(xi))
                    c[f"episodes_detected@{a}"] = f"{det_ep}/{c['episodes']}"
                r["classes"][lab] = c
            res["days"][day] = r
        out["models"][name] = res
    return out


def gate(df):
    d = df[~df.dup]
    att = d[d[F.LABEL] != "Benign"]
    share = att[F.LABEL].value_counts(normalize=True)
    minority = sorted(share[share < 0.01].index)
    days = sorted(d.day.unique())
    per_day = att.pivot_table(index=F.LABEL, columns="day", values="row_id", aggfunc="count", fill_value=0)
    ep = episodes(att)
    att = att.assign(ep=ep)
    groups = {lab: {day: {"flows": int(len(x)), "src_hosts": int(x[F.SRC].nunique()), "episodes": int(x.ep.nunique())}
                    for day, x in g.groupby("day")} for lab, g in att[att[F.LABEL].isin(minority)].groupby(F.LABEL)}
    g1_classes = [lab for lab in minority if len(days) >= 2 and all(per_day.loc[lab].get(dd, 0) >= 30 for dd in days)]
    fp = pd.util.hash_pandas_object(att[F.FEATURES].astype("float64") + 0.0, index=False).to_numpy()
    att = att.assign(fp=fp)
    overlap = {}
    for lab, g in att[att[F.LABEL].isin(minority)].groupby(F.LABEL):
        sets = [set(g.fp[g.day == dd]) for dd in days]
        if len(sets) == 2 and sets[0] and sets[1]:
            overlap[lab] = float(len(sets[0] & sets[1]) / len(sets[1]))
    exact_cross = int(df.groupby(pd.util.hash_pandas_object(df[EXACT_KEY], index=False).to_numpy()).day.nunique().gt(1).sum())
    ben = d[d[F.LABEL] == "Benign"].groupby("day").size().to_dict()
    hosts = {"attack_src": sorted(att[F.SRC].unique().tolist())[:20], "n_attack_src": int(att[F.SRC].nunique()),
             "attack_src_also_benign_src": int(att[F.SRC].isin(set(d.loc[d[F.LABEL] == "Benign", F.SRC])).sum())}
    G = {"G1": {"minority_classes": minority, "classes_with_30_per_day": g1_classes, "per_class_day": groups,
                "ok": len(g1_classes) >= 2},
         "G2": {"days": days, "flows_per_day": d.groupby("day").size().to_dict(), "attack_hosts": hosts,
                "ok": len(days) == 2},
         "G3": {"exact_duplicates_across_days": exact_cross, "minority_feature_fingerprint_overlap_day2_in_day1": overlap,
                "ok": exact_cross == 0},
         "G4": {"benign_per_day": ben, "ok": all(0.2 * v >= 100_000 for v in ben.values())},
         "G5": {"rows": int(len(df)), "ok": len(df) < 5_000_000},
         "G6": {"days_used_before": {dd: NP_V1_PERIODS.get(dd, "not used by NP-v1") for dd in days},
                "note": "Run 1 and GraphIDS used random splits over all rows, so every day was also in their test sets",
                "ok": False}}
    G["train"] = all(v["ok"] for k, v in G.items() if k.startswith("G"))
    return G


def run(cfg):
    df = load()
    res = {"gate": gate(df), "frozen_eval": evaluate(df, cfg)}
    out = K.path(cfg, "runs") / "external_unsw"
    out.mkdir(parents=True, exist_ok=True)
    (out / "EXTERNAL.json").write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
    return res


def monitor_exploratory(cfg, df=None, model="pilot_cns/s0"):
    """EXPLORATORY (not in the pre-registration): would the label-free drift monitor, with its CIC C1
    reference, have flagged the UNSW environment? 15-min windows per UTC day, label-free signals."""
    from netirava import drift as D
    df = load() if df is None else df
    d = df[~df.dup].sort_values(F.TS_START).reset_index(drop=True)
    ref = D.load_reference(cfg, model)
    m = A0.load(K.path(cfg, "models") / model)
    X = F.matrix(d)
    score = m.score(X)[1]
    w = (d[F.TS_START] // 900_000).to_numpy()
    rows = []
    for k in np.unique(w):
        idx = np.flatnonzero(w == k)
        if len(idx) < 2000:
            continue
        r = D.window_signals(score[idx], X[idx], ref, cfg)
        r["status"] = D.status(r, 0.001)
        rows.append({x: r[x] for x in ("n_flows", "AR@0.001", "TR@0.001", "S_PSI", "F_PSI_median", "F_PSI_top", "status",
                                        "AR_alarm@0.001", "TR_alarm@0.001", "S_PSI_alarm", "F_PSI_alarm")})
    t = pd.DataFrame(rows)
    out = {"windows": int(len(t)), "status_counts": t.status.value_counts().to_dict(),
           "alarm_share": {c: float(t[c].mean()) for c in ("AR_alarm@0.001", "TR_alarm@0.001", "S_PSI_alarm", "F_PSI_alarm")},
           "median": {c: float(t[c].median()) for c in ("AR@0.001", "TR@0.001", "S_PSI", "F_PSI_median")},
           "top_drifting_features_example": t.F_PSI_top.mode().iat[0] if len(t) else None}
    p = K.path(cfg, "runs") / "external_unsw" / "MONITOR_EXPLORATORY.json"
    p.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return out
