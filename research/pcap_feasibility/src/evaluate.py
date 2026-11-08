"""RQ-PCAP evaluation: LOCO binary (primary), controls, ablations, capture identifiability,
within-capture multiclass (EXPLORATORY). All thresholds are fixed on calibration benign of training captures."""
import time

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold

import features as F


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def fit(Xtr, ytr, cats, seed, params, multiclass=False):
    p = dict(params)
    p.update(random_seed=seed, cat_features=cats, allow_writing_files=False)
    if multiclass:
        p["loss_function"] = "MultiClass"
    m = CatBoostClassifier(**p)
    t0 = time.perf_counter()
    m.fit(Xtr, ytr)
    return m, time.perf_counter() - t0


def threshold_at_fpr(benign_scores: np.ndarray, fpr: float) -> float:
    """Alert iff score > threshold; at most floor(fpr * n) calibration benign exceed it."""
    s = np.sort(benign_scores)[::-1]
    k = int(np.floor(fpr * len(s)))
    return float(s[k]) if k < len(s) else float(s[-1])


def incidents(df: pd.DataFrame, alert: np.ndarray, cooldown: float) -> dict:
    a = df.loc[alert, ["ts", "orig_h", "is_malicious"]].sort_values("ts")
    n_inc = n_false = 0
    for _, g in a.groupby("orig_h"):
        last, has_mal = None, 0
        for ts, mal in zip(g["ts"], g["is_malicious"]):
            if last is not None and ts - last > cooldown:
                n_inc += 1
                n_false += int(not has_mal)
                has_mal = 0
            has_mal |= int(mal)
            last = ts
        if last is not None:
            n_inc += 1
            n_false += int(not has_mal)
    return {"incidents": n_inc, "false_incidents": n_false}


def binary_metrics(test: pd.DataFrame, score: np.ndarray, thr: float, cooldown: float) -> dict:
    y = test["is_malicious"].to_numpy()
    alert = score > thr
    tp, fp = int((alert & (y == 1)).sum()), int((alert & (y == 0)).sum())
    fn, tn = int((~alert & (y == 1)).sum()), int((~alert & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    out = {"threshold": thr, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec,
           "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
           "fpr": fp / (fp + tn) if fp + tn else None, "fpr_ci": wilson(fp, fp + tn),
           "recall_ci": wilson(tp, tp + fn)}
    out.update(incidents(test, alert, cooldown))
    fam = {}
    for lab, g in test[test["is_malicious"] == 1].groupby("detailed_label"):
        idx = test.index.get_indexer(g.index)
        fam[lab] = {"n": len(g), "recall": float(alert[idx].mean()),
                    "n_destinations": int(g[["resp_h", "resp_p"]].drop_duplicates().shape[0])}
    out["per_family"] = fam
    return out


def oracle_recall_at_fpr(y, score, fpr):
    """Analysis only: threshold taken from TEST benign (not deployable)."""
    thr = threshold_at_fpr(score[y == 0], fpr)
    return float((score[y == 1] > thr).mean()) if (y == 1).any() else None


def split_train(tr: pd.DataFrame, frac: float):
    fit_parts, cal_parts = [], []
    for _, g in tr.groupby("capture_id"):
        g = g.sort_values("ts")
        k = int(len(g) * frac)
        fit_parts.append(g.iloc[:k])
        cal_parts.append(g.iloc[k:])
    return pd.concat(fit_parts), pd.concat(cal_parts)


def build(df_fit, df_cal, df_te, variant, seed, exclude_groups=()):
    base = "C" if variant in ("C", "C_minus") else ("B" if variant == "B" else "A")
    if variant == "A_plus_permuted_B":
        base = "C"
    cols, cats = F.feature_set(df_fit, base, exclude_groups)
    Xs = [F.matrix(d, cols, cats) for d in (df_fit, df_cal, df_te)]
    if variant == "A_plus_noise":
        k = len(F.feature_set(df_fit, "B")[0])
        Xs = [F.add_noise(X, k, seed * 1000 + i) for i, X in enumerate(Xs)]
    if variant == "A_plus_permuted_B":
        block = F.feature_set(df_fit, "B")[0]
        Xs = [F.permute_block(X, block, seed * 1000 + i) for i, X in enumerate(Xs)]
    return Xs, cats


def loco(df: pd.DataFrame, cfg: dict, variants, seeds, exclude_groups=(), variant_name=None) -> list[dict]:
    ev = cfg["evaluation"]["primary"]
    cooldown = cfg["evaluation"]["incidents"]["cooldown_s"]
    params = cfg["model"]["params"]
    rows = []
    for test_cap in sorted(df["capture_id"].unique()):
        te = df[df["capture_id"] == test_cap].reset_index(drop=True)
        df_fit, df_cal = split_train(df[df["capture_id"] != test_cap], 0.7)
        for variant in variants:
            for seed in seeds:
                (Xf, Xc, Xt), cats = build(df_fit, df_cal, te, variant, seed, exclude_groups)
                m, t_fit = fit(Xf, df_fit["is_malicious"], cats, seed, params)
                t0 = time.perf_counter()
                st = m.predict_proba(Xt)[:, 1]
                t_pred = time.perf_counter() - t0
                sc = m.predict_proba(Xc)[:, 1]
                cal_benign = sc[df_cal["is_malicious"].to_numpy() == 0]
                y = te["is_malicious"].to_numpy()
                row = {"test_capture": test_cap, "variant": variant_name or variant, "seed": seed,
                       "n_features": Xf.shape[1], "n_fit": len(df_fit), "n_cal_benign": int(len(cal_benign)),
                       "n_test": len(te), "n_test_benign": int((y == 0).sum()), "n_test_mal": int((y == 1).sum()),
                       "pr_auc": float(average_precision_score(y, st)) if 0 < y.sum() < len(y) else None,
                       "roc_auc": float(roc_auc_score(y, st)) if 0 < y.sum() < len(y) else None,
                       "fit_seconds": round(t_fit, 2), "infer_us_per_flow": round(t_pred / len(te) * 1e6, 2)}
                for fpr in ev["fpr_targets"]:
                    key = f"fpr{fpr:g}"
                    thr = threshold_at_fpr(cal_benign, fpr)
                    met = binary_metrics(te, st, thr, cooldown)
                    met["support"] = {
                        "calibration": "OK" if len(cal_benign) >= ev["min_benign_for_fpr"][fpr] else "INSUFFICIENT SUPPORT",
                        "test": "OK" if (y == 0).sum() >= ev["min_benign_for_fpr"][fpr] else "INSUFFICIENT SUPPORT"}
                    met["oracle_recall_at_test_fpr"] = oracle_recall_at_fpr(y, st, fpr)
                    row[key] = met
                    # Sensitivity: Zeek records with 0 packets in both directions (conn.log artefact, see report)
                    zero = ((te["orig_pkts"] == 0) & (te["resp_pkts"] == 0)).to_numpy()
                    if zero.any():
                        keep = ~zero
                        sub = te[keep].reset_index(drop=True)
                        ms = binary_metrics(sub, st[keep], thr, cooldown)
                        ms["n_excluded"] = int(zero.sum())
                        ms["pr_auc"] = float(average_precision_score(y[keep], st[keep])) if 0 < y[keep].sum() < keep.sum() else None
                        row[key + "_excl_zero_pkt_records"] = ms
                if seed == seeds[0] and variant in ("C", "A", "B"):
                    imp = pd.Series(m.get_feature_importance(), index=Xf.columns).sort_values(ascending=False)
                    row["top_features"] = {k: round(float(v), 2) for k, v in imp.head(10).items()}
                rows.append(row)
    return rows


def capture_identifiability(df: pd.DataFrame, cfg: dict, benign_only: bool = True) -> dict:
    d = df[df["is_malicious"] == 0] if benign_only else df
    d = d.reset_index(drop=True)
    y = d["capture_id"].to_numpy()
    params = dict(cfg["model"]["params"], iterations=300)
    out = {}
    for name in ("A", "B", "C"):
        cols, cats = F.feature_set(d, name)
        X = F.matrix(d, cols, cats)
        pred = np.empty(len(d), dtype=object)
        for tr, te in StratifiedKFold(5, shuffle=True, random_state=0).split(X, y):
            m, _ = fit(X.iloc[tr], y[tr], cats, 0, params, multiclass=True)
            pred[te] = m.predict(X.iloc[te]).ravel()
        out[name] = {"macro_f1": float(f1_score(y, pred, average="macro")),
                     "accuracy": float((pred == y).mean()), "n": len(d), "chance": float(1 / len(set(y)))}
    return out


def within_capture_multiclass(df: pd.DataFrame, cfg: dict, seeds) -> dict:
    """EXPLORATORY: per-capture temporal split (first 60% / last 40%), pooled; multiclass on detailed_label."""
    sec = cfg["evaluation"]["secondary"]
    tr_parts, te_parts = [], []
    for _, g in df.groupby("capture_id"):
        g = g.sort_values("ts")
        k = int(len(g) * 0.6)
        tr_parts.append(g.iloc[:k])
        te_parts.append(g.iloc[k:])
    tr, te = pd.concat(tr_parts).reset_index(drop=True), pd.concat(te_parts).reset_index(drop=True)
    sup_tr, sup_te = tr["detailed_label"].value_counts(), te["detailed_label"].value_counts()
    scored = [c for c in sup_tr.index if sup_tr[c] >= sec["min_class_support"] and sup_te.get(c, 0) >= sec["min_class_support"]]
    out = {"support_train": sup_tr.to_dict(), "support_test": sup_te.to_dict(), "scored_classes": scored,
           "not_scored": [c for c in set(sup_tr.index) | set(sup_te.index) if c not in scored], "runs": []}
    trs, tes = tr[tr["detailed_label"].isin(scored)], te[te["detailed_label"].isin(scored)]
    for name in ("A", "B", "C"):
        cols, cats = F.feature_set(trs, name)
        for seed in seeds:
            m, _ = fit(F.matrix(trs, cols, cats), trs["detailed_label"], cats, seed, cfg["model"]["params"], True)
            pred = m.predict(F.matrix(tes, cols, cats)).ravel()
            yt = tes["detailed_label"].to_numpy()
            pcf = f1_score(yt, pred, labels=scored, average=None)
            ben = yt == "Benign"
            out["runs"].append({"set": name, "seed": seed, "macro_f1": float(f1_score(yt, pred, labels=scored, average="macro")),
                                "per_class_f1": dict(zip(scored, map(float, pcf))),
                                "benign_fpr": float((pred[ben] != "Benign").mean()) if ben.any() else None})
    return out
