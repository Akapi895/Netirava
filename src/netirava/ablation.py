"""Clean imbalance ablation (docs/protocols/evidence_round2_prereg.md §A).

Same data (fe_study frame: exact duplicates removed, CNS2022-adapted labels, attempted/indeterminate
excluded), same final train set (whole T1-T4 + pilot-train web rows), same 49 raw features, same A0
CatBoost recipe, same seeds and the same threshold rule (C1 benign, de-duplicated). Only the imbalance
handling differs:
  none     no resampling, no weights
  cw       CatBoost auto_class_weights = "Balanced"
  smotenc  A0 rule: classes < 1000 rows -> 1000 with SMOTENC (categorical codes copied)
The result never changes the deployed model.
"""

import json
import time

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.detectors import _StopAfterFirst, apply_smote, catboost_params, reference_recipe, threshold_at_fpr, wilson
from netirava.fe import EXCLUDE_STATUS, WEB_SEGS, drop_exact_duplicates, final_train_mask, study_frame

ARMS = {"none": {"smote": False, "cw": None}, "cw": {"smote": False, "cw": "Balanced"},
        "smotenc": {"smote": True, "cw": None}}
BENIGN = "Benign"


def fit(X, y, classes, arm, seed, cfg):
    from catboost import CatBoostClassifier
    rec = reference_recipe(cfg)
    rec["seed"] = int(seed)
    spec = ARMS[arm]
    if spec["smote"]:
        Xf, yf, sm = apply_smote(X, y, rec, classes)
    else:
        Xf, yf, sm = X, y, {"applied": False}
    params, probe_p = catboost_params(rec), catboost_params(rec, device="CPU")
    if spec["cw"]:
        params["auto_class_weights"] = probe_p["auto_class_weights"] = spec["cw"]
    if rec["device"] == "GPU" and rec.get("lr_rule") == "cpu_auto_probe":
        probe = CatBoostClassifier(**probe_p)
        probe.fit(Xf, yf, callbacks=[_StopAfterFirst()])
        params["learning_rate"] = float(probe.get_all_params()["learning_rate"])
    m = CatBoostClassifier(**params)
    t0 = time.perf_counter()
    m.fit(Xf, yf)
    return m, {"fit_s": time.perf_counter() - t0, "n_fit": int(len(yf)), "smote": sm,
               "learning_rate": params.get("learning_rate"), "auto_class_weights": spec["cw"]}


def per_class(y, pred, classes):
    out = {}
    for c in classes:
        t, p = y == c, pred == c
        n = int(t.sum())
        if not n and not p.sum():
            continue
        tp = int((t & p).sum())
        P_ = tp / p.sum() if p.sum() else 0.0
        R_ = tp / n if n else 0.0
        out[c] = {"support": n, "precision": float(P_), "recall": float(R_),
                  "f1": float(2 * P_ * R_ / (P_ + R_)) if P_ + R_ else 0.0,
                  "recall_wilson95": wilson(tp, n) if n else None, "inconclusive_n_lt_30": n < 30}
    return out


def incidents_count(g, alert, cooldown_ms=900_000):
    """Source incidents (src IP + cooldown on available_at) among alerted flows; false = no attack flow."""
    a = g.loc[alert, [F.SRC, "available_at", "y"]].sort_values([F.SRC, "available_at"])
    if a.empty:
        return 0, 0
    new = (a[F.SRC] != a[F.SRC].shift()) | (a.available_at.diff() > cooldown_ms)
    inc = new.cumsum()
    att = (a.y != BENIGN).groupby(inc.to_numpy()).any()
    return int(len(att)), int((~att).sum())


def binary(g, score, thr):
    """g: rows with column y (label, excluded rows removed); score aligned with g."""
    alert = score >= thr
    ben = (g.y == BENIGN).to_numpy()
    k, n = int((alert & ben).sum()), int(ben.sum())
    r = {"n_benign": n, "fp": k, "benign_fpr": k / n if n else None, "benign_fpr_wilson95": wilson(k, n) if n else None}
    r["recall_by_label"] = {lab: float(alert[(g.y == lab).to_numpy()].mean()) for lab in sorted(set(g.y) - {BENIGN})}
    r["support_by_label"] = {lab: int((g.y == lab).sum()) for lab in sorted(set(g.y) - {BENIGN})}
    r["source_incidents"], r["false_source_incidents"] = incidents_count(g.assign(_a=alert), alert)
    return r


def _labelled(df):
    """Drop attempted/indeterminate rows; y = adapted label (original where the day was not audited)."""
    d = df[~df.status.isin(EXCLUDE_STATUS)].copy()
    d["y"] = d.label_corrected
    return d.reset_index(drop=True)


def ops_holdout_frame():
    from netirava.dataset import load_stream
    cfg = K.load("configs/ops_holdout.yaml")
    h = load_stream(cfg, roles=["holdout"])
    ann = pd.read_parquet(K.path(cfg, "derived") / "truth_cns2022.parquet",
                          columns=["flow_id", "label_original", "label_corrected", "status"])
    return drop_exact_duplicates(h.merge(ann, on="flow_id", how="left", validate="one_to_one"))


def run(cfg, seeds=(0, 1, 2), alphas=(0.001, 0.01)):
    from netirava.fstudy import _holdout_frame
    classes = list(cfg["a0"]["known_classes"])
    d = study_frame(cfg)
    trn = d[final_train_mask(d)]
    X, y = F.matrix(trn), trn.label_corrected.map({c: i for i, c in enumerate(classes)}).to_numpy(np.int64)
    assert (y >= 0).all()
    cal = d[(d.study_role == "calib") & (d.label_corrected == BENIGN)]
    web = _labelled(d[d.segment.isin(WEB_SEGS) & (d.study_role == "inner_val")])
    known = _labelled(d[d.study_role == "known_tail"])
    dev = {s: _labelled(g) for s, g in d[d.study_role == "dev"].groupby("segment")}
    exp = {s: _labelled(g) for s, g in _holdout_frame(cfg).groupby("segment")}
    exp.update({s: _labelled(g) for s, g in ops_holdout_frame().groupby("segment")})
    out = {"n_train": int(len(trn)), "train_counts": trn.label_corrected.value_counts().to_dict(),
           "eval_support": {"web": web.y.value_counts().to_dict(), "known": known.y.value_counts().to_dict()},
           "runs": []}
    mdir = K.path(cfg, "derived") / "ablation_clean"
    mdir.mkdir(parents=True, exist_ok=True)
    for arm in ARMS:
        for s in seeds:
            m, info = fit(X, y, classes, arm, s, cfg)
            m.save_model(str(mdir / f"{arm}_s{s}.cbm"))
            score = lambda df: 1.0 - m.predict_proba(F.matrix(df))[:, 0]
            pred = lambda df: np.asarray(classes, dtype=object)[m.predict_proba(F.matrix(df)).argmax(1)]
            cs = score(cal)
            row = {"arm": arm, "seed": s, **info, "model_sha1": K.sha1_file(mdir / f"{arm}_s{s}.cbm")[:12],
                   "web_per_class": per_class(web.y.to_numpy(), pred(web), classes),
                   "known_per_class": per_class(known.y.to_numpy(), pred(known), classes), "alphas": {}}
            rare = [c for c in cfg["a0"]["rare_classes"] if c in row["web_per_class"]]
            row["rare_macro_f1_web_eval"] = float(np.mean([row["web_per_class"][c]["f1"] for c in rare]))
            for a in alphas:
                thr, real = threshold_at_fpr(cs, a)
                row["alphas"][str(a)] = {"threshold": float(thr), "calib_fpr": float(real),
                                         "web_binary": binary(web, score(web), thr),
                                         "dev": {k: binary(g, score(g), thr) for k, g in dev.items()},
                                         "exp": {k: binary(g, score(g), thr) for k, g in exp.items()}}
            out["runs"].append(row)
            print(arm, s, f"rareF1 {row['rare_macro_f1_web_eval']:.3f}",
                  {k: round(v["benign_fpr"], 5) for k, v in row["alphas"]["0.001"]["dev"].items()}, flush=True)
            (K.path(cfg, "runs") / "ablation_clean.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return out
