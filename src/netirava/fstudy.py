"""Feature-effectiveness study (Phase 4) and final holdout evaluation (Phase 5).

Every arm is fitted with the A0 recipe (CatBoost, SMOTE < 1000 -> 1000, cpu_auto_probe lr on GPU,
no HPO) on inner-train only, and scored on inner-val (M1, M3), calibration benign (threshold at
alpha) and the dev segments' benign rows (M2). Holdout rows are never loaded by run_study.
"""

import json
import time

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, roc_auc_score

from netirava import config as K
from netirava import features as F
from netirava.detectors import (_StopAfterFirst, catboost_params, reference_recipe,
                                threshold_at_fpr, wilson)
from netirava.fe import (EXCLUDE_STATUS, SHORTCUT, FeaturePipeline, context_features, final_train_mask,
                         study_frame)

BENIGN = "Benign"
NOISE_SEED = 104729


# --------------------------------------------------------------------------- data
def load(cfg):
    d = study_frame(cfg)
    cache = K.path(cfg, "derived") / "study" / "ctx.parquet"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.exists():
        ctx = pd.read_parquet(cache)
        assert len(ctx) == len(d) and (ctx.flow_id.to_numpy() == d.flow_id.to_numpy()).all()
    else:
        t0 = time.perf_counter()
        ctx = context_features(d)
        ctx.insert(0, "flow_id", d.flow_id.to_numpy())
        ctx.to_parquet(cache, index=False)
        print(f"context features: {time.perf_counter() - t0:.0f} s", flush=True)
    return d, ctx.drop(columns="flow_id").set_index(d.index)


# --------------------------------------------------------------------------- fit one arm
def _smote(X, y, smote_cats, rec, classes, scaler=None, weights=None):
    """SMOTENC with categorical columns copied (not interpolated). Continuous columns: NaN -> sentinel
    before, sentinel region -> NaN after. With `scaler` (fitted on inner-train) the k-NN search runs on
    log1p + robust-scaled values (Phase 2, P6); without it on raw values (A0 behaviour)."""
    from imblearn.over_sampling import SMOTENC
    from netirava.detectors import smote_plan
    counts = np.bincount(y, minlength=len(classes))
    if weights is None:
        plan, small = smote_plan(counts, rec["smote_lt"], rec["smote_k"])
    else:
        # A0 rule on EFFECTIVE (weighted) row counts: a de-duplicated class keeps its real size
        eff = np.bincount(y, weights=weights, minlength=len(classes))
        plan = {c: int(counts[c] + rec["smote_lt"] - eff[c]) for c in range(len(classes)) if 2 <= eff[c] < rec["smote_lt"]}
        small = [c for c in plan if counts[c] <= rec["smote_k"]]
    if small:
        raise ValueError(f"classes too small for SMOTE: {[classes[c] for c in small]}")
    if not plan:
        return X, y, {"applied": False}
    cont = [c for c in X.columns if c not in smote_cats]
    Z = X.copy()
    if scaler is not None:
        med, iqr = scaler
        Z[cont] = (np.log1p(Z[cont].astype(float).fillna(-0.5).clip(lower=-0.5)) - med) / iqr
    else:
        Z[cont] = Z[cont].astype(float).fillna(-1.0)
    sm = SMOTENC(categorical_features=[Z.columns.get_loc(c) for c in smote_cats], sampling_strategy=plan,
                 k_neighbors=rec["smote_k"], random_state=rec["seed"])
    Zr, yr = sm.fit_resample(Z, y)
    Zr = pd.DataFrame(np.asarray(Zr, dtype=object), columns=Z.columns)
    if scaler is not None:
        raw = np.expm1(Zr[cont].astype(float) * iqr + med)
        Zr[cont] = raw.where(raw >= -0.25, np.nan).clip(lower=0)
    else:
        v = Zr[cont].astype(float)
        Zr[cont] = v.where(v >= -0.5, np.nan)
    for c in smote_cats:
        Zr[c] = Zr[c].astype(float) if pd.api.types.is_numeric_dtype(X[c]) else Zr[c].astype(str)
    return Zr, np.asarray(yr, np.int64), {"applied": True, "plan": {classes[c]: t for c, t in plan.items()},
                                         "scaled_knn": scaler is not None}


def fit_arm(spec, tr, seed, cfg, ctx):
    from catboost import CatBoostClassifier, Pool
    classes = list(cfg["a0"]["known_classes"])
    pipe = FeaturePipeline(spec).fit(tr)
    X, cats = pipe.transform(tr, ctx=ctx, seed=seed)
    X = X.reset_index(drop=True)
    y = tr.label_corrected.map({c: i for i, c in enumerate(classes)}).to_numpy(np.int64)
    assert (y >= 0).all()
    rec = reference_recipe(cfg)
    rec["seed"] = int(seed)
    w, scaler = None, None
    if spec.get("prep"):
        # collapse rows identical in model input + label; weight = multiplicity
        key = pd.util.hash_pandas_object(X, index=False).to_numpy() ^ (y.astype(np.uint64) * np.uint64(0x9E3779B97F4A7C15))
        ks = pd.Series(key)
        first = ~ks.duplicated().to_numpy()
        w = ks.map(ks.value_counts()).to_numpy(float)[first]
        X, y = X[first].reset_index(drop=True), y[first]
        cont = [c for c in X.columns if c not in cats]
        L = np.log1p(X[cont].astype(float).fillna(-0.5).clip(lower=-0.5))
        scaler = (L.median(), (L.quantile(.75) - L.quantile(.25)).replace(0, 1.0))
        smote_cats = cats
    else:
        smote_cats = [c for c in F.CATEGORICAL_CODES if c in X.columns]
    n0 = len(X)
    Xf, yf, sm = _smote(X, y, smote_cats, rec, classes, scaler, weights=w)
    if w is not None:
        w = np.r_[w, np.ones(len(Xf) - n0)]
    params = catboost_params(rec)
    if rec["device"] == "GPU" and rec.get("lr_rule") == "cpu_auto_probe":
        probe = CatBoostClassifier(**catboost_params(rec, device="CPU"))
        probe.fit(Pool(Xf, yf, cat_features=cats, weight=w), callbacks=[_StopAfterFirst()])
        params["learning_rate"] = float(probe.get_all_params()["learning_rate"])
    m = CatBoostClassifier(**params)
    t0 = time.perf_counter()
    m.fit(Pool(Xf, yf, cat_features=cats, weight=w))
    return {"model": m, "pipe": pipe, "cats": cats, "columns": list(X.columns), "classes": classes,
            "fit_s": time.perf_counter() - t0, "n_fit": int(len(yf)), "n_unique_fit": int(n0), "smote": sm}


def predict(arm, df, ctx, seed):
    from catboost import Pool
    X, cats = arm["pipe"].transform(df, ctx=ctx, seed=seed)
    return arm["model"].predict_proba(Pool(X[arm["columns"]], cat_features=cats))


# --------------------------------------------------------------------------- metrics
def false_incidents(g, alert, cooldown_ms=900_000):
    """Incidents (src IP, cooldown on available_at) whose alerted flows are all Benign (corrected)."""
    a = g.loc[alert, [F.SRC, "available_at", "label_corrected"]].sort_values("available_at")
    n_inc = n_false = 0
    for _, h in a.groupby(F.SRC):
        last, att = None, False
        for t, lab in zip(h.available_at.to_numpy(), h.label_corrected.to_numpy()):
            if last is not None and t - last > cooldown_ms:
                n_inc += 1; n_false += int(not att); att = False
            att |= lab != BENIGN
            last = t
        if last is not None:
            n_inc += 1; n_false += int(not att)
    hours = (g.available_at.max() - g.available_at.min()) / 3_600_000
    return {"incidents": n_inc, "false_incidents": n_false, "false_incidents_per_hour": n_false / max(hours, 1e-9)}


def evaluate_arm(arm, d, ctx, seed, cfg, train_fps):
    classes = arm["classes"]
    alpha = cfg["fe_study"]["alpha"]
    out = {}
    va = d[d.study_role == "inner_val"]
    P = predict(arm, va, ctx, seed)
    yv = va.label_corrected.to_numpy()
    pred = np.asarray(classes)[P.argmax(1)]
    labs = [c for c in classes if (yv == c).any()]
    out["M1_macro_f1"] = float(f1_score(yv, pred, labels=labs, average="macro"))
    pc = f1_score(yv, pred, labels=labs, average=None)
    out["per_class_f1"] = {c: {"f1": float(f), "support": int((yv == c).sum()), "inconclusive": bool((yv == c).sum() < 30)}
                           for c, f in zip(labs, pc)}
    unseen = ~pd.Series(F.fingerprint(va)).isin(train_fps).to_numpy()
    lu = [c for c in labs if (yv[unseen] == c).any()]
    out["M3_macro_f1_unseen_fp"] = float(f1_score(yv[unseen], pred[unseen], labels=lu, average="macro"))
    out["M3_support"] = {c: int((yv[unseen] == c).sum()) for c in lu}
    # threshold on calibration benign
    ca = d[(d.study_role == "calib") & (d.label_corrected == BENIGN)]
    sc = 1 - predict(arm, ca, ctx, seed)[:, 0]
    thr, realised = threshold_at_fpr(sc, alpha)
    out["threshold"] = {"value": float(thr), "realised_calib_fpr": float(realised)}
    out["M2"] = {}
    for seg in cfg["fe_study"]["dev_fp_segments"]:
        g = d[(d.segment == seg) & ~d.status.isin(EXCLUDE_STATUS)]
        s = 1 - predict(arm, g, ctx, seed)[:, 0]
        alert = s >= thr
        ben = g.label_corrected.to_numpy() == BENIGN
        k, n = int((alert & ben).sum()), int(ben.sum())
        r = {"benign_fpr": k / n, "fp": k, "n_benign": n, "fpr_wilson95": wilson(k, n),
             "attack_recall": float(alert[~ben].mean()) if (~ben).any() else None}
        r.update(false_incidents(g, alert))
        out["M2"][seg] = r
    out["M2_mean_fpr"] = float(np.mean([v["benign_fpr"] for v in out["M2"].values()]))
    out["M2_false_inc_per_hour"] = float(np.mean([v["false_incidents_per_hour"] for v in out["M2"].values()]))
    out["n_features"] = len(arm["columns"])
    out["fit_s"] = round(arm["fit_s"], 1)
    return out


# --------------------------------------------------------------------------- diagnostics
def adversarial_auc(d, spec, ctx, cfg, seed=0, n=200_000):
    """Label-free drift: AUC of a classifier separating inner-train rows from dev rows (S1+R1)."""
    from catboost import CatBoostClassifier, Pool
    a = d[d.study_role == "inner_train"].sample(n, random_state=seed)
    b = d[d.study_role == "dev"].sample(n, random_state=seed)
    pipe = FeaturePipeline(spec).fit(d[d.study_role == "inner_train"])
    Xa, cats = pipe.transform(a, ctx=ctx, seed=seed)
    Xb, _ = pipe.transform(b, ctx=ctx, seed=seed)
    X = pd.concat([Xa, Xb], ignore_index=True)
    y = np.r_[np.zeros(len(Xa)), np.ones(len(Xb))]
    idx = np.random.default_rng(seed).permutation(len(X))
    tr, te = idx[: len(X) // 2], idx[len(X) // 2:]
    m = CatBoostClassifier(iterations=300, depth=6, verbose=0, random_seed=seed, thread_count=8)
    m.fit(Pool(X.iloc[tr], y[tr], cat_features=cats))
    p = m.predict_proba(Pool(X.iloc[te], cat_features=cats))[:, 1]
    imp = pd.Series(m.get_feature_importance(), index=X.columns).sort_values(ascending=False)
    return {"auc": float(roc_auc_score(y[te], p)), "top_drift_features": imp.head(10).round(2).to_dict()}


def benign_segment_probe(d, cfg, seed=0, n_per=20_000):
    """Shortcut probe (deviation from the declared host probe, which is degenerate with one attacker
    per class): can ONE feature identify the capture segment of BENIGN inner-train rows?"""
    from catboost import CatBoostClassifier
    b = d[(d.study_role == "inner_train") & (d.label_corrected == BENIGN)]
    b = pd.concat([g.sample(min(len(g), n_per), random_state=seed) for _, g in b.groupby("segment")])
    y = b.segment.to_numpy()
    idx = np.random.default_rng(seed).permutation(len(b))
    tr, te = idx[: len(b) // 2], idx[len(b) // 2:]
    res = {}
    for c in F.FEATURES:
        x = b[[c]].to_numpy(float)
        m = CatBoostClassifier(iterations=200, depth=4, verbose=0, random_seed=seed, thread_count=8)
        m.fit(x[tr], y[tr])
        res[c] = float(f1_score(y[te], m.predict(x[te]).ravel(), average="macro"))
    return {"chance": 1 / b.segment.nunique(), "macro_f1_by_feature": dict(sorted(res.items(), key=lambda kv: -kv[1]))}


def group_permutation_importance(arm, d, ctx, seed, groups):
    va = d[d.study_role == "inner_val"]
    X, cats = arm["pipe"].transform(va, ctx=ctx, seed=seed)
    X = X[arm["columns"]]
    from catboost import Pool
    yv = va.label_corrected.to_numpy()
    labs = [c for c in arm["classes"] if (yv == c).any()]
    base = f1_score(yv, np.asarray(arm["classes"])[arm["model"].predict_proba(Pool(X, cat_features=cats)).argmax(1)],
                    labels=labs, average="macro")
    out = {}
    rng = np.random.default_rng(seed)
    for g, cols in groups.items():
        cols = [c for c in cols if c in X.columns]
        if not cols:
            continue
        Xp = X.copy()
        Xp[cols] = Xp[cols].iloc[rng.permutation(len(Xp))].to_numpy()
        p = np.asarray(arm["classes"])[arm["model"].predict_proba(Pool(Xp, cat_features=cats)).argmax(1)]
        out[g] = float(base - f1_score(yv, p, labels=labs, average="macro"))
    return out


# --------------------------------------------------------------------------- study driver
def _summ(rows):
    m1 = np.array([r["M1_macro_f1"] for r in rows]); m3 = np.array([r["M3_macro_f1_unseen_fp"] for r in rows])
    m2 = np.array([r["M2_mean_fpr"] for r in rows]); fi = np.array([r["M2_false_inc_per_hour"] for r in rows])
    return {"M1_mean": m1.mean(), "M1_sd": m1.std(), "M3_mean": m3.mean(), "M3_sd": m3.std(), "M2_fpr_mean": m2.mean(),
            "M2_fpr_sd": m2.std(), "false_inc_h_mean": fi.mean(), "M1_seeds": m1.tolist(), "M2_seeds": m2.tolist()}


def run_study(cfg):
    fs = cfg["fe_study"]
    seeds = fs["seeds"]
    out_dir = K.path(cfg, "derived") / "study"
    out_dir.mkdir(parents=True, exist_ok=True)
    d, ctx = load(cfg)
    tr = d[d.study_role == "inner_train"].copy()
    train_fps = set(F.fingerprint(tr))
    log = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "exact_duplicates_removed": d.attrs.get("exact_duplicates_removed"),
           "study_role_counts": d.study_role.value_counts().to_dict(), "arms": {}, "decisions": []}
    path = out_dir / "STUDY.json"

    def save():
        path.write_text(json.dumps(log, indent=2, default=str), encoding="utf-8")

    def arm(name, spec):
        rows = []
        for s in seeds:
            a = fit_arm(spec, tr, s, cfg, ctx)
            r = evaluate_arm(a, d, ctx, s, cfg, train_fps)
            rows.append(r)
            print(f"{name} seed {s}: M1 {r['M1_macro_f1']:.4f} M3 {r['M3_macro_f1_unseen_fp']:.4f} "
                  f"M2 {r['M2_mean_fpr']:.5f} fi/h {r['M2_false_inc_per_hour']:.2f} ({r['fit_s']} s)", flush=True)
        log["arms"][name] = {"spec": spec, "seeds": rows, "summary": _summ(rows)}
        save()
        return log["arms"][name]["summary"]

    def m2_ok(cand, ref_name):
        ref = log["arms"][ref_name]["seeds"]
        ups = [np.mean([r["M2"][s]["fpr_wilson95"][1] for r in ref]) for s in fs["dev_fp_segments"]]
        cf = [np.mean([r["M2"][s]["benign_fpr"] for r in log["arms"][cand]["seeds"]]) for s in fs["dev_fp_segments"]]
        return all(c <= u for c, u in zip(cf, ups))

    # 1) G0 vs G_prep
    s0 = arm("G0", {})
    sp = arm("G_prep", {"prep": True})
    dm1 = sp["M1_mean"] - s0["M1_mean"]
    acc = dm1 > 0 and dm1 > max(sp["M1_sd"], s0["M1_sd"]) and m2_ok("G_prep", "G0")
    ref_name, ref_spec = ("G_prep", {"prep": True}) if acc else ("G0", {})
    log["decisions"].append({"group": "G_prep", "dM1": dm1, "M2_ok": m2_ok("G_prep", "G0"), "accepted": acc})
    # 2) shortcut drop (group) + adversarial drift
    spec_sd = dict(ref_spec, drop=SHORTCUT)
    ssd = arm("G_shortcut_drop", spec_sd)
    adv_ref = adversarial_auc(d, ref_spec, ctx, cfg)
    adv_sd = adversarial_auc(d, spec_sd, ctx, cfg)
    sref = log["arms"][ref_name]["summary"]
    dm1 = ssd["M1_mean"] - sref["M1_mean"]
    acc = dm1 >= -0.01 and (ssd["M2_fpr_mean"] < sref["M2_fpr_mean"] or adv_sd["auc"] < adv_ref["auc"])
    log["decisions"].append({"group": "G_shortcut_drop", "dM1": dm1, "dM2": ssd["M2_fpr_mean"] - sref["M2_fpr_mean"],
                             "adv_auc_ref": adv_ref, "adv_auc_drop": adv_sd, "accepted": acc})
    if acc:
        ref_name, ref_spec = "G_shortcut_drop", spec_sd
    save()
    # 3) additive groups with controls
    for g in ("ratio", "flag", "ctx"):
        spec = dict(ref_spec, **{g: True})
        sg = arm(f"G_{g}", spec)
        k = len([c for c in FeaturePipeline(spec).fit(tr).transform(tr.head(1000), ctx=ctx)[0].columns
                 if c.startswith({"ratio": "r_", "flag": "f_", "ctx": "ctx_"}[g])])
        sperm = arm(f"G_{g}_permuted", dict(spec, permute=g))
        snoise = arm(f"G_{g}_noise", dict(ref_spec, noise=k))
        sref = log["arms"][ref_name]["summary"]
        dm1 = sg["M1_mean"] - sref["M1_mean"]
        acc = (dm1 > 0 and dm1 > max(sg["M1_sd"], sref["M1_sd"]) and sg["M1_mean"] > sperm["M1_mean"]
               and m2_ok(f"G_{g}", ref_name))
        log["decisions"].append({"group": f"G_{g}", "n_cols": k, "dM1": dm1, "M1_permuted": sperm["M1_mean"],
                                 "M1_noise": snoise["M1_mean"], "dM3": sg["M3_mean"] - sref["M3_mean"],
                                 "dM2": sg["M2_fpr_mean"] - sref["M2_fpr_mean"], "M2_ok": m2_ok(f"G_{g}", ref_name),
                                 "accepted": acc})
        if acc:
            ref_name, ref_spec = f"G_{g}", spec
        save()
    # 4) diagnostics on the final reference (seed 0)
    log["final_spec"] = ref_spec
    log["final_arm"] = ref_name
    a = fit_arm(ref_spec, tr, seeds[0], cfg, ctx)
    cols = a["columns"]
    groups = {"ratio": [c for c in cols if c.startswith("r_")], "flag": [c for c in cols if c.startswith("f_")],
              "ctx": [c for c in cols if c.startswith("ctx_")], "shortcut": [c for c in SHORTCUT if c in cols],
              "ports": [F.SPORT, F.DPORT], "sizes": ["IN_BYTES", "OUT_BYTES", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT",
                                                     "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN"],
              "timing": [c for c in cols if "IAT" in c or "DURATION" in c],
              "flags_raw": ["TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS"]}
    log["permutation_importance_final_seed0"] = group_permutation_importance(a, d, ctx, seeds[0], groups)
    log["feature_importance_final_seed0"] = pd.Series(a["model"].get_feature_importance(), index=cols) \
        .sort_values(ascending=False).head(25).round(2).to_dict()
    log["benign_segment_probe"] = benign_segment_probe(d, cfg)
    log["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save()
    return {"decisions": log["decisions"], "final_arm": ref_name, "final_spec": ref_spec}


# --------------------------------------------------------------------------- Phase 5
def run_final(cfg):
    raise NotImplementedError("Phase 5 runs only after the study is frozen (tag fe-v2-frozen)")
