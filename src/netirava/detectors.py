"""Detectors.

A0-CIC (active): the NP-v1 CatBoost anchor recipe re-fitted on CIC known
classes (new model, own class map; not the UNSW checkpoint). Inherits base
params, device and lr_rule cpu_auto_probe from experiments/nextphase/configs.yaml
when present; SMOTE rule "classes with < 1000 training rows -> 1000" (SMOTENC).
Outputs: predicted known class, full probability vector, attack_score =
1 - p(Benign) (a decision score, not a calibrated probability).

Anomaly (shadow): IsolationForest fitted on TRAIN benign flows; score =
-score_samples (higher = more anomalous); predict() is never used.

Thresholds of both are chosen on CALIBRATION benign flows only.
"""

import json
import pickle
import time
from pathlib import Path

import numpy as np
import yaml

from netirava import config as K
from netirava import features as F

def threshold_at_fpr(benign_scores, target_fpr):
    """Smallest threshold t such that the share of benign scores >= t is <= target.
    Alerting rule everywhere: score >= t. Returns t and the realised share."""
    s = np.sort(np.asarray(benign_scores, float))[::-1]
    n = len(s)
    k = int(np.floor(target_fpr * n))           # number of benign allowed at or above t
    t = float(np.nextafter(s[k], np.inf)) if k < n else float(s[-1])
    realised = float((s >= t).mean())
    return t, realised


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [float(max(0.0, c - h)), float(min(1.0, c + h))]


# ------------------------------------------------------------ A0
BENIGN = "Benign"


def reference_recipe(cfg):
    """Base params from the NP-v1 config if available, else the documented fallback."""
    ref = cfg["a0"].get("reference_config")
    p = Path(ref) if ref and Path(ref).is_absolute() else (K.ROOT / ref if ref else None)
    if p and p.exists():
        r = yaml.safe_load(p.read_text(encoding="utf-8"))
        rec = {"source": str(p), "sha1": K.sha1_file(p), "base": dict(r["base"]), "device": r.get("device", "CPU"),
               "lr_rule": r.get("lr_rule"), "smote_lt": r["models"]["A0"]["smote_lt"],
               "smote_k": r["models"]["A0"]["smote_k"]}
    else:
        rec = {"source": "fallback (NP-v1 config not found)", "sha1": None,
               "base": {"boosting_type": "Plain", "verbose": 0, "iterations": 1000, "depth": 6, "l2_leaf_reg": 3,
                        "thread_count": 8}, "device": "CPU", "lr_rule": None, "smote_lt": 1000, "smote_k": 5}
    over = cfg["a0"].get("params_override") or {}
    rec["base"].update(over)
    if "device" in cfg["a0"]:
        rec["device"] = cfg["a0"]["device"]
    rec["seed"] = int(cfg["a0"]["seed"])
    return rec


def catboost_params(rec, device=None):
    p = dict(rec["base"])
    p["random_seed"] = rec["seed"]
    p["loss_function"] = "MultiClass"
    dev = device or rec["device"]
    if dev == "GPU":
        p["task_type"] = "GPU"
        p.pop("thread_count", None)
    return p


class _StopAfterFirst:
    def after_iteration(self, info):
        return False


def smote_plan(counts, lt, k):
    """{class_id: target} for classes with 2 <= n < lt (LCCDE rule). Classes with
    n <= k cannot use k neighbours; they are reported, not silently duplicated."""
    plan = {c: lt for c, n in enumerate(counts) if 2 <= n < lt}
    too_small = [c for c, n in enumerate(counts) if 0 < n <= k and c in plan]
    return plan, too_small


def apply_smote(X, y, rec, classes):
    counts = np.bincount(y, minlength=len(classes))
    plan, too_small = smote_plan(counts, rec["smote_lt"], rec["smote_k"])
    info = {"rule": f"classes with < {rec['smote_lt']} training rows -> {rec['smote_lt']}",
            "counts_before": {classes[i]: int(n) for i, n in enumerate(counts)}, "plan": {classes[c]: t for c, t in plan.items()}}
    if too_small:
        raise ValueError(f"classes too small for SMOTE k={rec['smote_k']}: {[classes[c] for c in too_small]} "
                         "- remove them from known_classes or record a deviation")
    if not plan:
        info["applied"] = False
        info["note"] = "no class below the threshold: no synthetic rows"
        return X, y, info
    from imblearn.over_sampling import SMOTENC
    cat_idx = [F.FEATURES.index(c) for c in F.CATEGORICAL_CODES]
    sm = SMOTENC(categorical_features=cat_idx, sampling_strategy=plan, k_neighbors=rec["smote_k"], random_state=rec["seed"])
    Xr, yr = sm.fit_resample(X, y)
    info["applied"] = True
    info["method"] = "SMOTENC (categorical codes copied from neighbours, not interpolated)"
    info["counts_after"] = {classes[i]: int(n) for i, n in enumerate(np.bincount(yr, minlength=len(classes)))}
    return Xr, yr.astype(np.int64), info


class A0:
    def __init__(self, model, classes, threshold, meta):
        self.model, self.classes, self.threshold, self.meta = model, list(classes), float(threshold), meta
        self.benign_idx = self.classes.index(BENIGN)
        self.version = meta["model_hash"]

    def score(self, X):
        P = self.model.predict_proba(X)
        attack = 1.0 - P[:, self.benign_idx]
        return P, attack, P.argmax(1)

    @staticmethod
    def load(path):
        from catboost import CatBoostClassifier
        path = Path(path)
        meta = json.loads((path / "a0_meta.json").read_text(encoding="utf-8"))
        m = CatBoostClassifier()
        m.load_model(str(path / "a0.cbm"))
        return A0(m, meta["classes"], meta["threshold"]["value"], meta)


VARIANTS = {   # imbalance handling (v2 ablation); "a0" is the deployed, pre-declared recipe
    "a0": {"smote": True, "class_weights": None},            # NP-v1 anchor: SMOTE classes < 1000 rows -> 1000
    "a1": {"smote": False, "class_weights": None},           # no resampling, no weights
    "a2": {"smote": False, "class_weights": "SqrtBalanced"}, # CatBoost auto_class_weights, no resampling
}


def train_a0(cfg, variant="a0", seed=None):
    from catboost import CatBoostClassifier
    vcfg = VARIANTS[variant]
    from netirava.dataset import training_frame
    t0 = time.perf_counter()
    classes = list(cfg["a0"]["known_classes"])
    assert classes[0] == BENIGN
    tr = training_frame(cfg, ["train"])
    unknown_in_train = sorted(set(tr[F.LABEL]) - set(classes))
    assert not unknown_in_train, f"train windows contain labels outside known_classes: {unknown_in_train}"
    y = tr[F.LABEL].map({c: i for i, c in enumerate(classes)}).to_numpy(np.int64)
    X = F.matrix(tr)
    rec = reference_recipe(cfg)
    if seed is not None:
        rec["seed"] = int(seed)
    if vcfg["smote"]:
        Xf, yf, sm = apply_smote(X, y, rec, classes)
    else:
        Xf, yf, sm = X, y, {"applied": False, "note": f"variant {variant}: no resampling"}
    params = catboost_params(rec)
    probe_params = catboost_params(rec, device="CPU")
    if vcfg["class_weights"]:
        params["auto_class_weights"] = probe_params["auto_class_weights"] = vcfg["class_weights"]
    lr_info = None
    if rec["device"] == "GPU" and rec.get("lr_rule") == "cpu_auto_probe":
        probe = CatBoostClassifier(**probe_params)
        probe.fit(Xf, yf, callbacks=[_StopAfterFirst()])
        params["learning_rate"] = float(probe.get_all_params()["learning_rate"])
        lr_info = {"rule": "cpu_auto_probe", "learning_rate": params["learning_rate"]}
    m = CatBoostClassifier(**params)
    t1 = time.perf_counter()
    m.fit(Xf, yf)
    fit_s = time.perf_counter() - t1
    out = K.path(cfg, "models") / (variant if rec["seed"] == int(cfg["a0"]["seed"]) else f"{variant}_s{rec['seed']}")
    out.mkdir(parents=True, exist_ok=True)
    m.save_model(str(out / "a0.cbm"))
    model_hash = K.sha1_file(out / "a0.cbm")[:12]
    allp = m.get_all_params()
    # ---- threshold on the calibration role, benign rows only
    cal = training_frame(cfg, ["calibration"])
    Pc = m.predict_proba(F.matrix(cal))
    sc = 1.0 - Pc[:, 0]
    ben = cal[F.LABEL].to_numpy() == BENIGN
    target = float(cfg["a0"]["target_fpr"])
    thr, realised = threshold_at_fpr(sc[ben], target)
    nb = int(ben.sum())
    k = int(round(realised * nb))
    thr_info = {"value": thr, "rule": "smallest t with share(benign calibration score >= t) <= target",
                "target_fpr": target, "realised_fpr_calibration": realised, "n_benign_calibration": nb,
                "wilson95": wilson(k, nb), "n_attack_rows_in_calibration": int((~ben).sum()),
                "uncertain": bool(nb < 10 / target),
                "note": "attack_score = 1 - p(Benign); not a calibrated probability"}
    counts = np.bincount(y, minlength=len(classes))
    meta = {"detector": "a0", "variant": variant, "variant_config": vcfg, "model_hash": model_hash, "classes": classes,
            "class_map": {c: i for i, c in enumerate(classes)},
            "train_counts": {c: int(n) for c, n in zip(classes, counts)},
            "train_prior": {c: float(n / counts.sum()) for c, n in zip(classes, counts)},
            "n_train": int(len(y)), "smote": sm, "recipe": {k2: v for k2, v in rec.items()},
            "catboost_params_passed": params, "lr_rule": lr_info,
            "resolved_params": {k2: allp.get(k2) for k2 in ("learning_rate", "iterations", "depth", "l2_leaf_reg",
                                                            "border_count", "bootstrap_type", "loss_function",
                                                            "boosting_type", "task_type", "random_seed")},
            "feature_schema": F.FEATURE_SCHEMA_VERSION, "feature_schema_hash": F.schema_hash(), "features": F.FEATURES,
            "features_kept_note": "ports, TTL and DNS_QUERY_ID kept; IPs, absolute timestamps and labels excluded",
            "threshold": thr_info, "fit_seconds": fit_s, "total_seconds": time.perf_counter() - t0,
            "catboost_version": __import__("catboost").__version__,
            "deviations_from_np_v1": [
                "dataset/taxonomy: CIC-2018 known classes instead of UNSW 10 classes (new fit, new class map)",
                "single seed (a0.seed) instead of 3-seed evaluation",
                "train rows = configured train windows (chronological), not the NP-v1 grouped CV",
                "threshold on attack_score chosen on a calibration window (NP-v1 used argmax only)"],
            "config_sha1": cfg["_sha1"]}
    (out / "a0_meta.json").write_text(json.dumps(meta, indent=2, default=str))
    write_model_card(meta, out / "MODEL_CARD.md")
    return {k2: meta[k2] for k2 in ("model_hash", "classes", "train_counts", "threshold", "fit_seconds", "resolved_params")}


def write_model_card(meta, path):
    t = meta["threshold"]
    lines = [
        f"# Model card — A0-CIC ({meta['model_hash']})", "",
        "CatBoost MultiClass, công thức anchor NP-v1, **fit mới trên CIC-2018**; không dùng trọng số UNSW.", "",
        f"- Known classes ({len(meta['classes'])}): " + ", ".join(meta["classes"]),
        f"- Train rows: {meta['n_train']:,} — " + ", ".join(f"{c} {n:,}" for c, n in meta["train_counts"].items()),
        f"- SMOTE: {meta['smote'].get('note', meta['smote'].get('method'))}",
        f"- Recipe source: {meta['recipe']['source']} (sha1 {meta['recipe']['sha1']})",
        f"- Device: {meta['resolved_params']['task_type']}; learning rate {meta['resolved_params']['learning_rate']} "
        f"({'cpu_auto_probe' if meta['lr_rule'] else 'CatBoost default'}); iterations {meta['resolved_params']['iterations']}, "
        f"depth {meta['resolved_params']['depth']}, l2 {meta['resolved_params']['l2_leaf_reg']}, border {meta['resolved_params']['border_count']}, seed {meta['resolved_params']['random_seed']}",
        f"- Features: {len(meta['features'])} ({meta['feature_schema']}); {meta['features_kept_note']}",
        f"- Output: predicted known class, full probability vector, attack_score = 1 − p(Benign) (decision score, not calibrated)",
        f"- Threshold: {t['value']:.6g} at target benign FPR {t['target_fpr']} on {t['n_benign_calibration']:,} calibration benign flows; "
        f"realised {t['realised_fpr_calibration']:.5f} (Wilson 95% {t['wilson95']}); uncertain={t['uncertain']}",
        "- Cannot name classes it was not trained on: unknown attacks can only surface as high attack_score.",
        "- Deviations from NP-v1: " + "; ".join(meta["deviations_from_np_v1"]),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------ anomaly
class Anomaly:
    def __init__(self, model, threshold, meta):
        self.model, self.threshold, self.meta = model, float(threshold), meta
        self.version = meta["model_hash"]

    def score(self, X):
        return -self.model.score_samples(F.log1p_signed(X))

    @staticmethod
    def load(path):
        with open(path / "anomaly.pkl", "rb") as f:
            m = pickle.load(f)
        meta = json.loads((path / "anomaly_meta.json").read_text(encoding="utf-8"))
        return Anomaly(m, meta["threshold"]["value"], meta)


def train_anomaly(cfg):
    from sklearn.ensemble import IsolationForest
    from netirava.dataset import training_frame
    c = cfg["anomaly"]
    t0 = time.perf_counter()
    tr = training_frame(cfg, ["train"])
    ben = tr[tr[F.LABEL] == "Benign"].sort_values("row_id")
    n_avail = len(ben)
    if n_avail > c["max_train_rows"]:
        rng = np.random.default_rng(0)
        ben = ben.iloc[np.sort(rng.choice(n_avail, c["max_train_rows"], replace=False))]
    X = F.log1p_signed(F.matrix(ben))
    m = IsolationForest(n_estimators=c["n_estimators"], max_samples=c["max_samples"], contamination=c["contamination"],
                        random_state=c["random_state"], n_jobs=c["n_jobs"])
    m.fit(X)
    out = K.path(cfg, "models") / "anomaly"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "anomaly.pkl", "wb") as f:
        pickle.dump(m, f)
    cal = training_frame(cfg, ["calibration"])
    cb = cal[F.LABEL].to_numpy() == "Benign"
    s = -m.score_samples(F.log1p_signed(F.matrix(cal)))
    thr, realised = threshold_at_fpr(s[cb], c["target_fpr"])
    nb = int(cb.sum())
    meta = {"detector": "anomaly", "model_hash": K.sha1_file(out / "anomaly.pkl")[:12],
            "algorithm": "sklearn IsolationForest", "params": {k: c[k] for k in ("n_estimators", "max_samples", "contamination", "random_state", "n_jobs")},
            "train_rows": int(len(ben)), "train_benign_available": int(n_avail),
            "sampling": f"uniform without replacement, numpy seed 0, cap {c['max_train_rows']} (train-role benign rows, source labels)",
            "transform": "sign(x)*log1p(|x|) on the 49 allowlisted features (fixed, not learned)",
            "score": "-score_samples (higher = more anomalous); predict() not used",
            "threshold": {"value": thr, "target_fpr": c["target_fpr"], "realised_fpr_calibration": realised,
                          "n_benign_calibration": nb, "wilson95": wilson(int(round(realised * nb)), nb),
                          "uncertain": bool(nb < 10 / c["target_fpr"])},
            "feature_schema_hash": F.schema_hash(), "fit_seconds": time.perf_counter() - t0,
            "sklearn_version": __import__("sklearn").__version__, "config_sha1": cfg["_sha1"]}
    (out / "anomaly_meta.json").write_text(json.dumps(meta, indent=2))
    return meta
