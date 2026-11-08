"""Drift / threshold-reliability monitor (runtime side, label-free). Pre-registered in
docs/OPS_STUDY_PREREG.md §4.

Reference = the calibration window (C1) scored by the same model, i.e. the data on which the
alert threshold was locked. Per 15-min event-time window of a replay run, four signals:

  AR     alert-rate ratio  share(score >= t_alpha) / alpha
  TR     tail ratio        share(q_ref(1-10 alpha) <= score < t_alpha) / reference share of that band
                           (primary: benign mass moving towards the threshold, below the alert tail)
  S_PSI  prediction drift  PSI of the score on reference-quantile bins
  F_PSI  data drift        median PSI over the 49 model features (+ the top drifting features)

Alarms (declared): AR/TR >= ratio_alarm and one-sided binomial p < p_alarm; PSI >= psi_alarm.
The monitor never changes a prediction, a threshold or an incident, and never reads labels.
"""

import json

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy.stats import binom

from netirava import config as K
from netirava import features as F

EPS = 1e-4
SCORE_Q = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 0.999]


def _dc(cfg):
    return cfg["ops"]["drift"]


def psi(p, q):
    p = np.maximum(np.asarray(p, float), EPS)
    q = np.maximum(np.asarray(q, float), EPS)
    p, q = p / p.sum(), q / q.sum()
    return float(np.sum((p - q) * np.log(p / q)))


def _bin_spec(x, categorical, top_k):
    x = np.asarray(x, float)
    if categorical:
        vals, cnt = np.unique(x, return_counts=True)
        keep = vals[np.argsort(-cnt, kind="stable")[:top_k]]
        return {"kind": "cat", "values": sorted(float(v) for v in keep)}
    edges = np.unique(np.quantile(x, np.linspace(0.1, 0.9, 9)))
    return {"kind": "num", "edges": [float(e) for e in edges]}


def _hist(x, spec):
    x = np.asarray(x, float)
    if spec["kind"] == "cat":
        vals = np.asarray(spec["values"])
        idx = np.searchsorted(vals, x)
        hit = (idx < len(vals)) & (vals[np.minimum(idx, len(vals) - 1)] == x)
        b = np.where(hit, idx, len(vals))
        return np.bincount(b, minlength=len(vals) + 1).astype(float)
    b = np.searchsorted(np.asarray(spec["edges"]), x, side="right")
    return np.bincount(b, minlength=len(spec["edges"]) + 1).astype(float)


def build_reference(cfg, model="a0"):
    """Reference of the monitor for one model, written to <models>/<model>/drift_reference.json.
    Uses the calibration window only (its benign rows already define the locked threshold)."""
    from netirava.dataset import training_frame
    from netirava.detectors import A0, threshold_at_fpr
    dc = _dc(cfg)
    m = A0.load(K.path(cfg, "models") / model)
    cal = training_frame(cfg, ["calibration"])
    cal = cal[cal.segment == dc["reference_window"]]
    ben = (cal[F.LABEL] == "Benign").to_numpy()
    X = F.matrix(cal)
    s = m.score(X)[1]
    sb = s[ben]
    levels = {}
    for a in dc["alphas"]:
        t, real = threshold_at_fpr(sb, a)
        q, _ = threshold_at_fpr(sb, dc["tail_band_factor"] * a)
        band = float(((s >= q) & (s < t)).mean())
        levels[str(a)] = {"t": t, "realised_fpr_ref": real, "q_band": q, "band_share_ref": band,
                          "alert_share_ref": float((s >= t).mean())}
    sq = np.unique(np.quantile(s, SCORE_Q))
    score_spec = {"kind": "num", "edges": [float(e) for e in sq]}
    feats = {}
    for j, c in enumerate(F.FEATURES):
        spec = _bin_spec(X[:, j], c in F.CATEGORICAL_CODES, int(dc["cat_top_k"]))
        h = _hist(X[:, j], spec)
        feats[c] = {**spec, "ref": (h / h.sum()).tolist()}
    hs = _hist(s, score_spec)
    ref = {"model_dir": model, "model_hash": m.version, "model_threshold": m.threshold, "window": dc["reference_window"],
           "n": int(len(s)), "n_benign": int(ben.sum()), "levels": levels,
           "score": {**score_spec, "ref": (hs / hs.sum()).tolist()}, "features": feats,
           "note": "label-free monitor reference; thresholds from calibration benign (same rule as the locked threshold)"}
    out = K.path(cfg, "models") / model / "drift_reference.json"
    out.write_text(json.dumps(ref, indent=1), encoding="utf-8")
    return ref


def load_reference(cfg, model="a0"):
    p = K.path(cfg, "models") / model / "drift_reference.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _ratio_alarm(k, n, p0, ratio_min, p_max):
    ratio = (k / n) / p0 if n and p0 > 0 else np.nan
    p = float(binom.sf(k - 1, n, p0)) if n and p0 > 0 else np.nan
    return ratio, p, bool(ratio >= ratio_min and p < p_max)


def window_signals(scores, X, ref, cfg, top=3):
    """Signals of one monitor window (label-free)."""
    dc = _dc(cfg)
    n = len(scores)
    row = {"n_flows": n}
    for a, lv in ref["levels"].items():
        k_al = int((scores >= lv["t"]).sum())
        k_band = int(((scores >= lv["q_band"]) & (scores < lv["t"])).sum())
        ar, p_ar, al_ar = _ratio_alarm(k_al, n, float(a), dc["ratio_alarm"], dc["p_alarm"])
        tr, p_tr, al_tr = _ratio_alarm(k_band, n, lv["band_share_ref"], dc["ratio_alarm"], dc["p_alarm"])
        row.update({f"AR@{a}": ar, f"AR_p@{a}": p_ar, f"AR_alarm@{a}": al_ar, f"alerts@{a}": k_al,
                    f"TR@{a}": tr, f"TR_p@{a}": p_tr, f"TR_alarm@{a}": al_tr, f"band@{a}": k_band,
                    f"FPR_est@{a}": float(a) * tr})
    row["S_PSI"] = psi(_hist(scores, ref["score"]), ref["score"]["ref"])
    fp = {c: psi(_hist(X[:, j], ref["features"][c]), ref["features"][c]["ref"]) for j, c in enumerate(F.FEATURES)}
    vals = np.array(list(fp.values()))
    row["F_PSI_median"] = float(np.median(vals))
    row["F_PSI_n_major"] = int((vals >= dc["psi_alarm"]).sum())
    row["F_PSI_top"] = ", ".join(f"{c} {v:.2f}" for c, v in sorted(fp.items(), key=lambda x: -x[1])[:top])
    row["S_PSI_alarm"] = bool(row["S_PSI"] >= dc["psi_alarm"])
    row["F_PSI_alarm"] = bool(row["F_PSI_median"] >= dc["psi_alarm"])
    return row


def windows_of(det, window_ms, min_flows):
    """Window index per flow: fixed windows aligned to each segment's first decision; small windows dropped (-1)."""
    start = det.groupby("segment").decision_at.transform("min")
    w = ((det.decision_at - start) // window_ms).astype(np.int64)
    key = det.segment + "#" + w.astype(str)
    size = key.map(key.value_counts())
    return np.where(size >= min_flows, key, None), start + w * window_ms


def status(row, alpha):
    a = str(alpha)
    if row.get(f"TR_alarm@{a}"):
        return "threshold-reliability WARN"
    if row.get(f"AR_alarm@{a}"):
        return "alert-volume ALERT"
    if row.get("S_PSI_alarm") or row.get("F_PSI_alarm"):
        return "distribution drift"
    return "ok"


def monitor_run(cfg, run_id, write=True):
    """Label-free monitor table of a replay run (one row per window). Reads run detections, the
    run's feature stream (no labels) and the reference of the run's model."""
    from netirava.storage import RunStore
    dc = _dc(cfg)
    st = RunStore(cfg, run_id)
    meta = st.meta()
    ref = load_reference(cfg, meta["a0"].get("model_dir") or "a0")
    if ref["model_hash"] != meta["a0"]["model_hash"]:
        raise ValueError(f"reference model {ref['model_hash']} != run model {meta['a0']['model_hash']}")
    det = st.detections(columns=["flow_id", "segment", "decision_at", "a0_score"])
    win, wstart = windows_of(det, int(dc["window_ms"]), int(dc["min_flows"]))
    det = det.assign(window=win, window_start=wstart)
    det = det[det.window.notna()]
    rows = []
    for seg, g in det.groupby("segment", sort=False):
        ids = g.flow_id.to_numpy()
        s = pq.read_table(K.path(cfg, "derived") / "stream.parquet", columns=["flow_id"] + F.FEATURES,
                          filters=[("segment", "=", seg)]).to_pandas().set_index("flow_id").loc[ids]
        X = s[F.FEATURES].to_numpy(np.float64)
        sc = g.a0_score.to_numpy()
        wv = g.window.to_numpy()
        for w in pd.unique(wv):
            m = wv == w
            r = {"window": w, "segment": seg, "window_start": int(g.window_start.to_numpy()[m][0]),
                 **window_signals(sc[m], X[m], ref, cfg)}
            r["status"] = status(r, dc["primary_alpha"])
            rows.append(r)
    tab = pd.DataFrame(rows).sort_values("window_start").reset_index(drop=True)
    tab["window_utc"] = pd.to_datetime(tab.window_start, unit="ms", utc=True).dt.strftime("%m-%d %H:%M")
    if write:
        tab.to_parquet(st.dir / "DRIFT_MONITOR.parquet", index=False)
    return tab
