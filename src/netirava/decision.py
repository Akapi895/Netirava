"""Decision layer, evaluated offline on stored scores (detections.parquet).

All variants are calibrated on CALIBRATION benign flows to the same total
flow-level FPR target alpha (several levels), and judged per flow:
  V1  A0 only        a0 >= t_a0(alpha)
  V2  anomaly only   an >= t_an(alpha)
  V3  OR             a0 >= t_a0(alpha/2) or an >= t_an(alpha/2)      (equal FPR split)
  V4  A0 + entity evidence (proposed):
        a0 >= t_a0(alpha/2)  or  [ an >= q_rho  and  E_W >= k(alpha/2) ]
      q_rho  = calibration-benign (1-rho) quantile of the anomaly score
      E_W    = number of flows of the same entity (source IP) with an >= q_rho
               decided in (t - W, t]  (causal: only flows already decided)
      k      = smallest count with calibration-benign FPR of the bracket <= alpha/2
  Ablations of V4: V4-a0agg (same evidence rule on the A0 score instead of the
  anomaly score) and V4-evidence-only (bracket alone at the full alpha).
  V4a (above) was the first pre-declared design; it gave no development gain because
  Bot flows sit between the 90th and 95th calibration-benign percentiles (never in
  the tail counted by E_W). Second and last design iteration, from that error:
  V4b A0 + entity mean:
        a0 >= t_a0(alpha/2)  or  [ n_W >= m  and  mean_W(an) >= tau(alpha/2) ]
      n_W, mean_W = number of flows and mean anomaly score of the same entity
      decided in (t - W, t] (causal); tau calibrated on calibration-benign flows.
  Ablations of V4b: same rule on the A0 score, and the bracket alone at alpha.
Union bounds keep every variant's calibration FPR <= alpha. Thresholds use
calibration only; development scenarios choose (W, rho) on a pre-declared
grid; the holdout is evaluated once with frozen parameters.
"""

import json

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, load_truth, training_frame, window_bounds
from netirava.detectors import A0, Anomaly, threshold_at_fpr, wilson

HOUR = 3_600_000


# ----------------------------------------------------------------------------- scores
def score_calibration(cfg):
    """A0 and anomaly scores of the calibration window (benign-only labels used for thresholds)."""
    m = K.path(cfg, "models")
    a0, an = A0.load(m / "a0"), Anomaly.load(m / "anomaly")
    cal = training_frame(cfg, ["calibration"])
    X = F.matrix(cal)
    tick = int(cfg["replay"]["decision_tick_ms"])
    df = pd.DataFrame({"flow_id": cal.flow_id, "segment": cal.segment, "entity": cal[cfg["policy"]["entity"]].astype(str),
                       "decision_at": ((cal.available_at + tick - 1) // tick) * tick,
                       "a0_score": a0.score(X)[1], "an_score": an.score(X), "is_benign": cal[F.LABEL] == "Benign"})
    df.to_parquet(m / "calibration_scores.parquet", index=False)
    return df


def entity_evidence(df, flag, window_ms):
    """Causal count of flagged flows per entity in (t - W, t], computed within each segment."""
    out = np.zeros(len(df), np.int64)
    for _, idx in df.groupby("segment").indices.items():
        g = df.iloc[idx]
        ec = pd.factorize(g.entity)[0].astype(np.int64)
        rel = (g.decision_at - g.decision_at.min()).to_numpy(np.int64)
        key = ec * (1 << 42) + rel
        order = np.argsort(key, kind="stable")
        ks, fs = key[order], flag[idx][order].astype(np.int64)
        csum = np.concatenate([[0], np.cumsum(fs)])
        hi = np.searchsorted(ks, key, side="right")
        lo = np.searchsorted(ks, key - window_ms, side="right")
        out[idx] = csum[hi] - csum[lo]
    return out


def entity_window_mean(df, score, window_ms):
    """Causal (count, mean score) of all flows of the same entity in (t - W, t], within each segment."""
    n = np.zeros(len(df), np.int64)
    mean = np.zeros(len(df))
    for _, idx in df.groupby("segment").indices.items():
        g = df.iloc[idx]
        ec = pd.factorize(g.entity)[0].astype(np.int64)
        rel = (g.decision_at - g.decision_at.min()).to_numpy(np.int64)
        key = ec * (1 << 42) + rel
        order = np.argsort(key, kind="stable")
        ks, sc = key[order], score[idx][order]
        cs = np.concatenate([[0.0], np.cumsum(sc)])
        hi = np.searchsorted(ks, key, side="right")
        lo = np.searchsorted(ks, key - window_ms, side="right")
        n[idx] = hi - lo
        mean[idx] = (cs[hi] - cs[lo]) / np.maximum(hi - lo, 1)
    return n, mean


def _k_for(evid_benign, target):
    """Smallest k with share(benign flows with evidence >= k) <= target (evid = 0 means not flagged)."""
    for k in range(1, int(evid_benign.max()) + 2):
        if (evid_benign >= k).mean() <= target:
            return k
    return int(evid_benign.max()) + 1


# ----------------------------------------------------------------------------- calibrate & apply
def calibrate(cal, alpha, W, rho, Wb=None, m=10):
    b = cal[cal.is_benign]
    t = {"alpha": alpha, "W_ms": W, "rho": rho, "Wb_ms": Wb or W, "m": m}
    t["a0_full"], _ = threshold_at_fpr(b.a0_score, alpha)
    t["an_full"], _ = threshold_at_fpr(b.an_score, alpha)
    t["a0_half"], _ = threshold_at_fpr(b.a0_score, alpha / 2)
    t["an_half"], _ = threshold_at_fpr(b.an_score, alpha / 2)
    t["q_an"], _ = threshold_at_fpr(b.an_score, rho)
    t["q_a0"], _ = threshold_at_fpr(b.a0_score, rho)
    ben = cal.is_benign.to_numpy()
    for name, col, q in (("an", "an_score", t["q_an"]), ("a0", "a0_score", t["q_a0"])):
        flag = cal[col].to_numpy() >= q
        ev = np.where(flag, entity_evidence(cal, flag, W), 0)
        t[f"k_{name}_half"] = _k_for(ev[ben], alpha / 2)
        t[f"k_{name}_full"] = _k_for(ev[ben], alpha)
    m, Wb = int(t["m"]), int(t["Wb_ms"])
    for name, col in (("an", "an_score"), ("a0", "a0_score")):
        n, mu = entity_window_mean(cal, cal[col].to_numpy(), Wb)
        v = np.where(n >= m, mu, -np.inf)[ben]
        t[f"tau_{name}_half"], _ = threshold_at_fpr(v, alpha / 2)
        t[f"tau_{name}_full"], _ = threshold_at_fpr(v, alpha)
    return t


def apply(df, t):
    a0, an = df.a0_score.to_numpy(), df.an_score.to_numpy()
    W = t["W_ms"]
    f_an = an >= t["q_an"]
    f_a0 = a0 >= t["q_a0"]
    e_an = np.where(f_an, entity_evidence(df, f_an, W), 0)
    e_a0 = np.where(f_a0, entity_evidence(df, f_a0, W), 0)
    return {
        "V1_A0": a0 >= t["a0_full"],
        "V2_anomaly": an >= t["an_full"],
        "V3_OR": (a0 >= t["a0_half"]) | (an >= t["an_half"]),
        "V4_A0+entity_anomaly": (a0 >= t["a0_half"]) | (e_an >= t["k_an_half"]),
        "abl_V4_A0+entity_a0score": (a0 >= t["a0_half"]) | (e_a0 >= t["k_a0_half"]),
        "abl_V4_entity_anomaly_only": e_an >= t["k_an_full"],
        **_v4b(df, t, a0),
    }


def _v4b(df, t, a0):
    out = {}
    for name, col in (("an", "an_score"), ("a0", "a0_score")):
        n, mu = entity_window_mean(df, df[col].to_numpy(), t["Wb_ms"])
        ok = n >= t["m"]
        out[name] = (ok & (mu >= t[f"tau_{name}_half"]), ok & (mu >= t[f"tau_{name}_full"]))
    return {"V4b_A0+entity_mean_anomaly": (a0 >= t["a0_half"]) | out["an"][0],
            "abl_V4b_A0+entity_mean_a0score": (a0 >= t["a0_half"]) | out["a0"][0],
            "abl_V4b_entity_mean_anomaly_only": out["an"][1]}


# ----------------------------------------------------------------------------- evaluation
def _episodes(d, gap):
    a = d[d.is_attack].sort_values([F.LABEL, "entity", "decision_at"])
    new = (a[F.LABEL] != a[F.LABEL].shift()) | (a.entity != a.entity.shift()) | (a.decision_at.diff() > gap)
    return pd.Series(new.cumsum().to_numpy(), index=a.index)


def _budget(d, alert, B):
    """Causal flow budget: per simulated hour only the first B alerts (time order) are kept."""
    o = np.argsort(d.decision_at.to_numpy(), kind="stable")
    h = (d.decision_at.to_numpy()[o] // HOUR)
    al = alert[o]
    rank = pd.Series(al.astype(int)).groupby(h).cumsum().to_numpy()
    kept = np.zeros(len(d), bool)
    kept[o] = al & (rank <= B)
    return kept


def scenario_metrics(d, alerts, budgets, boot_reps=1000, seed=2027):
    att = d.is_attack.to_numpy()
    ben = ~att
    ep = _episodes(d, 1_800_000)
    ep_full = pd.Series(-1, index=d.index)
    ep_full.loc[ep.index] = ep.values
    epv = ep_full.to_numpy()
    out = {}
    for name, al in alerts.items():
        fp = int((al & ben).sum())
        r = {"benign_fpr": fp / ben.sum() if ben.any() else None, "fp_per_million_benign": 1e6 * fp / ben.sum() if ben.any() else None,
             "benign_fpr_wilson95": wilson(fp, int(ben.sum())) if ben.any() else None,
             "alerts_per_hour": float(al.sum() / max(1, (d.decision_at // HOUR).nunique()))}
        if att.any():
            tp = int((al & att).sum())
            r.update(attack_recall=tp / att.sum(), alert_precision=tp / al.sum() if al.sum() else None,
                     episodes=int(len(np.unique(epv[att]))),
                     episodes_detected=int(len(np.unique(epv[att & al]))))
        for B in budgets:
            kept = _budget(d, al, B)
            if att.any():
                r[f"recall@B{B}"] = float((kept & att).sum() / att.sum())
            r[f"precision@B{B}"] = float((kept & att).sum() / kept.sum()) if kept.sum() else None
        out[name] = r
    # paired episode bootstrap of the attack-recall difference vs V1 and V3
    if att.any():
        e = epv[att]
        ue, inv = np.unique(e, return_inverse=True)
        n_e = np.bincount(inv)
        rng = np.random.default_rng(seed)
        hits = {k: np.bincount(inv, weights=v[att].astype(float)) for k, v in alerts.items()}
        draws = rng.integers(0, len(ue), (boot_reps, len(ue)))
        tot = n_e[draws].sum(1)
        for name in alerts:
            for ref in ("V1_A0", "V3_OR"):
                if name == ref:
                    continue
                dlt = (hits[name][draws].sum(1) - hits[ref][draws].sum(1)) / tot
                out[name][f"delta_recall_vs_{ref}"] = {"point": float((hits[name].sum() - hits[ref].sum()) / n_e.sum()),
                                                       "ci95_episode_bootstrap": [float(np.percentile(dlt, 2.5)), float(np.percentile(dlt, 97.5))],
                                                       "n_episodes": int(len(ue))}
    return out


def evaluate_run(cfg, run_id, params=None, unlock_holdout=False, out_name=None):
    from netirava.storage import RunStore
    dc = cfg["decision"]
    st = RunStore(cfg, run_id)
    det = st.detections(columns=["flow_id", "segment", "entity", "decision_at", "a0_score", "an_score"])
    if st.meta().get("unlock_holdout") and not unlock_holdout:
        raise RuntimeError("run contains the holdout; pass unlock_holdout=True")
    truth = load_truth(cfg)[["flow_id", F.LABEL]]
    d = det.merge(truth, on="flow_id", validate="one_to_one")
    d["is_attack"] = d[F.LABEL] != "Benign"
    scen = {w["id"]: w["scenario"] for w in window_bounds(cfg)}
    d["scenario"] = d.segment.map(scen)
    if not unlock_holdout:
        d = d[d.scenario != "holdout-ddos"]
    cal = pd.read_parquet(K.path(cfg, "models") / "calibration_scores.parquet")
    p = params or dc["v4"]
    res = {"run_id": run_id, "params": p, "levels": {}}
    for alpha in dc["fpr_levels"]:
        t = calibrate(cal, alpha, p["W_ms"], p["rho"], p.get("Wb_ms"), p.get("m", 10))
        res["levels"][str(alpha)] = {"thresholds": t, "scenarios": {}}
        for sc, g in d.groupby("scenario"):
            g = g.reset_index(drop=True)
            res["levels"][str(alpha)]["scenarios"][sc] = scenario_metrics(g, apply(g, t), dc["budgets_per_hour"])
    if out_name:
        (st.dir / out_name).write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    return res


def select_v4b(cfg, run_id, v4a):
    """Second design iteration, same pre-declared rule on DEVELOPMENT unknowns only (Bot, Web): maximise the
    mean flow recall of V4b over the dev scenarios and all FPR levels; ties -> smaller W, then smaller m."""
    dc = cfg["decision"]
    rows = []
    for W in dc["grid_v4b"]["W_ms"]:
        for m in dc["grid_v4b"]["m"]:
            r = evaluate_run(cfg, run_id, {**v4a, "Wb_ms": W, "m": m})
            vals = [r["levels"][a]["scenarios"][s]["V4b_A0+entity_mean_anomaly"]["attack_recall"]
                    for a in r["levels"] for s in dc["dev_scenarios"]]
            rows.append({"Wb_ms": W, "m": m, "dev_mean_recall": float(np.mean(vals))})
    rows.sort(key=lambda x: (-round(x["dev_mean_recall"], 6), x["Wb_ms"], x["m"]))
    return {"rule": select_v4b.__doc__.strip(), "grid": rows, "selected": {"Wb_ms": rows[0]["Wb_ms"], "m": rows[0]["m"]}}


def select_v4(cfg, run_id):
    """Pre-declared selection on DEVELOPMENT unknowns only (Bot, Web): maximise the mean flow recall of
    V4 over the dev scenarios and all FPR levels; ties -> smaller W, then smaller rho."""
    dc = cfg["decision"]
    rows = []
    for W in dc["grid"]["W_ms"]:
        for rho in dc["grid"]["rho"]:
            r = evaluate_run(cfg, run_id, {"W_ms": W, "rho": rho})
            vals = [r["levels"][a]["scenarios"][s]["V4_A0+entity_anomaly"]["attack_recall"]
                    for a in r["levels"] for s in dc["dev_scenarios"]]
            rows.append({"W_ms": W, "rho": rho, "dev_mean_recall": float(np.mean(vals))})
    rows.sort(key=lambda x: (-round(x["dev_mean_recall"], 6), x["W_ms"], x["rho"]))
    return {"rule": select_v4.__doc__.strip(), "grid": rows, "selected": {"W_ms": rows[0]["W_ms"], "rho": rows[0]["rho"]}}
