"""Causal completed-flow replay.

Order: capture segments in chronological order; within a segment by
(available_at, flow_id). available_at = FLOW_END + export_delay (computed in
prepare). A flow is decided at the first decision tick >= available_at; its
batching delay = decision_at - available_at (event time).

Detectors are stateless per flow, so scoring is vectorised over chunks of
consecutive events (fast mode) with outputs identical to per-tick scoring;
the policy then walks the events one by one in decision order. Paced mode
scores tick by tick and sleeps to follow simulated time / speed.

The runtime never reads labels, roles or quality flags: the stream file has
no label column and features.flow_event_batch rejects evaluator columns.
"""

import datetime as dt
import hashlib
import json
import time

import numpy as np
import pandas as pd
import psutil

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, window_bounds
from netirava.detectors import A0, Anomaly
from netirava.policy import Policy
from netirava.storage import RunStore

REPLAY_ROLES = ("known_replay", "replay", "stress")
HOLDOUT_ROLE = "holdout"   # only replayed with unlock_holdout=True, after the method is frozen


def replay_frame(cfg, segments=None, unlock_holdout=False):
    roles = list(REPLAY_ROLES) + ([HOLDOUT_ROLE] if unlock_holdout else [])
    s = load_stream(cfg, roles=roles, segments=segments)
    order = {w["id"]: i for i, w in enumerate(window_bounds(cfg))}
    s["_seg_order"] = s.segment.map(order)
    s = s.sort_values(["_seg_order", "available_at", "flow_id"], kind="stable").reset_index(drop=True)
    return F.flow_event_batch(s.drop(columns=["_seg_order", "role"]))


def score_chunk(X, a0, an, cfg, stats):
    t0 = time.perf_counter()
    P, att, pred = a0.score(X)
    t_a0 = time.perf_counter() - t0
    out = {"P": P, "att": att, "pred": pred, "t_a0": t_a0, "an": None, "an_status": "off", "t_an": 0.0}
    if an is not None:
        t1 = time.perf_counter()
        try:
            out["an"] = an.score(X)
            out["an_status"] = "ok"
        except Exception as e:                       # shadow must not stop the active path
            out["an_status"] = "missing"
            stats["shadow_errors"].append(repr(e))
        out["t_an"] = time.perf_counter() - t1
        if out["an_status"] == "ok" and out["t_an"] * 1000 / max(len(X), 1) > cfg["replay"]["shadow_deadline_ms_per_event"]:
            out["an_status"] = "late"
    return out


def run(cfg, mode="a0", pace="fast", speed=None, segments=None, max_events=None, run_id=None, models_dir=None,
        unlock_holdout=False):
    mdir = models_dir or K.path(cfg, "models")
    a0 = A0.load(mdir / "a0")
    an = Anomaly.load(mdir / "anomaly") if mode == "a0-shadow" else None
    ev = replay_frame(cfg, segments, unlock_holdout)
    if max_events is not None:
        ev = ev.iloc[:max_events].reset_index(drop=True)
    tick = int(cfg["replay"]["decision_tick_ms"])
    avail = ev.available_at.to_numpy(np.int64)
    decision_at = ((avail + tick - 1) // tick) * tick
    pc = cfg["policy"]
    run_id = run_id or (dt.datetime.now().strftime("%Y%m%dT%H%M%S") + f"_{mode}_{pace}")
    store = RunStore(cfg, run_id, create=True)
    active = Policy(pc["cooldown_ms"], pc["budget_per_hour"], shadow=False, id_start=1)
    shadow = Policy(pc["cooldown_ms"], None, shadow=True, id_start=10_000_001) if an is not None else None
    n = len(ev)
    K_ = len(a0.classes)
    P_all = np.zeros((n, K_), np.float32)
    att_all = np.zeros(n)
    pred_all = np.zeros(n, np.int64)
    an_all = np.full(n, np.nan)
    an_status = np.full(n, "off", dtype=object)
    act = np.full(n, "", dtype=object)
    reason = np.full(n, "", dtype=object)
    inc = np.zeros(n, np.int64)
    sinc = np.zeros(n, np.int64)
    chunk_id = np.zeros(n, np.int64)
    stats = {"shadow_errors": [], "t_a0": 0.0, "t_an": 0.0, "t_policy": 0.0, "peak_rss_mb": 0.0,
             "paced_max_lag_s": 0.0, "paced_lag_samples": []}
    proc = psutil.Process()
    seg = ev.segment.to_numpy()
    ent = ev[pc["entity"]].astype(str).to_numpy()
    fid = ev.flow_id.to_numpy(np.int64)
    # chunk boundaries: fast = fixed size; paced = one decision tick per chunk
    if pace == "paced":
        bounds = np.flatnonzero(np.r_[True, decision_at[1:] != decision_at[:-1]])
        bounds = np.r_[bounds, n]
        sp = float(speed or cfg["replay"]["default_speed"])
    else:
        bounds = np.r_[np.arange(0, n, int(cfg["replay"]["chunk_events"])), n]
    wall0 = time.perf_counter()
    sim0 = decision_at[0] if n else 0
    cur_seg = None
    for ci, (a, b) in enumerate(zip(bounds[:-1], bounds[1:])):
        if pace == "paced":
            due = wall0 + (decision_at[a] - sim0) / 1000.0 / sp
            now = time.perf_counter()
            if due > now:
                time.sleep(due - now)
            lag = max(0.0, time.perf_counter() - due)
            stats["paced_max_lag_s"] = max(stats["paced_max_lag_s"], lag)
            stats["paced_lag_samples"].append(lag)
        out = score_chunk(F.matrix(ev.iloc[a:b]), a0, an, cfg, stats)
        stats["t_a0"] += out["t_a0"]
        stats["t_an"] += out["t_an"]
        P_all[a:b] = out["P"]
        att_all[a:b] = out["att"]
        pred_all[a:b] = out["pred"]
        an_status[a:b] = out["an_status"]
        if out["an"] is not None:
            an_all[a:b] = out["an"]
        chunk_id[a:b] = ci
        t2 = time.perf_counter()
        cand = out["att"] >= a0.threshold
        sw = (out["an"] >= an.threshold) if out["an"] is not None else np.zeros(b - a, bool)
        for j in np.flatnonzero(cand | sw):
            i = a + j
            if seg[i] != cur_seg:                  # capture boundary: state of the previous segment is dropped
                cur_seg = seg[i]
                active.reset()
                if shadow:
                    shadow.reset()
            if cand[j]:
                d = active.step(int(decision_at[i]), ent[i], fid[i], seg[i])
                act[i], reason[i], inc[i] = d.action, d.reason, d.incident_id
            if sw[j]:
                sinc[i] = shadow.step(int(decision_at[i]), ent[i], fid[i], seg[i]).incident_id
        stats["t_policy"] += time.perf_counter() - t2
        stats["peak_rss_mb"] = max(stats["peak_rss_mb"], proc.memory_info().rss / 2**20)
    wall = time.perf_counter() - wall0
    det = pd.DataFrame({"flow_id": fid, "segment": seg, "entity": ent, "available_at": avail, "decision_at": decision_at,
                        "batching_delay_ms": decision_at - avail, "chunk_id": chunk_id,
                        "a0_pred": np.asarray(a0.classes, dtype=object)[pred_all], "a0_score": att_all,
                        "a0_candidate": att_all >= a0.threshold, "active_action": act, "active_reason": reason,
                        "incident_id": inc})
    for k, c in enumerate(a0.classes):
        det[f"p_{c}"] = P_all[:, k]
    if an is not None:
        det["an_score"] = an_all
        det["an_would_alert"] = an_all >= an.threshold
        det["an_status"] = an_status
        det["shadow_incident_id"] = sinc
    store.write_detections(det)
    alerts = [{"alert_id": k + 1, "incident_id": i["incident_id"], "flow_id": i["first_flow_id"], "entity": i["entity"],
               "detector": "a0", "created_at": i["opened_at"], "reason": i["open_reason"], "policy_version": pc["version"],
               "status": "notified" if i["notified"] else "suppressed_budget"} for k, i in enumerate(active.incidents)]
    store.write_incidents(active.incidents + (shadow.incidents if shadow else []), alerts)
    span_s = (decision_at[-1] - decision_at[0]) / 1000 if n else 0
    n_an = {s: int((an_status == s).sum()) for s in ("ok", "missing", "late", "off")}
    meta = {
        "run_id": run_id, "mode": mode, "pace": pace, "unlock_holdout": bool(unlock_holdout), "speed": speed if pace == "paced" else None,
        "created_wall_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "config_sha1": cfg["_sha1"],
        "manifest_sha1": K.sha1_file(K.path(cfg, "derived") / "manifest.json"),
        "stream_sha1": json.loads((K.path(cfg, "derived") / "manifest.json").read_text(encoding="utf-8"))["stream_sha1"],
        "a0": {"model_hash": a0.version, "threshold": a0.threshold, "classes": a0.classes},
        "anomaly": ({"model_hash": an.version, "threshold": an.threshold} if an else None),
        "feature_schema": F.FEATURE_SCHEMA_VERSION, "feature_schema_hash": F.schema_hash(),
        "contracts": F.CONTRACT_VERSION, "policy": pc, "segments": sorted(set(seg.tolist())),
        "events": n, "event_time_span_s": float(span_s), "max_events": max_events,
        "decision_tick_ms": tick, "export_delay_ms": cfg["replay"]["export_delay_ms"],
        "wall_seconds": wall, "wall_a0_s": stats["t_a0"], "wall_shadow_s": stats["t_an"], "wall_policy_s": stats["t_policy"],
        "throughput_events_per_wall_s": n / wall if wall else None,
        "a0_compute_us_per_event": stats["t_a0"] / n * 1e6 if n else None,
        "shadow_compute_us_per_event": (stats["t_an"] / n * 1e6 if n and an else None),
        "peak_rss_mb": stats["peak_rss_mb"], "shadow_status_counts": n_an,
        "degraded": bool(an is not None and (n_an["missing"] > 0)), "shadow_errors": stats["shadow_errors"][:5],
        "paced_max_lag_s": stats["paced_max_lag_s"] if pace == "paced" else None,
        "paced_p95_lag_s": float(np.percentile(stats["paced_lag_samples"], 95)) if stats["paced_lag_samples"] else None,
        "active": {"candidates": int(det.a0_candidate.sum()), "incidents": len(active.incidents),
                   "notified": int(sum(i["notified"] for i in active.incidents)),
                   "suppressed_budget": int(sum(i["open_reason"] == "budget_exceeded" for i in active.incidents))},
        "shadow": ({"would_alert": int(det.an_would_alert.sum()), "incidents": len(shadow.incidents)} if an else None),
    }
    meta["active_decisions_sha1"] = hashlib.sha1(
        pd.util.hash_pandas_object(det[["flow_id", "a0_pred", "a0_candidate", "active_action", "active_reason", "incident_id"]],
                                   index=False).to_numpy().tobytes()).hexdigest()
    store.write_meta(meta)
    return {k: meta[k] for k in ("run_id", "mode", "events", "wall_seconds", "throughput_events_per_wall_s", "active",
                                 "shadow", "degraded", "shadow_status_counts", "active_decisions_sha1")}
