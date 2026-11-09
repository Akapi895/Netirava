"""NF-ToN-IoT-v3 supplementary experiment (docs/protocols/ton_iot.md, docs/ton_iot_evaluation.md).

audit  : streaming, label-aware inventory of the raw CSV (no model). Definitions:
         flow identity      = one CSV row (row_id = 0-based line index after the header)
         exact fingerprint  = hash(FLOW_START, FLOW_END, SRC, DST, 49 features); label NOT included
         feature fingerprint= hash(49 features) only
         episode            = (label, src IP, dst IP), split at gaps > 30 min in FLOW_START
The raw file is opened read-only; every output goes to artifacts/ton_iot_v1/.
"""

import json
import time

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv

from netirava import config as K
from netirava import features as F

HOUR = 3_600_000
EXACT_KEY = [F.TS_START, F.TS_END, F.SRC, F.DST] + F.FEATURES


def _reader(path, block_mb=64):
    return pacsv.open_csv(path, read_options=pacsv.ReadOptions(block_size=block_mb << 20))


def audit(cfg):
    src = K.path(cfg, "raw_csv")
    out = K.path(cfg, "derived") / "audit"
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    rd = _reader(src)
    schema = {f.name: str(f.type) for f in rd.schema}
    missing = [c for c in F.FEATURES + [F.TS_START, F.TS_END, F.SRC, F.DST, F.LABEL, F.LABEL_BIN] if c not in schema]
    nulls, ninf, nneg = {}, {}, {}
    fmin = {c: np.inf for c in F.FEATURES}
    fmax = {c: -np.inf for c in F.FEATURES}
    hourly, lab_bin_mismatch, end_before_start, n = {}, 0, 0, 0
    src_by_lab, dst_by_lab = {}, {}
    H_exact, H_feat, LAB, HOURS = [], [], [], []
    lab_codes = {}
    for b in rd:
        df = b.to_pandas()
        n0 = n
        n += len(df)
        for c in df.columns:
            k = int(df[c].isna().sum())
            if k:
                nulls[c] = nulls.get(c, 0) + k
        for c in F.FEATURES:
            v = df[c].to_numpy(dtype=np.float64)
            k = int(np.isinf(v).sum())
            if k:
                ninf[c] = ninf.get(c, 0) + k
            k = int((v < 0).sum())
            if k:
                nneg[c] = nneg.get(c, 0) + k
            fmin[c] = min(fmin[c], float(np.nanmin(v)))
            fmax[c] = max(fmax[c], float(np.nanmax(v)))
        lab = df[F.LABEL].astype(str)
        lab_bin_mismatch += int(((lab == "Benign") != (df[F.LABEL_BIN] == 0)).sum())
        end_before_start += int((df[F.TS_END] < df[F.TS_START]).sum())
        h = (df[F.TS_START] // HOUR).to_numpy(np.int64)
        for (hh, l), v in pd.Series(1, index=pd.MultiIndex.from_arrays([h, lab])).groupby(level=[0, 1]).size().items():
            hourly[(int(hh), l)] = hourly.get((int(hh), l), 0) + int(v)
        for l, g in df.groupby(lab):
            src_by_lab.setdefault(l, set()).update(g[F.SRC].unique().tolist())
            dst_by_lab.setdefault(l, set()).update(g[F.DST].unique().tolist())
        for l in lab.unique():
            lab_codes.setdefault(l, len(lab_codes))
        H_exact.append(pd.util.hash_pandas_object(df[EXACT_KEY], index=False).to_numpy())
        H_feat.append(pd.util.hash_pandas_object(df[F.FEATURES].astype("float64") + 0.0, index=False).to_numpy())
        LAB.append(lab.map(lab_codes).to_numpy(np.int16))
        HOURS.append(h)
    he, hf, lb, hr = np.concatenate(H_exact), np.concatenate(H_feat), np.concatenate(LAB), np.concatenate(HOURS)
    inv = {v: k for k, v in lab_codes.items()}
    np.savez_compressed(out / "fingerprints.npz", exact=he, feat=hf, label=lb, hour=hr)
    t = pd.DataFrame({"he": he, "lab": lb})
    dup = t.duplicated("he", keep="first").to_numpy()
    nlab = t.groupby("he").lab.transform("nunique").to_numpy()
    per_label = {}
    for code, name in inv.items():
        m = lb == code
        u = pd.unique(he[m])
        shared = int(pd.Series(u).isin(t.he[(nlab > 1)]).sum())
        uniq_exact_rows_in_label = int((~t[m].duplicated("he")).sum())
        per_label[name] = {"raw_rows": int(m.sum()), "unique_exact_fingerprints": int(len(u)),
                           "exact_fingerprints_shared_with_other_label": shared,
                           "exact_fingerprints_only_this_label": int(len(u) - shared),
                           "rows_in_conflicting_fingerprints": int((m & (nlab > 1)).sum()),
                           "unique_feature_fingerprints": int(len(pd.unique(hf[m]))),
                           "src_ips": len(src_by_lab.get(name, ())), "dst_ips": len(dst_by_lab.get(name, ())),
                           "src_examples": sorted(src_by_lab.get(name, ()))[:8] if name != "Benign" else None,
                           "dst_examples": sorted(dst_by_lab.get(name, ()))[:8] if name != "Benign" else None,
                           "within_label_exact_unique_rows": uniq_exact_rows_in_label}
    hh = pd.Series(hourly).rename_axis(["hour", "label"]).reset_index(name="n")
    hh["hour_utc"] = pd.to_datetime(hh.hour * HOUR, unit="ms", utc=True).astype(str)
    hh.to_csv(out / "hourly_label_counts.csv", index=False)
    rep = {"csv": str(src), "rows": int(n), "schema": schema, "missing_contract_columns": missing,
           "nulls": nulls, "infinities": ninf, "negative_values": nneg,
           "constant_features": [c for c in F.FEATURES if fmin[c] == fmax[c]],
           "feature_min_max": {c: [fmin[c], fmax[c]] for c in F.FEATURES},
           "label_binary_mismatch": lab_bin_mismatch, "end_before_start": end_before_start,
           "ts_min_utc": str(pd.to_datetime(hr.min() * HOUR, unit="ms", utc=True)),
           "ts_max_utc": str(pd.to_datetime(hr.max() * HOUR, unit="ms", utc=True)),
           "exact_duplicate_rows": int(dup.sum()), "rows_in_label_conflicting_exact_fingerprints": int((nlab > 1).sum()),
           "per_label": per_label, "seconds": time.perf_counter() - t0}
    (out / "AUDIT.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    return rep


# --------------------------------------------------------------------------- prepare (streaming, two passes)
def _u01(row_id, seed):
    """Deterministic uniform in [0, 1) from (row_id, seed): splitmix64."""
    z = (row_id.astype(np.uint64) + np.uint64(seed) * np.uint64(0x9E3779B97F4A7C15)) & np.uint64(0xFFFFFFFFFFFFFFFF)
    z = (z ^ (z >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
    z = (z ^ (z >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
    z = z ^ (z >> np.uint64(31))
    return (z >> np.uint64(11)).astype(np.float64) / float(1 << 53)


def _window_index(ts, wins):
    starts = np.array([w["start_ms"] for w in wins])
    ends = np.array([w["end_ms"] for w in wins])
    wi = np.searchsorted(starts, ts, side="right") - 1
    ok = (wi >= 0) & (ts < ends[np.clip(wi, 0, None)])
    return np.where(ok, wi, -1)


def prepare(cfg):
    import pyarrow.parquet as pq
    from netirava.dataset import window_bounds
    t0 = time.perf_counter()
    src, out = K.path(cfg, "raw_csv"), K.path(cfg, "derived")
    wins = window_bounds(cfg)
    fp = np.load(out / "audit" / "fingerprints.npz")
    dup = pd.Series(fp["exact"]).duplicated(keep="first").to_numpy()
    pc_ = cfg["prepare"]
    caps, seed = pc_["train_cap_per_class"], int(pc_["sample_seed"])
    # pass 1: support per (window, label) after dedup
    cnt, raw_cnt, offset = {}, {}, 0
    rd = pacsv.open_csv(src, read_options=pacsv.ReadOptions(block_size=64 << 20),
                        convert_options=pacsv.ConvertOptions(include_columns=[F.TS_START, F.LABEL]))
    for b in rd:
        ts = b.column(F.TS_START).to_numpy()
        lab = np.asarray(b.column(F.LABEL).to_pylist(), dtype=object)
        wi = _window_index(ts, wins)
        d = dup[offset:offset + len(ts)]
        offset += len(ts)
        for (w, l), v in pd.Series(1, index=pd.MultiIndex.from_arrays([wi, lab])).groupby(level=[0, 1]).size().items():
            if w >= 0:
                raw_cnt[(w, l)] = raw_cnt.get((w, l), 0) + int(v)
        m = (wi >= 0) & ~d
        for (w, l), v in pd.Series(1, index=pd.MultiIndex.from_arrays([wi[m], lab[m]])).groupby(level=[0, 1]).size().items():
            cnt[(w, l)] = cnt.get((w, l), 0) + int(v)
    train_n = {}
    for (w, l), v in cnt.items():
        if wins[w]["role"] == "train":
            train_n[l] = train_n.get(l, 0) + v
    p_keep = {l: min(1.0, caps.get(l, caps["default"]) / n) for l, n in train_n.items()}
    # pass 2: write stream (no labels) and truth
    stream_w = truth_w = None
    kept, offset = {}, 0
    rd = pacsv.open_csv(src, read_options=pacsv.ReadOptions(block_size=64 << 20))
    for b in rd:
        df = b.to_pandas()
        n = len(df)
        rid = np.arange(offset, offset + n, dtype=np.int64)
        d = dup[offset:offset + n]
        offset += n
        wi = _window_index(df[F.TS_START].to_numpy(), wins)
        role = np.array([wins[i]["role"] if i >= 0 else "" for i in wi], dtype=object)
        lab = df[F.LABEL].astype(str).to_numpy()
        keep = (wi >= 0) & ~d
        tr = keep & (role == "train")
        if tr.any():
            u = _u01(rid, seed)
            pk = np.array([p_keep.get(l, 1.0) for l in lab])
            keep &= ~tr | (u < pk)
        if not keep.any():
            continue
        sub = df.loc[keep].copy()
        sub.insert(0, "row_id", rid[keep])
        sub["flow_id"] = sub.row_id
        sub["segment"] = [wins[i]["id"] for i in wi[keep]]
        sub["role"] = role[keep]
        sub["available_at"] = sub[F.TS_END].astype(np.int64) + int(cfg["replay"]["export_delay_ms"])
        for (sg, l), v in sub.groupby(["segment", F.LABEL]).size().items():
            kept[(sg, l)] = kept.get((sg, l), 0) + int(v)
        truth = pd.DataFrame({"row_id": sub.row_id, "flow_id": sub.flow_id, F.LABEL: sub[F.LABEL].astype(str),
                              F.LABEL_BIN: sub[F.LABEL_BIN].astype(np.int64), "role": sub.role, "segment": sub.segment,
                              "label_quality": "clear", "unknown_to_model": ~sub[F.LABEL].isin(cfg["a0"]["known_classes"])})
        stream = sub.drop(columns=[F.LABEL, F.LABEL_BIN])
        for c in F.FEATURES:
            stream[c] = stream[c].astype(np.float64)
        ts_tab, tr_tab = pa.Table.from_pandas(stream, preserve_index=False), pa.Table.from_pandas(truth, preserve_index=False)
        if stream_w is None:
            stream_w = pq.ParquetWriter(out / "stream.parquet", ts_tab.schema)
            truth_w = pq.ParquetWriter(out / "truth.parquet", tr_tab.schema)
        stream_w.write_table(ts_tab.cast(stream_w.schema))
        truth_w.write_table(tr_tab.cast(truth_w.schema))
    stream_w.close()
    truth_w.close()
    seg_role = {w["id"]: w["role"] for w in wins}
    sup = {}
    for (sg, l), v in kept.items():
        sup.setdefault(sg, {})[l] = v
    man = {"dataset": cfg["dataset"]["name"], "source_csv": str(src), "source_sha1_expected": cfg["dataset"]["sha1"],
           "selection_rule": "FLOW_START in [start, end) of a configured window; exact duplicates (timestamps, IPs, 49 features) "
                             "removed keeping the first copy in file order; TRAIN rows Bernoulli-sampled per class with "
                             "p = min(1, cap / n_train_class), u = splitmix64(row_id, seed)",
           "dedup": pc_["dedup"], "train_caps": caps, "sample_seed": seed, "p_keep_train": p_keep, "train_n_after_dedup": train_n,
           "export_delay_ms": int(cfg["replay"]["export_delay_ms"]), "windows": wins,
           "support_raw_in_windows": {f"{wins[w]['id']}|{l}": v for (w, l), v in raw_cnt.items()},
           "support_after_dedup": {f"{wins[w]['id']}|{l}": v for (w, l), v in cnt.items()},
           "support_by_segment": sup, "rows": int(sum(kept.values())),
           "rows_by_role": pd.Series({sg: sum(v.values()) for sg, v in sup.items()}).groupby(lambda s: seg_role[s]).sum().to_dict(),
           "files": {"stream": "stream.parquet", "truth": "truth.parquet"}, "elapsed_s": time.perf_counter() - t0,
           "config_sha1": cfg["_sha1"]}
    man["stream_sha1"] = K.sha1_file(out / "stream.parquet")
    man["truth_sha1"] = K.sha1_file(out / "truth.parquet")
    (out / "manifest.json").write_text(json.dumps(man, indent=1, default=str), encoding="utf-8")
    return man


# --------------------------------------------------------------------------- split audit + gate (labels/hosts/time only)
def _episodes(d, gap=1_800_000):
    a = d.sort_values([F.LABEL, F.SRC, F.DST, F.TS_START])
    new = (a[F.LABEL] != a[F.LABEL].shift()) | (a[F.SRC] != a[F.SRC].shift()) | (a[F.DST] != a[F.DST].shift()) | \
          (a[F.TS_START].diff() > gap)
    return pd.Series(new.cumsum().to_numpy(), index=a.index)


def split_audit(cfg):
    import pyarrow.parquet as pq
    from netirava.dataset import window_bounds
    out = K.path(cfg, "derived")
    man = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    cols = ["flow_id", "segment", "role", F.TS_START, F.TS_END, F.SRC, F.DST, F.SPORT, F.DPORT, "PROTOCOL"]
    s = pq.read_table(out / "stream.parquet", columns=cols).to_pandas()
    t = pq.read_table(out / "truth.parquet", columns=["flow_id", F.LABEL]).to_pandas()
    d = s.merge(t, on="flow_id", validate="one_to_one")
    att = d[d[F.LABEL] != "Benign"].copy()
    att["ep"] = _episodes(att)
    feat = pq.read_table(out / "stream.parquet", columns=["flow_id"] + F.FEATURES,
                         filters=[("flow_id", "in", att.flow_id.tolist())]).to_pandas().set_index("flow_id").loc[att.flow_id]
    att["ffp"] = pd.util.hash_pandas_object(feat[F.FEATURES].astype("float64") + 0.0, index=False).to_numpy()
    tr, te = att[att.role == "train"], att[att.role == "replay"]
    n_attack_train = man["train_n_after_dedup"]
    tot_att_train = sum(v for k, v in n_attack_train.items() if k != "Benign")
    rule = cfg["a0"]["minority_rule"]
    classes = {}
    for lab in sorted(att[F.LABEL].unique()):
        a, b = tr[tr[F.LABEL] == lab], te[te[F.LABEL] == lab]
        trs, tes = set(a[F.SRC]), set(b[F.SRC])
        share = n_attack_train.get(lab, 0) / tot_att_train
        classes[lab] = {
            "train_rows_after_dedup": n_attack_train.get(lab, 0), "share_of_attack_train_after_dedup": share,
            "minority": share < rule["share_of_attack_train_rows_lt"],
            "train_rows_fit": int(len(a)), "test_rows": int(len(b)), "test_segments": sorted(b.segment.unique()),
            "train_src": sorted(trs), "test_src": sorted(tes), "test_src_not_in_train": sorted(tes - trs),
            "test_rows_from_src_not_in_train": int(b[F.SRC].isin(tes - trs).sum()),
            "train_episodes": int(a.ep.nunique()), "test_episodes": int(b.ep.nunique()),
            "test_dst": int(b[F.DST].nunique()),
            "test_feature_fp_seen_in_train_share": float(b.ffp.isin(set(a.ffp)).mean()) if len(b) else None,
            "test_support_level": ("ok" if len(b) >= rule["test_unique_flows_min"] else
                                   "limited" if len(b) >= rule["test_flows_limited"] else "INCONCLUSIVE")}
    wins = {w["id"]: w for w in window_bounds(cfg)}
    tw = d[d.role == "train"]
    cross = int((tw[F.TS_END].to_numpy() >= tw.segment.map(lambda x: wins[x]["end_ms"]).to_numpy()).sum())
    key = lambda x: x[F.SRC] + ":" + x[F.SPORT].astype(str) + ">" + x[F.DST] + ":" + x[F.DPORT].astype(str) + "/" + x.PROTOCOL.astype(str)
    conn_tr = set(key(d[d.role == "train"]))
    te_all = d[d.role == "replay"]
    conn_shared = int(key(te_all).isin(conn_tr).sum())
    ben = d[d[F.LABEL] == "Benign"].groupby("role").size().to_dict()
    cal_n = int(d[(d.role == "calibration") & (d[F.LABEL] == "Benign")].shape[0])
    res = {"classes": classes, "train_flows_ending_after_their_window": cross,
           "test_flows_sharing_5tuple_with_a_train_flow": conn_shared, "test_flows": int(len(te_all)),
           "benign_by_role": ben, "calibration_benign": cal_n,
           "alpha_resolution": {str(a): {"min_benign_for_10_fp": int(10 / a), "ok": cal_n >= 10 / a} for a in cfg["a0"]["fpr_levels"]}}
    (out / "SPLIT_AUDIT.json").write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
    return res


# --------------------------------------------------------------------------- the single fit + calibration
class _Monitor:
    """Samples process RSS every 1 s and GPU memory used every 2 s (nvidia-smi) in a background thread."""
    def __init__(self):
        import threading
        self.rss, self.gpu, self.stop, self.err = [], [], False, None
        self.t = threading.Thread(target=self.loop, daemon=True)

    def loop(self):
        import subprocess
        import psutil
        p, k = psutil.Process(), 0
        while not self.stop:
            self.rss.append(p.memory_info().rss / 2**20)
            if k % 2 == 0:
                try:
                    o = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
                                       capture_output=True, text=True, timeout=5).stdout.strip().splitlines()
                    self.gpu.append(float(o[0]))
                except Exception as e:      # not fatal: telemetry only
                    self.err = repr(e)
            k += 1
            time.sleep(1.0)

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop = True
        self.t.join(timeout=5)

    def summary(self):
        return {"peak_process_rss_mb": max(self.rss) if self.rss else "not measured",
                "peak_gpu_memory_used_mb_device_total": max(self.gpu) if self.gpu else "not measured",
                "gpu_note": "nvidia-smi memory.used of the whole device (includes other processes), sampled every 2 s",
                "rss_samples": len(self.rss), "gpu_samples": len(self.gpu), "telemetry_error": self.err}


def train_once(cfg):
    from catboost import CatBoostClassifier
    from netirava.dataset import training_frame
    from netirava.detectors import threshold_at_fpr, wilson
    mdir = K.path(cfg, "models") / "a0"
    mdir.mkdir(parents=True, exist_ok=True)
    marker = mdir / "FIT_STARTED.json"
    if marker.exists() or (mdir / "a0.cbm").exists():
        raise RuntimeError(f"single-fit budget already used ({marker}); refusing to fit again")
    classes = list(cfg["a0"]["known_classes"])
    rec = {k: v for k, v in cfg["a0"]["recipe"].items() if k != "early_stopping"}
    timing, t_all = {}, time.perf_counter()
    t = time.perf_counter()
    tr = training_frame(cfg, ["train"])
    unk = sorted(set(tr[F.LABEL]) - set(classes))
    assert not unk, unk
    X = F.matrix(tr)
    y = tr[F.LABEL].map({c: i for i, c in enumerate(classes)}).to_numpy(np.int64)
    timing["load_train_s"] = time.perf_counter() - t
    params = dict(rec, train_dir=str(mdir / "catboost_info"), metric_period=10, verbose=100, allow_writing_files=True)
    marker.write_text(json.dumps({"fit_started_utc": pd.Timestamp.now(tz="UTC").isoformat(), "params": params,
                                  "n_train": int(len(y)), "config_sha1": cfg["_sha1"],
                                  "note": "single-fit budget: this file blocks any further fit"}, indent=1), encoding="utf-8")
    m = CatBoostClassifier(**params)
    with _Monitor() as mon:
        t = time.perf_counter()
        try:
            m.fit(X, y)
        except Exception as e:
            (mdir / "FIT_FAILED.json").write_text(json.dumps({"error": repr(e), "utc": pd.Timestamp.now(tz="UTC").isoformat()}))
            raise
        timing["fit_s"] = time.perf_counter() - t
    t = time.perf_counter()
    m.save_model(str(mdir / "a0.cbm"))
    timing["persist_s"] = time.perf_counter() - t
    allp = m.get_all_params()
    # calibration on the separate benign window
    t = time.perf_counter()
    cal = training_frame(cfg, ["calibration"])
    ben = (cal[F.LABEL] == cfg["labels"]["benign"]).to_numpy()
    sc = 1.0 - m.predict_proba(F.matrix(cal[ben]))[:, classes.index("Benign")]
    timing["calibration_s"] = time.perf_counter() - t
    levels = {}
    for a in cfg["a0"]["fpr_levels"]:
        thr, real = threshold_at_fpr(sc, a)
        k = int(round(real * len(sc)))
        levels[str(a)] = {"threshold": thr, "realised_fpr": real, "fp": k, "wilson95": wilson(k, len(sc)),
                          "resolution_ok": len(sc) >= 10 / a}
    target = float(cfg["a0"]["target_fpr"])
    counts = np.bincount(y, minlength=len(classes))
    meta = {"detector": "a0", "variant": "ton_iot_cw_balanced", "model_hash": K.sha1_file(mdir / "a0.cbm")[:12],
            "model_sha1": K.sha1_file(mdir / "a0.cbm"), "model_bytes": (mdir / "a0.cbm").stat().st_size,
            "classes": classes, "class_map": {c: i for i, c in enumerate(classes)},
            "train_counts": {c: int(n) for c, n in zip(classes, counts)}, "n_train": int(len(y)),
            "params_passed": params, "resolved_params": {k: allp.get(k) for k in sorted(allp)},
            "class_weights_resolved": allp.get("class_weights"), "tree_count": int(m.tree_count_),
            "best_iteration": m.get_best_iteration(), "best_score": m.get_best_score(), "n_fits": 1,
            "feature_schema": F.FEATURE_SCHEMA_VERSION, "feature_schema_hash": F.schema_hash(), "features": F.FEATURES,
            "threshold": {"value": levels[str(target)]["threshold"], "target_fpr": target,
                          "rule": "smallest t with share(benign calibration score >= t) <= target", "levels": levels,
                          "n_benign_calibration": int(len(sc)),
                          "note": "attack_score = 1 - p(Benign); a decision score, not a calibrated probability"},
            "calibration_score_quantiles": {str(q): float(np.quantile(sc, q)) for q in (0.5, 0.9, 0.99, 0.995, 0.999, 0.9995)},
            "timing": timing | {"train_once_total_s": time.perf_counter() - t_all}, "resources": mon.summary(),
            "catboost_version": __import__("catboost").__version__, "config_sha1": cfg["_sha1"]}
    (mdir / "a0_meta.json").write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")
    return meta


# --------------------------------------------------------------------------- evaluation (evaluator side: reads labels)
def _flow_metrics(d, classes, thr_levels):
    from sklearn.metrics import average_precision_score, balanced_accuracy_score, f1_score, roc_auc_score
    from netirava.detectors import wilson
    y, pred = d[F.LABEL].to_numpy(), d.a0_pred.to_numpy()
    present = [c for c in classes if (y == c).any()]
    pc = {}
    for c in classes:
        t, p = y == c, pred == c
        n = int(t.sum())
        if not n and not p.sum():
            continue
        tp = int((t & p).sum())
        P_, R_ = (tp / p.sum() if p.sum() else 0.0), (tp / n if n else None)
        pc[c] = {"support": n, "predicted": int(p.sum()), "precision": float(P_), "recall": R_,
                 "f1": (float(2 * P_ * R_ / (P_ + R_)) if R_ is not None and P_ + R_ else 0.0) if n else None,
                 "recall_wilson95_iid": wilson(tp, n) if n else None}
    ben = y == "Benign"
    r = {"n": int(len(d)), "prevalence_attack": float((~ben).mean()), "per_class_argmax": pc,
         "macro_f1_present": float(f1_score(y, pred, labels=present, average="macro", zero_division=0)),
         "weighted_f1": float(f1_score(y, pred, labels=present, average="weighted", zero_division=0)),
         "balanced_accuracy": float(balanced_accuracy_score(y, pred)) if len(present) > 1 else None,
         "confusion_class_order": classes,
         "confusion": pd.crosstab(pd.Categorical(y, classes), pd.Categorical(pred, classes), dropna=False).values.tolist(),
         "alphas": {}, "auc_vs_benign": {}}
    s = d.a0_score.to_numpy()
    for c in present:
        if c == "Benign" or not ben.any():
            continue
        m = ben | (y == c)
        r["auc_vs_benign"][c] = {"auroc": float(roc_auc_score(y[m] == c, s[m])), "auprc": float(average_precision_score(y[m] == c, s[m])),
                                 "positive": c, "prevalence_in_pair": float((y[m] == c).mean())}
    for a, t in thr_levels.items():
        al = s >= t
        k, nb = int((al & ben).sum()), int(ben.sum())
        rr = {"threshold": t, "fp": k, "n_benign": nb, "benign_fpr": k / nb if nb else None,
              "benign_fpr_wilson95_iid": wilson(k, nb) if nb else None, "recall_by_class": {}, "end_to_end_fine_recall": {}}
        for c in present:
            if c == "Benign":
                continue
            m = y == c
            rr["recall_by_class"][c] = float(al[m].mean())
            rr["end_to_end_fine_recall"][c] = float((al[m] & (pred[m] == c)).mean())
        r["alphas"][a] = rr
    return r


def evaluate(cfg, run_ids):
    from netirava.ops import correlation_run
    from netirava.storage import RunStore
    meta_m = json.loads((K.path(cfg, "models") / "a0" / "a0_meta.json").read_text(encoding="utf-8"))
    classes = meta_m["classes"]
    thr = {a: v["threshold"] for a, v in meta_m["threshold"]["levels"].items()}
    truth = pd.read_parquet(K.path(cfg, "derived") / "truth.parquet", columns=["flow_id", F.LABEL])
    frames, out = [], {"model_hash": meta_m["model_hash"], "thresholds": thr, "runs": {}, "segments": {}}
    for rid in run_ids:
        st = RunStore(cfg, rid)
        det = st.detections(columns=["flow_id", "segment", "a0_score", "a0_pred", "a0_candidate", "fine_label", "predicted_family"])
        d = det.merge(truth, on="flow_id", how="left", validate="one_to_one")
        assert d[F.LABEL].notna().all()
        assert (d.a0_candidate == (d.a0_score >= meta_m["threshold"]["value"])).all()
        out["runs"][rid] = {"meta": {k: st.meta()[k] for k in ("events", "wall_seconds", "a0_compute_us_per_event", "peak_rss_mb",
                                                                 "active", "active_decisions_sha1", "stream_sha1", "config_sha1")},
                            "correlation": correlation_run(cfg, rid, label_sets=("original",))}
        for seg, g in d.groupby("segment"):
            out["segments"][seg] = _flow_metrics(g, classes, thr)
        frames.append(d)
    out["pooled"] = _flow_metrics(pd.concat(frames, ignore_index=True), classes, thr)
    p = K.path(cfg, "runs") / "EVALUATION_TON.json"
    p.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return out


def sensitivity_and_uncertainty(cfg, run_ids, reps=2000, seed=2027):
    """Pre-declared (protocol section 7): (a) flow metrics on test flows whose 5-tuple never occurs in train;
    (b) episode-bootstrap CI of binary recall per attack class at each alpha, on the saved replay outputs."""
    import pyarrow.parquet as pq
    from netirava.storage import RunStore
    meta_m = json.loads((K.path(cfg, "models") / "a0" / "a0_meta.json").read_text(encoding="utf-8"))
    classes = meta_m["classes"]
    thr = {a: v["threshold"] for a, v in meta_m["threshold"]["levels"].items()}
    cols = ["flow_id", "role", F.SRC, F.DST, F.SPORT, F.DPORT, "PROTOCOL", F.TS_START]
    s = pq.read_table(K.path(cfg, "derived") / "stream.parquet", columns=cols).to_pandas()
    key = s[F.SRC] + ":" + s[F.SPORT].astype(str) + ">" + s[F.DST] + ":" + s[F.DPORT].astype(str) + "/" + s.PROTOCOL.astype(str)
    train_keys = set(key[s.role == "train"])
    s["novel_5tuple"] = ~key.isin(train_keys)
    truth = pd.read_parquet(K.path(cfg, "derived") / "truth.parquet", columns=["flow_id", F.LABEL])
    d = pd.concat([RunStore(cfg, r).detections(columns=["flow_id", "segment", "a0_score", "a0_pred"]) for r in run_ids], ignore_index=True)
    d = d.merge(truth, on="flow_id").merge(s[["flow_id", "novel_5tuple", F.SRC, F.DST, F.TS_START]], on="flow_id")
    out = {"novel_5tuple_share_by_class": d.groupby(F.LABEL).novel_5tuple.mean().to_dict(),
           "novel_5tuple_subset": _flow_metrics(d[d.novel_5tuple], classes, thr), "episode_bootstrap": {}}
    att = d[d[F.LABEL] != "Benign"].copy()
    att["ep"] = _episodes(att)
    rng = np.random.default_rng(seed)
    for lab, g in att.groupby(F.LABEL):
        eps = g.ep.unique()
        r = {"episodes": int(len(eps)), "flows": int(len(g))}
        for a, t in thr.items():
            hit = (g.a0_score >= t).groupby(g.ep).agg(["sum", "size"])
            h, n = hit["sum"].to_numpy(float), hit["size"].to_numpy(float)
            draws = rng.integers(0, len(eps), (reps, len(eps)))
            rec = h[draws].sum(1) / n[draws].sum(1)
            r[a] = {"flow_recall": float(h.sum() / n.sum()), "episode_bootstrap_ci95": [float(np.percentile(rec, 2.5)), float(np.percentile(rec, 97.5))],
                    "episodes_with_any_alert": int((h > 0).sum())}
        out["episode_bootstrap"][lab] = r
    p = K.path(cfg, "runs") / "SENSITIVITY_TON.json"
    p.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return out
