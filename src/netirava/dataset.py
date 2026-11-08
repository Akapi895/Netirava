"""Dataset access: streaming profile (inspect) and subset preparation (prepare).

The raw CSV is read in batches with pyarrow and never modified. Labels are
written only to the evaluator truth table; the replay stream file contains
no label columns.
"""

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

from netirava import config as K
from netirava import features as F

MS_HOUR = 3_600_000
MS_DAY = 86_400_000


def open_stream(csv_path, block_mb=64, columns=None):
    ro = pacsv.ReadOptions(block_size=block_mb << 20)
    co = pacsv.ConvertOptions(include_columns=columns) if columns else None
    return pacsv.open_csv(csv_path, read_options=ro, convert_options=co)


def utc(ms):
    return pd.to_datetime(ms, unit="ms", utc=True)


# --------------------------------------------------------------------------- inspect
def inspect(cfg):
    src = K.path(cfg, "raw_csv")
    out = K.path(cfg, "runs") / "inspect"
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    rep = {"dataset": cfg["dataset"]["name"], "csv": str(src), "bytes": src.stat().st_size}
    rep["sha1"] = K.sha1_file(src)
    man = {}
    bag = src.parent.parent / "manifest-sha1.txt"
    if bag.exists():
        for line in bag.read_text(encoding="utf-8").splitlines():
            d, rel = line.split(maxsplit=1)
            man[Path(rel).name] = d
    rep["bagit_sha1"] = man.get(src.name)
    rep["sha1_matches_bagit"] = rep["sha1"] == rep["bagit_sha1"]
    reader = open_stream(src)
    schema = reader.schema
    rep["schema"] = {f.name: str(f.type) for f in schema}
    nulls = {f.name: 0 for f in schema}
    neg = {}
    n = 0
    hourly = {}
    bad_time = {"end_before_start": 0, "start_le_0": 0}
    ts_min, ts_max = None, None
    label_mismatch = 0
    for batch in reader:
        df = batch.to_pandas()
        n += len(df)
        for c in df.columns:
            nulls[c] += int(df[c].isna().sum())
        for c in F.FEATURES:
            k = int((df[c] < 0).sum())
            if k:
                neg[c] = neg.get(c, 0) + k
        s, e = df[F.TS_START].to_numpy(), df[F.TS_END].to_numpy()
        bad_time["end_before_start"] += int((e < s).sum())
        bad_time["start_le_0"] += int((s <= 0).sum())
        ts_min = s.min() if ts_min is None else min(ts_min, s.min())
        ts_max = e.max() if ts_max is None else max(ts_max, e.max())
        label_mismatch += int(((df[F.LABEL] == "Benign") != (df[F.LABEL_BIN] == 0)).sum())
        g = df.groupby([df[F.TS_START] // MS_HOUR, F.LABEL]).size()
        for (h, a), v in g.items():
            hourly[(int(h), a)] = hourly.get((int(h), a), 0) + int(v)
    rep.update(rows=n, nulls={k: v for k, v in nulls.items() if v}, negative_feature_values=neg,
               time_checks=bad_time, ts_min_utc=str(utc(ts_min)), ts_max_utc=str(utc(ts_max)),
               timestamp_unit="epoch milliseconds (13 digits), interpreted as UTC",
               label_binary_mismatch=label_mismatch)
    h = pd.Series(hourly).rename_axis(["hour", "attack"]).reset_index(name="n")
    h["hour_utc"] = utc(h.hour * MS_HOUR).astype(str)
    h.to_csv(out / "hourly_class_counts.csv", index=False)
    day = h.assign(day=utc(h.hour * MS_HOUR).dt.strftime("%Y-%m-%d")).pivot_table(
        index="attack", columns="day", values="n", aggfunc="sum", fill_value=0)
    day.to_csv(out / "class_by_utc_day.csv")
    rep["class_counts"] = h.groupby("attack").n.sum().sort_values(ascending=False).to_dict()
    rep["elapsed_s"] = time.perf_counter() - t0
    (out / "INSPECT.json").write_text(json.dumps(rep, indent=2, default=str))
    return rep


# --------------------------------------------------------------------------- prepare
def window_bounds(cfg):
    rows = []
    for w in cfg["windows"]:
        s = int(pd.Timestamp(w["start_utc"], tz="UTC").value // 1_000_000)
        e = int(pd.Timestamp(w["end_utc"], tz="UTC").value // 1_000_000)
        rows.append({**w, "start_ms": s, "end_ms": e})
    rows.sort(key=lambda r: r["start_ms"])
    for a, b in zip(rows, rows[1:]):
        assert a["end_ms"] <= b["start_ms"], f"windows overlap: {a['id']} / {b['id']}"
    return rows


def prepare(cfg):
    """Select every flow whose FLOW_START falls inside a configured window
    (no row sampling, no class balancing) and write:
      stream.parquet  features + identifiers + times (NO labels)
      truth.parquet   row_id, labels, role, quality, unknown flag (evaluator only)
      manifest.json   windows, roles, support, checksums
    Role of a row = role of its window; within-window splits are by time."""
    src = K.path(cfg, "raw_csv")
    out = K.path(cfg, "derived")
    out.mkdir(parents=True, exist_ok=True)
    wins = window_bounds(cfg)
    starts = np.array([w["start_ms"] for w in wins])
    ends = np.array([w["end_ms"] for w in wins])
    keep_cols = [F.TS_START, F.TS_END, F.SRC, F.DST] + F.FEATURES + [F.LABEL_BIN, F.LABEL]
    reader = open_stream(src)
    parts, offset = [], 0
    t0 = time.perf_counter()
    for batch in reader:
        df = batch.to_pandas()
        df.insert(0, "row_id", np.arange(offset, offset + len(df), dtype=np.int64))
        offset += len(df)
        s = df[F.TS_START].to_numpy()
        wi = np.searchsorted(starts, s, side="right") - 1
        ok = (wi >= 0) & (s < ends[np.clip(wi, 0, None)])
        if ok.any():
            sub = df.loc[ok, ["row_id"] + keep_cols].copy()
            sub["segment"] = np.asarray([wins[i]["id"] for i in wi[ok]])
            parts.append(sub)
    df = pd.concat(parts, ignore_index=True)
    assert df.row_id.is_unique
    cap = int(cfg["dataset"].get("max_rows", 3_000_000))
    assert len(df) <= cap, f"subset has {len(df):,} rows > cap {cap:,}: shrink windows in the config"
    delay = int(cfg["replay"]["export_delay_ms"])
    df["available_at"] = df[F.TS_END].astype(np.int64) + delay
    seg = {w["id"]: w for w in wins}
    df["role"] = df.segment.map(lambda s: seg[s]["role"])
    q = cfg["labels"]
    df["label_quality"] = np.where(df[F.LABEL].isin(q["flagged_classes"]), "flagged", "clear")
    known = set(cfg["a0"]["known_classes"])
    df["unknown_to_model"] = ~df[F.LABEL].isin(known)
    df["flow_id"] = df.row_id
    df = df.sort_values(["available_at", "row_id"], kind="stable").reset_index(drop=True)
    truth_cols = ["row_id", "flow_id", F.LABEL, F.LABEL_BIN, "role", "segment", "label_quality", "unknown_to_model"]
    stream_cols = [c for c in df.columns if c not in (F.LABEL, F.LABEL_BIN, "label_quality", "unknown_to_model")]
    pq.write_table(pa.Table.from_pandas(df[stream_cols], preserve_index=False), out / "stream.parquet")
    pq.write_table(pa.Table.from_pandas(df[truth_cols], preserve_index=False), out / "truth.parquet")
    support = df.pivot_table(index=F.LABEL, columns="segment", values="row_id", aggfunc="count", fill_value=0)
    manifest = {
        "dataset": cfg["dataset"]["name"], "source_csv": str(src), "source_sha1_expected": cfg["dataset"]["sha1"],
        "selection_rule": "all flows with FLOW_START_MILLISECONDS in [start, end) of a configured window; "
                          "no row sampling, no class balancing; role assigned per window",
        "export_delay_ms": delay, "available_at": "FLOW_END_MILLISECONDS + export_delay_ms",
        "windows": [{k: v for k, v in w.items()} for w in wins],
        "rows": int(len(df)), "rows_by_role": df.role.value_counts().to_dict(),
        "support_by_segment": {c: {k: int(v) for k, v in support[c].items() if v} for c in support.columns},
        "unknown_to_model_rows": int(df.unknown_to_model.sum()),
        "flagged_label_rows": int((df.label_quality == "flagged").sum()),
        "files": {"stream": "stream.parquet", "truth": "truth.parquet"},
        "elapsed_s": time.perf_counter() - t0, "config_sha1": cfg["_sha1"],
    }
    manifest["stream_sha1"] = K.sha1_file(out / "stream.parquet")
    manifest["truth_sha1"] = K.sha1_file(out / "truth.parquet")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    return manifest, df


def load_stream(cfg, roles=None, segments=None):
    """Replay/training input WITHOUT labels."""
    filters = []
    if roles is not None:
        filters.append(("role", "in", list(roles)))
    if segments is not None:
        filters.append(("segment", "in", list(segments)))
    t = pq.read_table(K.path(cfg, "derived") / "stream.parquet", filters=filters or None)
    df = t.to_pandas()
    assert F.LABEL not in df.columns and F.LABEL_BIN not in df.columns
    return df.sort_values(["available_at", "row_id"], kind="stable").reset_index(drop=True)


def load_truth(cfg):
    return pq.read_table(K.path(cfg, "derived") / "truth.parquet").to_pandas()


def training_frame(cfg, roles):
    """Features + label for TRAINING / CALIBRATION roles only (never replay)."""
    assert not set(roles) & {"replay", "stress", "known_replay", "holdout"}, "labels of replay roles are evaluator-only"
    s = load_stream(cfg, roles=roles)
    t = load_truth(cfg)[["row_id", F.LABEL]]
    return s.merge(t, on="row_id", how="left", validate="one_to_one")


# --------------------------------------------------------------------------- audit
def audit(cfg):
    s = load_stream(cfg)
    s = s[s.role != "holdout"]          # holdout stays unexamined until the method is frozen (support is in manifest.json)
    t = load_truth(cfg)
    d = s.merge(t[["flow_id", F.LABEL]], on="flow_id", validate="one_to_one")
    d["fp"] = F.fingerprint(d)
    rep = {"rows": len(d)}
    wins = {w["id"]: w for w in window_bounds(cfg)}
    rep["segments"] = {}
    train_fp = set(d.loc[d.role == "train", "fp"])
    train_src = set(d.loc[d.role == "train", F.SRC])
    train_dst = set(d.loc[d.role == "train", F.DST])
    for seg, g in d.groupby("segment"):
        w = wins[seg]
        att = g[g[F.LABEL] != "Benign"]
        ben = g[g[F.LABEL] == "Benign"]
        att_src = set(att[F.SRC])
        r = {"role": w["role"], "scenario": w["scenario"], "start_utc": w["start_utc"], "end_utc": w["end_utc"],
             "rows": len(g), "labels": g[F.LABEL].value_counts().to_dict(),
             "available_at_span_utc": [str(pd.to_datetime(g.available_at.min(), unit="ms", utc=True)),
                                       str(pd.to_datetime(g.available_at.max(), unit="ms", utc=True))],
             "distinct_src": int(g[F.SRC].nunique()), "distinct_dst": int(g[F.DST].nunique())}
        if w["role"] != "train":
            r["fp_seen_in_train_share"] = {lab: float(x.fp.isin(train_fp).mean()) for lab, x in g.groupby(F.LABEL)}
            r["src_seen_in_train_share"] = {lab: float(x[F.SRC].isin(train_src).mean()) for lab, x in g.groupby(F.LABEL)}
            r["dst_seen_in_train_share"] = {lab: float(x[F.DST].isin(train_dst).mean()) for lab, x in g.groupby(F.LABEL)}
        if len(att):
            r["attack_src_ips"] = int(len(att_src))
            r["attack_src_also_benign_src_same_window"] = float(np.mean([ip in set(ben[F.SRC]) for ip in att_src]))
            r["benign_flows_from_or_to_attack_src"] = int((ben[F.SRC].isin(att_src) | ben[F.DST].isin(att_src)).sum())
            r["attack_dst_also_benign_dst_same_window"] = float(np.mean([ip in set(ben[F.DST]) for ip in set(att[F.DST])]))
        rep["segments"][seg] = r
    nl = d.groupby("fp")[F.LABEL].nunique()
    multi = d.fp.map(nl) > 1
    rep["cross_label_fingerprint_rows"] = {lab: int(multi[d[F.LABEL] == lab].sum()) for lab in d[F.LABEL].unique()}
    rep["cross_label_pairs_top"] = (d[multi].groupby("fp")[F.LABEL].agg(lambda x: " | ".join(sorted(set(x))))
                                    .value_counts().head(10).to_dict())
    out = K.path(cfg, "derived") / "AUDIT.json"
    out.write_text(json.dumps(rep, indent=2, default=str))
    return {k: (v if k != "segments" else {s2: {x: v[s2][x] for x in ("role", "rows", "labels")} for s2 in v})
            for k, v in rep.items()}
