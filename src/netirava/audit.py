"""Subset audit (evaluator side; descriptive, no model): support by segment,
fingerprint overlap between roles, cross-label collisions, host overlap
(source vs destination, same window vs other roles)."""

import json

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, load_truth, window_bounds


def audit(cfg):
    s = load_stream(cfg)
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
