"""Minority cohort inventory over the whole NF-CSE-CIC-IDS2018-v3 CSV (docs/protocols/evidence_round2_prereg.md §B).

Uses labels, IPs, ports, times and a hash of the full row only (no model score). An episode is
(label, src IP, dst IP) split at gaps > 30 min. "Used" = intersects any window of demo.yaml,
fe_study.yaml or ops_holdout.yaml (scope hosts respected). "Credible" = web flows that match the
CNS2022-adapted rule (18.218.115.60 <-> 172.31.69.28, inside a CNS window, TCP with port 80 on one side);
everything else is "unverified" (no rule). Eligible cohort = unused AND credible AND >= 30 flows after
exact de-duplication AND not overlapping any train window.
"""

import json

import numpy as np
import pandas as pd
import pyarrow.csv as pacsv

from netirava import config as K
from netirava import features as F
from netirava.relabel import W, WEB, WEB_ATT, WEB_VIC

GAP_MS = 1_800_000
KEEP = [F.TS_START, F.TS_END, F.SRC, F.DST, F.SPORT, F.DPORT, "PROTOCOL", F.LABEL]
EXACT_KEY = [F.TS_START, F.TS_END, F.SRC, F.DST] + F.FEATURES


def scan(cfg):
    ro = pacsv.ReadOptions(block_size=64 << 20)
    parts, offset, pair = [], 0, {}
    for b in pacsv.open_csv(K.path(cfg, "raw_csv"), read_options=ro):
        df = b.to_pandas()
        pm = ((df[F.SRC] == WEB_ATT) & (df[F.DST] == WEB_VIC)) | ((df[F.SRC] == WEB_VIC) & (df[F.DST] == WEB_ATT))
        if pm.any():
            x = df[pm]
            key = pd.to_datetime(x[F.TS_START], unit="ms", utc=True).dt.strftime("%m-%d") + " " + x[F.LABEL] +                 np.where((x.PROTOCOL == 6) & ((x[F.DPORT] == 80) | (x[F.SPORT] == 80)), " tcp80", " other")
            for k, v in key.value_counts().items():
                pair[k] = pair.get(k, 0) + int(v)
        rid = np.arange(offset, offset + len(df), dtype=np.int64)
        offset += len(df)
        att = (df[F.LABEL] != "Benign").to_numpy()
        if not att.any():
            continue
        sub = df.loc[att]
        h = pd.util.hash_pandas_object(sub[EXACT_KEY], index=False).to_numpy()
        keep = sub[KEEP].copy()
        keep["row_id"], keep["h"] = rid[att], h
        parts.append(keep)
    return pd.concat(parts, ignore_index=True), offset, pair


def windows(paths=("configs/demo.yaml", "configs/fe_study.yaml", "configs/ops_holdout.yaml")):
    from netirava.dataset import window_bounds
    rows = []
    for p in paths:
        for w in window_bounds(K.load(p)):
            rows.append({"config": p, "id": w["id"], "role": w["role"], "start": w["start_ms"], "end": w["end_ms"],
                         "scope": w.get("scope_hosts")})
    return pd.DataFrame(rows).drop_duplicates(["id", "start", "end"])


def in_windows(a, wins):
    used = np.zeros(len(a), bool)
    names = np.full(len(a), "", dtype=object)
    t, src, dst = a[F.TS_START].to_numpy(), a[F.SRC].to_numpy(), a[F.DST].to_numpy()
    for _, w in wins.iterrows():
        m = (t >= w.start) & (t < w.end)
        if w.scope:
            m &= np.isin(src, w.scope) | np.isin(dst, w.scope)
        used |= m
        names[m] = np.where(names[m] == "", w.id, names[m] + "," + w.id)
    return used, names


def credible_web(a):
    pair = ((a[F.SRC] == WEB_ATT) & (a[F.DST] == WEB_VIC)) | ((a[F.SRC] == WEB_VIC) & (a[F.DST] == WEB_ATT))
    # label-specific CNS2022 window (same definition as the earlier forensics: Web 115, XSS 41, SQLi 20)
    t = a[F.TS_START].to_numpy(np.int64)
    lab = a[F.LABEL].to_numpy()
    win = {"Brute_Force_-Web": ("bf_start", "bf"), "Brute_Force_-XSS": ("xss",), "SQL_Injection": ("sqli_start", "sqli")}
    inwin = np.zeros(len(a), bool)
    for l, ks in win.items():
        for k in ks:
            inwin |= (lab == l) & (t >= W[k][0]) & (t <= W[k][1])
    tcp80 = (a.PROTOCOL == 6) & ((a[F.DPORT] == 80) | (a[F.SPORT] == 80))
    return (a[F.LABEL].isin(WEB) & pair & inwin & tcp80).to_numpy()


def run(cfg):
    a, n_rows, pair_all = scan(cfg)
    a = a.sort_values("row_id").reset_index(drop=True)
    a["dup"] = a.duplicated("h", keep="first")
    nlab = a.groupby("h")[F.LABEL].transform("nunique")
    conflict = {lab: int(((a[F.LABEL] == lab) & (nlab > 1)).sum()) for lab in a[F.LABEL].unique()}
    a["day"] = pd.to_datetime(a[F.TS_START], unit="ms", utc=True).dt.strftime("%m-%d")
    wins = windows()
    a["used"], a["used_in"] = in_windows(a, wins)
    tr = wins[wins.role == "train"]
    a["in_train"], _ = in_windows(a, tr)
    a["credible"] = credible_web(a)
    a = a.sort_values([F.LABEL, F.SRC, F.DST, F.TS_START]).reset_index(drop=True)
    new = (a[F.LABEL] != a[F.LABEL].shift()) | (a[F.SRC] != a[F.SRC].shift()) | (a[F.DST] != a[F.DST].shift()) | \
          (a[F.TS_START].diff() > GAP_MS)
    a["ep"] = new.cumsum()
    g = a.groupby("ep")
    ep = pd.DataFrame({"label": g[F.LABEL].first(), "src": g[F.SRC].first(), "dst": g[F.DST].first(), "day": g.day.first(),
                       "start_utc": pd.to_datetime(g[F.TS_START].min(), unit="ms", utc=True).dt.strftime("%m-%d %H:%M"),
                       "end_utc": pd.to_datetime(g[F.TS_START].max(), unit="ms", utc=True).dt.strftime("%m-%d %H:%M"),
                       "flows": g.size(), "flows_dedup": g.dup.agg(lambda s: int((~s).sum())),
                       "credible_dedup": g.apply(lambda x: int(x.h[x.credible].nunique())),
                       "used": g.used.any(), "used_flows": g.used.sum(), "in_train": g.in_train.any(),
                       "used_in": g.used_in.agg(lambda s: ",".join(sorted({w for v in s if v for w in v.split(",")})))})
    ep["eligible"] = ~ep.used & ~ep.in_train & (ep.credible_dedup >= 30)
    summ = {}
    for lab, x in ep.groupby("label"):
        unused = x[~x.used]
        summ[lab] = {"flows": int(x.flows.sum()), "flows_dedup": int(x.flows_dedup.sum()), "days": sorted(x.day.unique()),
                     "episodes": int(len(x)), "src_ips": int(x.src.nunique()), "dst_ips": int(x.dst.nunique()),
                     "episodes_used": int(x.used.sum()), "episodes_unused": int(len(unused)),
                     "unused_flows_dedup": int(unused.flows_dedup.sum()),
                     "unused_episodes_ge30_dedup": int((unused.flows_dedup >= 30).sum()),
                     "credible_flows_dedup": int(x.credible_dedup.sum()),
                     "credible_flows_dedup_unused": int(unused.credible_dedup.sum()),
                     "eligible_cohorts": int(x.eligible.sum())}
    pair_days = a[((a[F.SRC] == WEB_ATT) & (a[F.DST] == WEB_VIC)) | ((a[F.SRC] == WEB_VIC) & (a[F.DST] == WEB_ATT))] \
        .groupby(["day", F.LABEL]).size().to_dict()
    out = {"csv_rows": int(n_rows), "attack_rows": int(len(a)), "attack_rows_exact_duplicates": int(a.dup.sum()),
           "rows_whose_exact_copy_carries_another_label": conflict,
           "credible_definition": "web label inside its own CNS2022 window, attacker-victim pair, TCP with port 80; "
                                  "counted as unique flows (by full-row hash)",
           "by_label": summ, "web_attacker_victim_pair_by_day_label_all_rows": dict(sorted(pair_all.items())),
           "eligible": ep[ep.eligible].to_dict(orient="records"),
           "rule": __doc__.strip()}
    res = K.path(cfg, "runs") / "minority_inventory"
    res.mkdir(parents=True, exist_ok=True)
    ep.to_csv(res / "episodes.csv")
    (res / "INVENTORY.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return out
