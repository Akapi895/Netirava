"""EDA and data-quality audit for the feature-engineering study (configs/fe_study.yaml).

Holdout rows are never read (fe.study_frame). Label-dependent sections use only
inner-train / calibration rows (corrected labels); label-free sections use every
non-holdout row. Output: <derived>/eda/EDA.json (+ csv tables).
"""

import json

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.fe import CAT_CODES, study_frame

APP_SPECIFIC = {"DNS_QUERY_ID": "dns", "DNS_QUERY_TYPE": "dns", "DNS_TTL_ANSWER": "dns", "FTP_COMMAND_RET_CODE": "ftp",
                "ICMP_TYPE": "icmp", "ICMP_IPV4_TYPE": "icmp", "TCP_WIN_MAX_IN": "tcp", "TCP_WIN_MAX_OUT": "tcp",
                "TCP_FLAGS": "tcp", "CLIENT_TCP_FLAGS": "tcp", "SERVER_TCP_FLAGS": "tcp"}


def _psi(ref, cur, bins=10):
    qs = np.unique(np.quantile(ref, np.linspace(0, 1, bins + 1)))
    if len(qs) < 3:
        return 0.0 if np.array_equal(np.unique(ref), np.unique(cur)) else float("nan")
    a = np.histogram(np.clip(ref, qs[0], qs[-1]), qs)[0] / len(ref) + 1e-6
    b = np.histogram(np.clip(cur, qs[0], qs[-1]), qs)[0] / len(cur) + 1e-6
    return float(np.sum((a - b) * np.log(a / b)))


def run(cfg, sample=300_000, seed=0):
    out = K.path(cfg, "derived") / "eda"
    out.mkdir(parents=True, exist_ok=True)
    d = study_frame(cfg)
    rep = {"rows_non_holdout": len(d), "study_role_counts": d.study_role.value_counts().to_dict()}
    X = d[F.FEATURES]

    # ---- 1. per-feature profile (label-free, all non-holdout rows)
    prof = []
    for c in F.FEATURES:
        v = X[c].to_numpy(np.float64)
        top = pd.Series(v).value_counts(normalize=True).iloc[0]
        prof.append({"feature": c, "min": v.min(), "p50": np.median(v), "p99": np.quantile(v, .99), "max": v.max(),
                     "n_unique": int(pd.Series(v).nunique()), "share_zero": float((v == 0).mean()),
                     "top_value_share": float(top), "near_constant": bool(top > 0.999),
                     "categorical_code": c in CAT_CODES or c in (F.SPORT, F.DPORT, "DNS_QUERY_ID")})
    prof = pd.DataFrame(prof)
    prof.to_csv(out / "feature_profile.csv", index=False)
    rep["near_constant_features"] = prof.loc[prof.near_constant, "feature"].tolist()

    # ---- 2. structural zeros: share non-zero by protocol / application
    proto = d.PROTOCOL.to_numpy()
    dns = (d[F.DPORT].to_numpy() == 53) | (d[F.SPORT].to_numpy() == 53)
    ftp = (d[F.DPORT].to_numpy() == 21) | (d[F.SPORT].to_numpy() == 21)
    ctx = {"tcp": proto == 6, "udp": proto == 17, "icmp": proto == 1, "dns": dns, "ftp": ftp}
    struct = {}
    for c, app in APP_SPECIFIC.items():
        v = X[c].to_numpy() != 0
        struct[c] = {"nonzero_in_" + app: float(v[ctx[app]].mean()) if ctx[app].any() else None,
                     "nonzero_outside_" + app: float(v[~ctx[app]].mean())}
    rep["structural_zeros"] = struct
    rep["protocol_counts"] = pd.Series(proto).value_counts().to_dict()

    # ---- 3. internal consistency checks (label-free)
    tot = d.IN_PKTS + d.OUT_PKTS
    hist = d[[c for c in F.FEATURES if c.startswith("NUM_PKTS_")]].sum(axis=1)
    chk = {
        "hist_sum_ne_total_pkts": int((hist != tot).sum()),
        "duration_in_gt_flow_duration": int((d.DURATION_IN > d.FLOW_DURATION_MILLISECONDS).sum()),
        "duration_out_gt_flow_duration": int((d.DURATION_OUT > d.FLOW_DURATION_MILLISECONDS).sum()),
        "min_ttl_gt_max_ttl": int((d.MIN_TTL > d.MAX_TTL).sum()),
        "shortest_gt_longest_pkt": int((d.SHORTEST_FLOW_PKT > d.LONGEST_FLOW_PKT).sum()),
        "in_bytes_lt_20x_in_pkts": int((d.IN_BYTES < 20 * d.IN_PKTS).sum()),
        "out_pkts_zero": int((d.OUT_PKTS == 0).sum()),
        "zero_duration_multi_pkt": int(((d.FLOW_DURATION_MILLISECONDS == 0) & (tot > 1)).sum()),
        "retrans_in_gt_in_pkts": int((d.RETRANSMITTED_IN_PKTS > d.IN_PKTS).sum()),
        "rows": len(d)}
    rep["consistency"] = chk

    # ---- 4. redundancy: Spearman on an inner-train sample (label-free use of inner-train rows)
    tr = d[d.study_role == "inner_train"]
    smp = tr.sample(min(sample, len(tr)), random_state=seed)
    num = [c for c in F.FEATURES if smp[c].nunique() > 1]
    rho = smp[num].rank().corr()
    pairs = [(a, b, float(rho.loc[a, b])) for i, a in enumerate(num) for b in num[i + 1:] if abs(rho.loc[a, b]) >= 0.95]
    rep["redundant_pairs_abs_rho_ge_0.95"] = sorted(pairs, key=lambda x: -abs(x[2]))
    rep["constant_in_inner_train"] = [c for c in F.FEATURES if c not in num]

    # ---- 5. drift (label-free): PSI of each feature, inner-train vs calibration / dev segments
    drift = {}
    ref = smp
    for name, g in [("C1", d[d.study_role == "calib"])] + [(s, d[d.segment == s]) for s in cfg["fe_study"]["dev_fp_segments"]]:
        g = g.sample(min(sample, len(g)), random_state=seed)
        drift[name] = {c: _psi(ref[c].to_numpy(float), g[c].to_numpy(float)) for c in F.FEATURES}
    dr = pd.DataFrame(drift)
    dr.to_csv(out / "drift_psi.csv")
    rep["drift_top10_mean_psi"] = dr.mean(axis=1).sort_values(ascending=False).head(10).round(3).to_dict()
    # benign-only drift (labels of calibration + inner-train only)
    btr = tr[tr.label_corrected == "Benign"]
    bca = d[(d.study_role == "calib") & (d.label_corrected == "Benign")]
    b1, b2 = btr.sample(min(sample, len(btr)), random_state=seed), bca.sample(min(sample, len(bca)), random_state=seed)
    bpsi = pd.Series({c: _psi(b1[c].to_numpy(float), b2[c].to_numpy(float)) for c in F.FEATURES})
    rep["benign_drift_train_vs_C1_top10_psi"] = bpsi.sort_values(ascending=False).head(10).round(3).to_dict()

    # ---- 6. labels (inner-train + calibration only)
    lab = d[d.study_role.isin(["inner_train", "inner_val", "calib", "excluded"])]
    rep["support_corrected"] = {r: g.label_corrected.value_counts().to_dict() for r, g in lab.groupby("study_role")}
    rep["status_in_train_windows"] = d[d.role == "train"].status.value_counts().to_dict()

    # ---- 7. duplicates + label conflicts in inner-train
    fp = F.fingerprint(tr)
    t2 = pd.DataFrame({"fp": fp, "y": tr.label_corrected.to_numpy()})
    dup_rows = t2.duplicated(["fp", "y"]).sum()
    nl = t2.groupby("fp").y.nunique()
    multi = t2.fp.map(nl) > 1
    rep["inner_train_duplicates"] = {
        "rows": len(t2), "exact_duplicate_rows": int(dup_rows), "unique_rows": int(len(t2) - dup_rows),
        "duplicate_share_by_class": t2.assign(dup=t2.duplicated(["fp", "y"], keep=False)).groupby("y").dup.mean().round(4).to_dict(),
        "multi_label_fingerprints": int((nl > 1).sum()),
        "rows_in_multi_label_fingerprints_by_class": t2[multi].y.value_counts().to_dict(),
        "multi_label_pairs": t2[multi].groupby("fp").y.agg(lambda s: "|".join(sorted(set(s)))).value_counts().head(10).to_dict()}
    # val rows whose fingerprint was seen in inner-train (leakage-by-duplication indicator)
    va = d[d.study_role == "inner_val"]
    seen = pd.Series(F.fingerprint(va)).isin(set(fp)).to_numpy()
    rep["inner_val_fingerprint_seen_in_train_by_class"] = pd.Series(seen).groupby(va.label_corrected.to_numpy()).mean().round(4).to_dict()

    # ---- 8. host / episode structure per class (inner-train)
    hs = {}
    for y, g in tr.groupby("label_corrected"):
        hs[y] = {"rows": len(g), "src_ips": int(g[F.SRC].nunique()), "dst_ips": int(g[F.DST].nunique()),
                 "segments": sorted(g.segment.unique().tolist())}
    rep["host_structure_inner_train"] = hs

    # ---- 9. shortcut signal: share of attack rows whose value never occurs among inner-train benign rows
    ben = tr[tr.label_corrected == "Benign"]
    att = tr[tr.label_corrected != "Benign"]
    sc = {}
    for c in F.FEATURES:
        bv = set(ben[c].unique())
        sc[c] = {y: float((~g[c].isin(bv)).mean()) for y, g in att.groupby("label_corrected")}
    scd = pd.DataFrame(sc).T
    scd.to_csv(out / "value_unseen_in_benign.csv")
    rep["features_value_exclusive_to_attack_mean_top10"] = scd.mean(axis=1).sort_values(ascending=False).head(10).round(3).to_dict()

    # ---- 10. mutual information with the class (inner-train sample)
    from sklearn.feature_selection import mutual_info_classif
    ms = pd.concat([g.sample(min(len(g), 20000), random_state=seed) for _, g in tr.groupby("label_corrected")])
    disc = [c in CAT_CODES or c in (F.SPORT, F.DPORT, "DNS_QUERY_ID") for c in F.FEATURES]
    mi = mutual_info_classif(ms[F.FEATURES].to_numpy(float), ms.label_corrected.to_numpy(), discrete_features=disc,
                             random_state=seed)
    mi = pd.Series(mi, index=F.FEATURES).sort_values(ascending=False)
    mi.to_csv(out / "mutual_info.csv")
    rep["mutual_info_top15"] = mi.head(15).round(3).to_dict()
    rep["mutual_info_bottom10"] = mi.tail(10).round(4).to_dict()

    (out / "EDA.json").write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
    return rep
