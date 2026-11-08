"""Feature-engineering study: study frame, leakage-safe inner split, feature groups, causal context.

Pre-registered in configs/fe_study.yaml. Leakage guards:
  * holdout rows are never loaded here (study_frame asserts it);
  * every learned parameter (top-k ports, SMOTE scaler) is fitted on inner-train only (FeaturePipeline.fit);
  * the inner split is by time with a purge gap: inner-train flows END before the cut,
    inner-val flows START at least `purge_ms` after it;
  * context features use only flows of the same segment that became available STRICTLY earlier.
"""

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream

EXCLUDE_STATUS = {"attempted", "indeterminate"}
WEB_SEGS = ("T5_0222_web_head", "K5_0222_web_tail")

CAT_CODES = ["PROTOCOL", "L7_PROTO", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_TYPE", "FTP_COMMAND_RET_CODE",
             "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS"]
FLAG_COLS = ["TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS"]
FLAG_BITS = {"FIN": 1, "SYN": 2, "RST": 4, "PSH": 8, "ACK": 16, "URG": 32, "ECE": 64, "CWR": 128}
SHORTCUT = ["L4_SRC_PORT", "DNS_QUERY_ID", "MIN_TTL", "MAX_TTL", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT"]
CTX_WINDOW_MS = 60_000


# --------------------------------------------------------------------------- study frame + split
EXACT_KEY = [F.TS_START, F.TS_END, F.SRC, F.DST] + F.FEATURES


def drop_exact_duplicates(df):
    """Remove flows that are identical in timestamps, IPs, ports and all 49 features (NF-v3 exports
    ~50% of FTP/SSH/GoldenEye attack flows twice; EDA 2026-11-08). Label-free and causal: the
    first copy (lowest flow_id) is kept; applicable at runtime as an event de-duplication."""
    keep = ~df.sort_values("flow_id").duplicated(EXACT_KEY, keep="first")
    out = df.loc[keep.reindex(df.index).to_numpy()].copy()
    out.attrs["exact_duplicates_removed"] = int(len(df) - len(out))
    return out.reset_index(drop=True)


def study_frame(cfg):
    """Non-holdout stream rows + corrected/original labels + study_role.
    study_role: inner_train | inner_val | calib | dev | known_tail | excluded."""
    from netirava.pilot import pilot_role
    roles = sorted({w["role"] for w in cfg["windows"]} - {"holdout"})
    s = load_stream(cfg, roles=roles)
    assert not (s.role == "holdout").any(), "holdout rows must never enter the study"
    ann = pd.read_parquet(K.path(cfg, "derived") / "truth_cns2022.parquet",
                          columns=["flow_id", "label_original", "label_corrected", "status"])
    d = s.merge(ann, on="flow_id", how="left", validate="one_to_one")
    assert d.label_corrected.notna().all()
    d = drop_exact_duplicates(d)
    ic = cfg["fe_study"]["inner_split"]
    sr = np.full(len(d), "other", dtype=object)
    sr[d.role.to_numpy() == "calibration"] = "calib"
    sr[np.isin(d.segment, cfg["fe_study"]["dev_fp_segments"])] = "dev"
    sr[(d.role.to_numpy() == "known_replay") & ~np.isin(d.segment, WEB_SEGS)] = "known_tail"
    # T1-T4: time split with purge
    t0, t1 = d[F.TS_START].to_numpy(np.int64), d.available_at.to_numpy(np.int64)
    for seg, g in d[(d.role == "train") & ~d.segment.isin(WEB_SEGS)].groupby("segment"):
        cut = np.quantile(g[F.TS_START].to_numpy(np.int64), ic["fit_frac"])
        idx = g.index.to_numpy()
        sr[idx[t1[idx] < cut]] = "inner_train"
        sr[idx[t0[idx] >= cut + ic["purge_ms"]]] = "inner_val"
        sr[idx[(t1[idx] >= cut) & (t0[idx] < cut + ic["purge_ms"])]] = "purged"
    # web: pilot split (declared in the pilot, unchanged)
    web = d.segment.isin(WEB_SEGS).to_numpy()
    pr = pilot_role(d[web])
    sr[np.flatnonzero(web)] = np.where(pr == "train", "inner_train", "inner_val")
    excl = d.status.isin(EXCLUDE_STATUS).to_numpy() & np.isin(sr, ["inner_train", "inner_val"])
    sr[excl] = "excluded"
    d["study_role"] = sr
    return d


def final_train_mask(d):
    """Final training set (Phase 5): whole T1-T4 + pilot-train web rows, excluded statuses dropped."""
    return ((d.role == "train") & ~d.segment.isin(WEB_SEGS) & ~d.status.isin(EXCLUDE_STATUS)) | \
           (d.segment.isin(WEB_SEGS) & (d.study_role == "inner_train"))


# --------------------------------------------------------------------------- causal context
def context_features(df, window_ms=CTX_WINDOW_MS):
    """Per flow, statistics of flows of the same entity in the same segment with
    available_at in [t - window, t) (strictly earlier). Only identifiers are used for
    grouping; they never become features. Order-independent of the input row order."""
    out = {}
    t_all = df.available_at.to_numpy(np.int64)
    seg = df.segment.to_numpy()
    for ent, peer, pre in ((F.SRC, F.DST, "src"), (F.DST, F.SRC, "dst")):
        n = np.zeros(len(df)); nd_port = np.zeros(len(df)); nd_peer = np.zeros(len(df))
        noreply = np.full(len(df), np.nan); lbytes = np.full(len(df), np.nan)
        key = pd.Series(seg).astype(str) + "|" + df[ent].astype(str).to_numpy()
        order = np.lexsort((df.flow_id.to_numpy(), t_all, key.to_numpy()))
        k_sorted = key.to_numpy()[order]
        bounds = np.flatnonzero(np.r_[True, k_sorted[1:] != k_sorted[:-1], True])
        dport, peer_v = df[F.DPORT].to_numpy(), df[peer].to_numpy()
        nor = (df.OUT_PKTS.to_numpy() == 0).astype(float)
        lb = np.log1p(df.IN_BYTES.to_numpy(np.float64))
        for a, b in zip(bounds[:-1], bounds[1:]):
            idx = order[a:b]
            t = t_all[idx]
            cp, cpe = {}, {}
            l = r = 0
            s_nor = s_lb = 0.0
            for i in range(len(idx)):
                while r < i and t[r] < t[i]:              # add flows strictly earlier than t[i]
                    j = idx[r]
                    cp[dport[j]] = cp.get(dport[j], 0) + 1
                    cpe[peer_v[j]] = cpe.get(peer_v[j], 0) + 1
                    s_nor += nor[j]; s_lb += lb[j]
                    r += 1
                while l < r and t[l] < t[i] - window_ms:   # drop flows older than the window
                    j = idx[l]
                    cp[dport[j]] -= 1
                    if not cp[dport[j]]:
                        del cp[dport[j]]
                    cpe[peer_v[j]] -= 1
                    if not cpe[peer_v[j]]:
                        del cpe[peer_v[j]]
                    s_nor -= nor[j]; s_lb -= lb[j]
                    l += 1
                k = r - l
                row = idx[i]
                n[row], nd_port[row], nd_peer[row] = k, len(cp), len(cpe)
                if k:
                    noreply[row], lbytes[row] = s_nor / k, s_lb / k
        out[f"ctx_{pre}_n"] = n
        out[f"ctx_{pre}_distinct_dport"] = nd_port
        out[f"ctx_{pre}_distinct_peer"] = nd_peer
        out[f"ctx_{pre}_noreply_share"] = noreply
        out[f"ctx_{pre}_mean_log_inbytes"] = lbytes
    return pd.DataFrame(out, index=df.index)


# --------------------------------------------------------------------------- feature pipeline
def _div(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where(b > 0, a / b, np.nan)


def port_bucket(p):
    p = np.asarray(p, np.int64)
    return np.where(p < 1024, "wk", np.where(p < 49152, "reg", "eph")).astype(object)


class FeaturePipeline:
    """Deterministic feature builder. `spec` keys:
      prep (bool)          categorical codes, port categories, structural NaN, dedup weights, SMOTE scaling
      drop (list)          raw columns dropped (shortcut candidates)
      ratio, flag, ctx     add groups
      noise (int)          add N(0,1) control columns
      permute (str|None)   name of a group whose columns are permuted (control)
    Learned state (fit on inner-train only): top-k destination ports."""
    VERSION = "fe-pipeline-v1"

    def __init__(self, spec, top_k_ports=50):
        self.spec = dict(spec)
        self.top_k = top_k_ports
        self.top_ports = None

    def fit(self, train_df):
        if self.spec.get("prep"):
            vc = train_df[F.DPORT].value_counts()
            self.top_ports = set(int(p) for p in vc.index[: self.top_k])
        return self

    def group_columns(self, X):
        g = {"ratio": [c for c in X.columns if c.startswith("r_")],
             "flag": [c for c in X.columns if c.startswith("f_")],
             "ctx": [c for c in X.columns if c.startswith("ctx_")],
             "shortcut": [c for c in SHORTCUT if c in X.columns]}
        return g

    def transform(self, df, ctx=None, seed=0):
        sp = self.spec
        X = df[F.FEATURES].copy().astype(float)
        cats = []
        if sp.get("prep"):
            proto = df.PROTOCOL.to_numpy()
            dns = (df[F.DPORT].to_numpy() == 53) | (df[F.SPORT].to_numpy() == 53)
            for c in ("DNS_QUERY_ID", "DNS_QUERY_TYPE", "DNS_TTL_ANSWER"):
                X.loc[~dns, c] = np.nan
            X.loc[(df[F.DPORT].to_numpy() != 21) & (df[F.SPORT].to_numpy() != 21), "FTP_COMMAND_RET_CODE"] = np.nan
            X.loc[proto != 1, ["ICMP_TYPE", "ICMP_IPV4_TYPE"]] = np.nan
            X.loc[proto != 6, ["TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT"] + FLAG_COLS] = np.nan
            for c in CAT_CODES:
                v = X[c]
                X[c] = np.where(v.isna(), "NA", v.fillna(0).astype(np.int64).astype(str)).astype(object)
                cats.append(c)
            dp = df[F.DPORT].to_numpy(np.int64)
            assert self.top_ports is not None, "fit() first"
            X[F.DPORT] = np.where(np.isin(dp, list(self.top_ports)), dp.astype(str),
                                  np.char.add("other_", port_bucket(dp).astype(str))).astype(object)
            X[F.SPORT] = port_bucket(df[F.SPORT].to_numpy())
            cats += [F.DPORT, F.SPORT]
        if sp.get("ratio"):
            ib, ob, ip_, op = (df[c].to_numpy(float) for c in ("IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS"))
            X["r_in_bpp"], X["r_out_bpp"] = _div(ib, ip_), _div(ob, op)
            X["r_bytes_out_in"], X["r_pkts_out_in"] = _div(ob, ib), _div(op, ip_)
            X["r_retrans_in"] = _div(df.RETRANSMITTED_IN_PKTS, ip_)
            X["r_retrans_out"] = _div(df.RETRANSMITTED_OUT_PKTS, op)
            tot = ip_ + op
            for c in ("NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES",
                      "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES"):
                X["r_share_" + c[9:]] = _div(df[c], tot)
            dur = df.FLOW_DURATION_MILLISECONDS.to_numpy(float)
            X["r_dur_in_share"], X["r_dur_out_share"] = _div(df.DURATION_IN, dur), _div(df.DURATION_OUT, dur)
            X["r_pkt_rate"] = _div(tot, dur)
        if sp.get("flag"):
            for c in FLAG_COLS:
                v = df[c].to_numpy(np.int64)
                for name, bit in FLAG_BITS.items():
                    X[f"f_{c[:6].lower()}_{name}"] = ((v & bit) > 0).astype(float)
            X["f_no_reply"] = (df.OUT_PKTS.to_numpy() == 0).astype(float)
        if sp.get("ctx"):
            assert ctx is not None, "context features must be computed on the full segment stream"
            X = X.join(ctx.loc[df.index])
        drop = [c for c in sp.get("drop", []) if c in X.columns]
        X = X.drop(columns=drop)
        cats = [c for c in cats if c in X.columns]
        if sp.get("permute"):
            cols = self.group_columns(X)[sp["permute"]]
            perm = np.random.default_rng(seed + 7919).permutation(len(X))
            X[cols] = X[cols].iloc[perm].to_numpy()
        if sp.get("noise"):
            rng = np.random.default_rng(seed + 104729)
            for i in range(int(sp["noise"])):
                X[f"noise_{i}"] = rng.standard_normal(len(X))
        bad = set(X.columns) & set(F.NEVER_INPUT)
        assert not bad, f"forbidden columns in the model input: {bad}"
        return X, cats
