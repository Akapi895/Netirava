import numpy as np
import pandas as pd
import pytest

from netirava import features as F
from netirava.fe import FeaturePipeline, context_features, drop_exact_duplicates


def _flows(n=400, seed=0):
    rng = np.random.default_rng(seed)
    d = pd.DataFrame({c: rng.integers(0, 50, n).astype(float) for c in F.FEATURES})
    d["PROTOCOL"] = rng.choice([6, 17, 1], n).astype(float)
    d[F.DPORT] = rng.choice([80, 443, 53, 21, 3389, 50000], n).astype(float)
    d[F.SPORT] = rng.integers(1000, 65000, n).astype(float)
    d["flow_id"] = np.arange(n)
    d["segment"] = np.where(np.arange(n) < n // 2, "A", "B")
    d["available_at"] = np.sort(rng.integers(0, 600_000, n)) + np.where(d.segment == "B", 10_000_000, 0)
    d[F.TS_START] = d.available_at - 10
    d[F.TS_END] = d.available_at
    d[F.SRC] = rng.choice(["10.0.0.1", "10.0.0.2", "10.0.0.3"], n)
    d[F.DST] = rng.choice(["10.0.1.1", "10.0.1.2"], n)
    return d


def test_context_is_causal_prefix_invariant_and_order_free():
    d = _flows()
    full = context_features(d)
    # change every flow after time T: features of flows available at or before T must not change
    T = int(np.median(d.available_at[d.segment == "A"]))
    d2 = d.copy()
    fut = d2.available_at > T
    d2.loc[fut, F.DPORT] = 9999.0
    d2.loc[fut, "IN_BYTES"] = 1e6
    d2.loc[fut, F.DST] = "10.9.9.9"
    past = (d.available_at <= T).to_numpy()
    pd.testing.assert_frame_equal(full[past], context_features(d2)[past])
    # row order does not matter
    sh = d.sample(frac=1, random_state=1)
    pd.testing.assert_frame_equal(full, context_features(sh).loc[d.index])
    # a flow never sees itself or flows with the same available_at; first flow of an entity sees nothing
    first = d.sort_values(["available_at", "flow_id"]).groupby(["segment", F.SRC]).head(1).index
    assert (full.loc[first, "ctx_src_n"] == 0).all()


def test_context_resets_at_segment_boundary():
    d = _flows()
    d[F.SRC] = "10.0.0.1"
    ctx = context_features(d)
    firstB = d[d.segment == "B"].sort_values("available_at").index[0]
    assert ctx.loc[firstB, "ctx_src_n"] == 0


def test_pipeline_learns_only_from_fit_frame_and_never_emits_identifiers():
    d = _flows()
    tr, va = d.iloc[:200], d.iloc[200:].copy()
    p = FeaturePipeline({"prep": True, "ratio": True, "flag": True}).fit(tr)
    ports = set(p.top_ports)
    va[F.DPORT] = 12345.0                       # changing val data cannot change learned state
    p.transform(va)
    assert p.top_ports == ports
    X, cats = p.transform(va)
    assert not set(X.columns) & set(F.NEVER_INPUT)
    assert set(cats) <= set(X.columns)
    assert (X.loc[va.PROTOCOL != 6, "TCP_FLAGS"] == "NA").all()   # structural NaN for non-TCP


def test_g0_pipeline_equals_feature_matrix():
    d = _flows()
    X, cats = FeaturePipeline({}).fit(d).transform(d)
    assert cats == [] and list(X.columns) == F.FEATURES
    np.testing.assert_array_equal(X.to_numpy(), F.matrix(d))


def test_drop_and_controls():
    d = _flows()
    p = FeaturePipeline({"drop": ["L4_SRC_PORT", "DNS_QUERY_ID"], "ratio": True, "permute": "ratio", "noise": 3}).fit(d)
    X, _ = p.transform(d, seed=0)
    assert "L4_SRC_PORT" not in X and "DNS_QUERY_ID" not in X
    assert sum(c.startswith("noise_") for c in X.columns) == 3
    Xr, _ = FeaturePipeline({"ratio": True}).fit(d).transform(d)
    assert not np.array_equal(X["r_in_bpp"].fillna(-1).to_numpy(), Xr["r_in_bpp"].fillna(-1).to_numpy())
    assert sorted(X["r_in_bpp"].fillna(-1)) == sorted(Xr["r_in_bpp"].fillna(-1))   # same marginal


def test_exact_duplicates_keep_first_copy():
    d = _flows(50)
    dup = d.iloc[[3, 7]].copy()
    dup["flow_id"] = [1000, 1001]
    out = drop_exact_duplicates(pd.concat([d, dup], ignore_index=True))
    assert len(out) == 50 and out.attrs["exact_duplicates_removed"] == 2
    assert not out.flow_id.isin([1000, 1001]).any()


def test_smote_only_adds_rows_of_planned_classes():
    from netirava.fstudy import _smote
    d = _flows(600)
    X, cats = FeaturePipeline({"prep": True, "ratio": True}).fit(d).transform(d)
    X = X.reset_index(drop=True)
    y = np.zeros(len(X), np.int64)
    y[:40] = 1
    rec = {"smote_lt": 100, "smote_k": 5, "seed": 0}
    cont = [c for c in X.columns if c not in cats]
    L = np.log1p(X[cont].astype(float).fillna(-0.5).clip(lower=-0.5))
    Xr, yr, info = _smote(X, y, cats, rec, ["Benign", "Rare"], (L.median(), (L.quantile(.75) - L.quantile(.25)).replace(0, 1.0)))
    assert info["applied"] and len(Xr) == len(X) + 60 and (yr[len(X):] == 1).all()
    for c in cats:                                  # categorical values are copied from real rows
        assert set(Xr[c].iloc[len(X):]) <= set(X.loc[y == 1, c])
