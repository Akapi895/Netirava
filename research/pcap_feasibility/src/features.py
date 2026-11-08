"""Feature sets A (flow-only), B (packet/protocol), C (A + B) and leakage guard."""
import re

import numpy as np
import pandas as pd

A_NUM = ["duration", "orig_bytes", "resp_bytes", "missed_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts",
         "resp_ip_bytes", "resp_p"]
A_CAT = ["proto", "conn_state"]

B_GROUPS = {
    "pkt_size_dist": r"^[or]_size_",
    "timing": r"^([or]_iat_|first_resp_delay$)",
    "tcp_flags": r"^[or]_(syn|fin|rst|psh|ack|urg)$",
    "first_n_sizes": r"^first\d+_signed_size$",
    "dns_meta": r"^dns_",
    "http_meta": r"^http_",
    "tls_meta": r"^tls_",
    "ssh_meta": r"^ssh_",
    "payload_stats": r"^[or]_(payload_pkt_frac|first_payload_len|first_payload_entropy)$",
    "zeek_service": r"^zeek_service$",
}
B_CAT = {"zeek_service", "dns_qtype", "http_method", "tls_client_version"}

# Never features: identities, time, labels, capture, join artefacts, OS-fingerprint fields.
FORBIDDEN = {"ts", "uid", "orig_h", "resp_h", "orig_p", "local_orig", "local_resp", "history", "tunnel_parents",
             "label", "detailed_label", "is_malicious", "capture_id", "service", "b_missing", "b_ambiguous_pkts",
             "ip_ttl", "ip_id", "tcp_window"}


def b_columns(df: pd.DataFrame) -> dict[str, list[str]]:
    out = {}
    for g, pat in B_GROUPS.items():
        out[g] = [c for c in df.columns if re.search(pat, c) and c not in FORBIDDEN]
    return out


def feature_set(df: pd.DataFrame, name: str, exclude_groups=()) -> tuple[list[str], list[str]]:
    """Return (columns, categorical columns) for A, B or C."""
    groups = b_columns(df)
    b = [c for g, cols in groups.items() if g not in exclude_groups for c in cols]
    a = A_NUM + A_CAT
    cols = {"A": a, "B": b, "C": a + b}[name]
    bad = FORBIDDEN.intersection(cols)
    if bad:
        raise AssertionError(f"forbidden columns in feature set {name}: {bad}")
    cats = [c for c in cols if c in A_CAT or c in B_CAT]
    return cols, cats


def matrix(df: pd.DataFrame, cols: list[str], cats: list[str]) -> pd.DataFrame:
    X = df[cols].copy()
    for c in cats:
        X[c] = X[c].astype("string").fillna("NA").astype(str)
    for c in cols:
        if c not in cats:
            X[c] = pd.to_numeric(X[c], errors="coerce").astype(float)
    return X


def add_noise(X: pd.DataFrame, k: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    noise = pd.DataFrame(rng.standard_normal((len(X), k)), index=X.index, columns=[f"noise_{i}" for i in range(k)])
    return pd.concat([X, noise], axis=1)


def permute_block(X: pd.DataFrame, block: list[str], seed: int) -> pd.DataFrame:
    """Permute the rows of `block` jointly (keeps marginals and intra-block correlation, breaks the link to y/A)."""
    rng = np.random.default_rng(seed)
    X = X.copy()
    perm = rng.permutation(len(X))
    X[block] = X[block].iloc[perm].to_numpy()
    return X
