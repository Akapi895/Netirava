"""Feature contract: explicit allowlist, fixed (non-learned) transforms, fingerprints.

The model input is the NetFlow v3 schema minus identifiers, absolute
timestamps and labels. Ports, TTL and DNS query id are KEPT (documented in
the model card); nothing here is learned from data.
"""

import hashlib

import numpy as np
import pandas as pd

TS_START, TS_END = "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS"
SRC, DST = "IPV4_SRC_ADDR", "IPV4_DST_ADDR"
SPORT, DPORT = "L4_SRC_PORT", "L4_DST_PORT"
LABEL_BIN, LABEL = "Label", "Attack"

FEATURES = [
    "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL", "L7_PROTO", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "FLOW_DURATION_MILLISECONDS", "DURATION_IN",
    "DURATION_OUT", "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES", "RETRANSMITTED_IN_BYTES",
    "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS", "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT", "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE", "SRC_TO_DST_IAT_MIN", "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG", "SRC_TO_DST_IAT_STDDEV", "DST_TO_SRC_IAT_MIN", "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG", "DST_TO_SRC_IAT_STDDEV",
]
# Codes / identifiers stored as integers: interpolating them (e.g. SMOTE) yields
# values with no meaning. Used by the SMOTE guard in detectors.a0.
CATEGORICAL_CODES = ["L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL", "L7_PROTO", "TCP_FLAGS", "CLIENT_TCP_FLAGS",
                     "SERVER_TCP_FLAGS", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
                     "FTP_COMMAND_RET_CODE"]
NEVER_INPUT = [SRC, DST, TS_START, TS_END, LABEL_BIN, LABEL, "row_id", "flow_id", "segment", "role",
               "label_quality", "unknown_to_model", "scenario", "available_at"]
FEATURE_SCHEMA_VERSION = "nfv3-49-allowlist-v1"

assert not set(FEATURES) & set(NEVER_INPUT)


def schema_hash():
    return hashlib.sha1(("|".join(FEATURES) + FEATURE_SCHEMA_VERSION).encode()).hexdigest()[:12]


def matrix(df):
    """Model input matrix in allowlist order; raises if a column is missing."""
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        raise KeyError(f"missing features: {missing}")
    return df[FEATURES].to_numpy(dtype=np.float64)


def log1p_signed(X):
    """Fixed transform for the anomaly detector (no fitted parameters)."""
    return np.sign(X) * np.log1p(np.abs(X))


def fingerprint(df, cols=FEATURES):
    return pd.util.hash_pandas_object(df[cols].astype("float64") + 0.0, index=False).to_numpy(np.uint64)


# --------------------------------------------------------------------------- runtime contract
CONTRACT_VERSION = "netirava-contracts-v1"
# columns a FlowEvent batch may carry (identifiers are for policy/logging, never model input)
FLOW_EVENT_COLUMNS = ["flow_id", "segment", TS_START, TS_END, "available_at", SRC, DST] + FEATURES
FORBIDDEN_IN_RUNTIME = [LABEL, LABEL_BIN, "role", "label_quality", "unknown_to_model", "scenario"]


def flow_event_batch(df):
    """Project a stream frame onto the FlowEvent contract (no labels); fail on evaluator columns."""
    bad = [c for c in FORBIDDEN_IN_RUNTIME if c in df.columns]
    if bad:
        raise ValueError(f"label/evaluator columns reached the runtime: {bad}")
    return df[FLOW_EVENT_COLUMNS]
