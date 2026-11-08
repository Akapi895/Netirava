"""Parser for IoT-23 `conn.log.labeled` (Zeek conn.log + label columns).

Quirk: in some captures the last three fields (tunnel_parents, label, detailed-label) are separated by
spaces instead of tabs, both in the `#fields` header and in rows. Both variants are handled.
"""
import re
from pathlib import Path

import numpy as np
import pandas as pd

TAIL = ["tunnel_parents", "label", "detailed_label"]
NUMERIC = ["ts", "duration", "orig_bytes", "resp_bytes", "missed_bytes", "orig_pkts", "orig_ip_bytes",
           "resp_pkts", "resp_ip_bytes", "orig_p", "resp_p"]


def _split(line: str, n: int) -> list[str]:
    parts = line.rstrip("\n").rstrip("\r").split("\t")
    if len(parts) < n:
        parts = parts[:-1] + re.split(r"\s+", parts[-1].strip())
    return parts


def read_conn_labeled(path: Path) -> pd.DataFrame:
    fields = None
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                head = _split(line, 0)[1:]
                head = head[:-1] + re.split(r"\s+", head[-1].strip()) if len(head) < 23 else head
                fields = [h.replace("id.", "").replace(".", "_").replace("-", "_") for h in head]
                fields = fields[:-3] + TAIL
                continue
            if line.startswith("#") or not line.strip():
                continue
            parts = _split(line, len(fields))
            if len(parts) != len(fields):
                raise ValueError(f"bad row in {path}: {len(parts)} fields, expected {len(fields)}")
            rows.append(parts)
    df = pd.DataFrame(rows, columns=fields)
    df = df.replace({"-": np.nan, "(empty)": np.nan})
    for c in NUMERIC:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["label"] = df["label"].str.strip()
    df["is_malicious"] = (df["label"].str.lower() == "malicious").astype(int)
    df["detailed_label"] = df["detailed_label"].fillna("Benign").where(df["is_malicious"] == 1, "Benign")
    return df.reset_index(drop=True)
