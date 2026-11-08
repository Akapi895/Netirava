"""Run the pre-registered RQ-PCAP evaluation. Usage: python -I scripts/run_eval.py"""
import glob
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import psutil
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import evaluate as E  # noqa: E402
import features as F  # noqa: E402


def jdump(obj, name):
    def conv(o):
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        raise TypeError(type(o))
    (ROOT / "results" / name).write_text(json.dumps(obj, indent=2, default=conv), encoding="utf-8")


def coverage(df: pd.DataFrame) -> dict:
    groups = F.b_columns(df)
    out = {"flows": len(df), "per_capture": {}, "groups": {}, "missing_by_column": {}}
    for c, g in df.groupby("capture_id"):
        out["per_capture"][c] = {"flows": len(g), "labels": g["detailed_label"].value_counts().to_dict(),
                                 "proto": g["proto"].value_counts().to_dict(),
                                 "zero_packet_zeek_records": int(((g.orig_pkts == 0) & (g.resp_pkts == 0)).sum()),
                                 "distinct_destinations_by_label": g.groupby("detailed_label").apply(
                                     lambda x: x[["resp_h", "resp_p"]].drop_duplicates().shape[0]).to_dict()}
    for gname, cols in groups.items():
        if not cols:
            out["groups"][gname] = {"columns": 0, "coverage": 0.0, "note": "no flow carried this protocol"}
            continue
        if gname == "zeek_service":
            has = df["zeek_service"] != "none"
        else:
            has = df[cols].notna().any(axis=1)
        out["groups"][gname] = {"columns": len(cols), "coverage": float(has.mean()),
                                "coverage_by_label": df.assign(h=has).groupby("detailed_label")["h"].mean().round(4).to_dict()}
    for c in F.feature_set(df, "C")[0]:
        miss = float(df[c].isna().mean()) if c not in ("zeek_service",) else float((df[c] == "none").mean())
        out["missing_by_column"][c] = round(miss, 4)
    pay = (df["o_first_payload_len"].fillna(0) > 0) | (df["r_first_payload_len"].fillna(0) > 0)
    meta = df[[c for g in ("dns_meta", "http_meta", "tls_meta", "ssh_meta") for c in groups[g]]].notna().any(axis=1)
    enc = df[[c for g in ("tls_meta", "ssh_meta") for c in groups[g]]].notna().any(axis=1) if groups["tls_meta"] + groups["ssh_meta"] else pd.Series(False, index=df.index)
    out["share"] = {"encrypted_tls_ssh": float(enc.mean()), "with_protocol_metadata": float(meta.mean()),
                    "no_metadata": float(1 - meta.mean()), "no_payload_either_direction": float(1 - pay.mean()),
                    "no_metadata_by_label": df.assign(m=~meta).groupby("detailed_label")["m"].mean().round(4).to_dict()}
    return out


def main():
    cfg = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))
    seeds = cfg["model"]["seeds"]
    df = pd.concat([pd.read_parquet(f) for f in sorted(glob.glob(str(ROOT / "work" / "*" / "flows_features.parquet")))],
                   ignore_index=True)
    proc = psutil.Process()
    log = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "python": platform.python_version(),
           "git_commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                                        cwd=ROOT).stdout.strip(),
           "extract": {Path(p).parent.name: json.loads(Path(p).read_text(encoding="utf-8"))
                       for p in sorted(glob.glob(str(ROOT / "work" / "*" / "extract_stats.json")))}}
    t = time.perf_counter()
    jdump(coverage(df), "coverage.json")
    print("coverage done", flush=True)

    rows = E.loco(df, cfg, ["A", "B", "C", "A_plus_noise", "A_plus_permuted_B"], seeds)
    jdump(rows, "loco_main.json")
    print("loco main done", round(time.perf_counter() - t), flush=True)

    abl = []
    for g in F.B_GROUPS:
        if F.b_columns(df)[g]:
            abl += E.loco(df, cfg, ["C"], seeds[:1], exclude_groups=(g,), variant_name=f"C_minus_{g}")
    jdump(abl, "loco_ablation_groups.json")
    print("ablation done", round(time.perf_counter() - t), flush=True)

    jdump({"benign_only": E.capture_identifiability(df, cfg, True)}, "capture_identifiability.json")
    print("identifiability done", round(time.perf_counter() - t), flush=True)

    jdump(E.within_capture_multiclass(df, cfg, seeds), "within_capture_multiclass_EXPLORATORY.json")
    log.update(finished=time.strftime("%Y-%m-%d %H:%M:%S"), eval_seconds=round(time.perf_counter() - t, 1),
               eval_peak_mb=round(getattr(proc.memory_info(), "peak_wset", proc.memory_info().rss) / 1e6, 1))
    jdump(log, "run_log.json")
    print("all done", log["eval_seconds"], flush=True)


if __name__ == "__main__":
    main()
