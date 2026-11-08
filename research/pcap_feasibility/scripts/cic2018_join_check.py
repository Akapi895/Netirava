"""Source A join feasibility (NO modelling): can NF-CSE-CIC-IDS2018-v3 flows of the 22-02 web windows be joined
to packets of the web server's per-host pcap (172.31.69.28)? Reads Netirava artifacts read-only.
Usage: python -I scripts/cic2018_join_check.py <netirava root>"""
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from extract import parse_packets  # noqa: E402

HOST = "172.31.69.28"
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}


def load_flows(netirava: Path) -> pd.DataFrame:
    art = netirava / "artifacts" / "cic18_causal_demo_v1"
    cols = ["flow_id", "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS", "IPV4_SRC_ADDR", "L4_SRC_PORT",
            "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL", "IN_PKTS", "OUT_PKTS", "segment"]
    s = pq.read_table(art / "stream.parquet", columns=cols,
                      filters=[("segment", "in", ["T5_0222_web_head", "K5_0222_web_tail"])]).to_pandas()
    s = s[(s.IPV4_SRC_ADDR == HOST) | (s.IPV4_DST_ADDR == HOST)]
    t = pq.read_table(art / "truth.parquet", columns=["flow_id", "Attack", "label_quality"]).to_pandas()
    s = s.merge(t, on="flow_id", how="left")
    s = s[s.PROTOCOL.isin(PROTO)].reset_index(drop=True)
    return pd.DataFrame({"ts": s.FLOW_START_MILLISECONDS / 1e3,
                         "duration": (s.FLOW_END_MILLISECONDS - s.FLOW_START_MILLISECONDS) / 1e3,
                         "proto": s.PROTOCOL.map(PROTO), "orig_h": s.IPV4_SRC_ADDR, "orig_p": s.L4_SRC_PORT,
                         "resp_h": s.IPV4_DST_ADDR, "resp_p": s.L4_DST_PORT, "service": np.nan,
                         "nf_pkts": s.IN_PKTS + s.OUT_PKTS, "attack": s.Attack, "segment": s.segment})


def main(netirava: Path):
    pcap = next((ROOT / "data").glob("CIC2018-*/UCAP172.31.69.28.pcap"))
    flows = load_flows(netirava)
    out = {"nf_flows_touching_host": len(flows), "labels": flows["attack"].value_counts().to_dict(),
           "nf_time_range_utc": [str(pd.to_datetime(flows.ts.min(), unit="s")), str(pd.to_datetime(flows.ts.max(), unit="s"))]}
    # Offset scan on a sample (time zone of pcap vs NF timestamps is not documented): 0, +-1h .. +-5h
    sample = flows.sample(min(3000, len(flows)), random_state=0).reset_index(drop=True)
    scan = {}
    for h in range(-5, 6):
        sh = sample.assign(ts=sample.ts + h * 3600)
        accs, st = parse_packets(pcap, sh, tol=1.0, first_n=5)
        scan[h] = len(accs) / len(sh)
    best = max(scan, key=scan.get)
    out["offset_scan_match_rate"] = scan
    out["best_offset_h"] = best
    f = flows.assign(ts=flows.ts + best * 3600)
    accs, st = parse_packets(pcap, f, tol=1.0, first_n=5)
    got = np.array([accs[i].o.n + accs[i].r.n if i in accs else 0 for i in range(len(f))])
    amb = np.array([accs[i].ambiguous if i in accs else 0 for i in range(len(f))])
    matched = got > 0
    ratio = got[matched] / f.nf_pkts.to_numpy()[matched].clip(min=1)
    out.update(pcap_stats=st, join_rate=float(matched.mean()), flows_ambiguous=int((amb > 0).sum()),
               pkt_count_ratio_pcap_over_nf={"median": float(np.median(ratio)), "p10": float(np.quantile(ratio, .1)),
                                             "p90": float(np.quantile(ratio, .9)),
                                             "exact_share": float((got[matched] == f.nf_pkts.to_numpy()[matched]).mean())},
               join_rate_by_label=f.assign(m=matched).groupby("attack")["m"].agg(["mean", "size"]).round(4).to_dict("index"),
               join_rate_by_segment=f.assign(m=matched).groupby("segment")["m"].mean().round(4).to_dict())
    (ROOT / "results" / "cic2018_join_check.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
