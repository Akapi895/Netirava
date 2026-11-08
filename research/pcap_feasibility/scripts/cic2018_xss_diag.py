import sys, socket, dpkt
from pathlib import Path
sys.path.insert(0, sys.argv[2] + "/scripts"); sys.path.insert(0, sys.argv[2] + "/src")
from cic2018_join_check import load_flows
from extract import parse_packets
import pandas as pd
f = load_flows(Path(sys.argv[1]))
pcap = next(Path(sys.argv[2], "data").glob("CIC2018-*/UCAP*.pcap"))
accs, st = parse_packets(pcap, f, 1.0, 5)
f["m"] = [i in accs for i in range(len(f))]
x = f[(f.attack=="Brute_Force_-XSS")]
for m, g in x.groupby("m"):
    print("matched" if m else "UNMATCHED", len(g), "time", pd.to_datetime(g.ts.min(),unit="s"), "->", pd.to_datetime(g.ts.max(),unit="s"),
          "src", g.orig_h.value_counts().head(2).to_dict(), "dst", g.resp_h.value_counts().head(2).to_dict(), "dport", g.resp_p.value_counts().head(2).to_dict(), "pkts med", g.nf_pkts.median())
tmin=tmax=None; inwin=0
lo, hi = x[~x.m].ts.min(), x[~x.m].ts.max()
with open(pcap,"rb") as fh:
    for ts, buf in dpkt.pcap.UniversalReader(fh):
        tmin = ts if tmin is None else min(tmin, ts); tmax = ts if tmax is None else max(tmax, ts)
        inwin += lo <= ts <= hi
print("pcap time", pd.to_datetime(tmin,unit="s"), "->", pd.to_datetime(tmax,unit="s"), "packets inside unmatched-XSS window", inwin)
print("all unmatched by label", f[~f.m].attack.value_counts().to_dict())
