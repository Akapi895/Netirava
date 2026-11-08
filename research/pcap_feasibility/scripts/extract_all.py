"""Join each capture's labeled Zeek flows with packet/protocol features. One process per capture so the
reported peak RSS is per capture.  Usage: python -I scripts/extract_all.py <capture_id>"""
import json
import sys
import time
from pathlib import Path

import psutil
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from extract import extract  # noqa: E402
from zeeklog import read_conn_labeled  # noqa: E402


def main(cid: str) -> None:
    cfg = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    t0 = time.perf_counter()
    flows = read_conn_labeled(ROOT / "data" / cid / "conn.log.labeled")
    t_log = time.perf_counter() - t0
    feats, st = extract(ROOT / "data" / cid / "capture.pcap", flows, cfg["join"]["time_tolerance_s"],
                        cfg["features"]["first_n"])
    out = flows.join(feats)
    out["capture_id"] = cid
    dest = ROOT / "work" / cid
    dest.mkdir(parents=True, exist_ok=True)
    out.to_parquet(dest / "flows_features.parquet", index=False)
    mi = proc.memory_info()
    st.update(capture=cid, zeek_log_seconds=round(t_log, 2), total_seconds=round(time.perf_counter() - t0, 2),
              rss_start_mb=round(rss0 / 1e6, 1), rss_end_mb=round(mi.rss / 1e6, 1),
              peak_mb=round(getattr(mi, "peak_wset", mi.rss) / 1e6, 1),
              pcap_mb=round((ROOT / "data" / cid / "capture.pcap").stat().st_size / 1e6, 2))
    (dest / "extract_stats.json").write_text(json.dumps(st, indent=2), encoding="utf-8")
    print(json.dumps(st))


if __name__ == "__main__":
    main(sys.argv[1])
