"""Budgeted download of the pre-registered IoT-23 captures.

- Sizes are checked with HEAD first; the whole plan is aborted if it would exceed the budget.
- One attempt per file (no retries), as required by the study brief.
- Writes data/DOWNLOAD_MANIFEST.json with byte counts and sha256.
"""
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def head_size(url: str) -> int:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "rq-pcap-feasibility"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Length"])


def main() -> int:
    cfg = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))
    budget = cfg["budget"]["max_download_mb"] * 1e6
    caps = cfg["captures"][: cfg["budget"]["max_captures"]]
    plan = []
    for c in caps:
        base = f"{cfg['base_url']}/{c['id']}"
        plan.append((c["id"], f"{base}/{c['pcap']}", "capture.pcap"))
        plan.append((c["id"], f"{base}/bro/conn.log.labeled", "conn.log.labeled"))
        plan.append((c["id"], f"{base}/README.md", "README.md"))
    sizes = [head_size(u) for _, u, _ in plan]
    total = sum(sizes)
    print(f"planned {len(plan)} files, {total / 1e6:.1f} MB (budget {budget / 1e6:.0f} MB)")
    if total > budget:
        print("BLOCKED: plan exceeds budget; nothing downloaded")
        return 2
    out = ROOT / "data"
    manifest = {"budget_mb": budget / 1e6, "planned_mb": total / 1e6, "files": []}
    for (cid, url, name), size in zip(plan, sizes):
        dest = out / cid / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        h = hashlib.sha256()
        n = 0
        req = urllib.request.Request(url, headers={"User-Agent": "rq-pcap-feasibility"})
        with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
                h.update(chunk)
                n += len(chunk)
        ok = n == size
        manifest["files"].append({"capture": cid, "url": url, "path": str(dest.relative_to(ROOT)),
                                  "bytes": n, "expected": size, "complete": ok, "sha256": h.hexdigest(),
                                  "seconds": round(time.time() - t0, 1)})
        print(f"{cid}/{name}: {n / 1e6:.2f} MB {'ok' if ok else 'INCOMPLETE'}")
    manifest["downloaded_mb"] = sum(f["bytes"] for f in manifest["files"]) / 1e6
    (out / "DOWNLOAD_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
