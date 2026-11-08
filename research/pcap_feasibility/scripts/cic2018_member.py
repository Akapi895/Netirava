"""Fetch ONE member of a CIC-2018 per-day pcap.zip with HTTP Range requests (no full archive download).
Usage: python -I scripts/cic2018_member.py <day> <member name> <max_mb>"""
import hashlib, json, struct, sys, time, urllib.request, zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
day, member, max_mb = sys.argv[1], sys.argv[2], float(sys.argv[3])
url = f"https://cse-cic-ids2018.s3.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/{day}/pcap.zip"
fetched = 0

def rng(a, b):
    global fetched
    r = urllib.request.Request(url, headers={"Range": f"bytes={a}-{b}", "User-Agent": "rq-pcap-feasibility"})
    with urllib.request.urlopen(r, timeout=300) as f:
        data = f.read()
    fetched += len(data)
    return data

size = int(urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60).headers["Content-Length"])
tail = rng(size - 65536, size - 1)
i = tail.rfind(b"PK\x06\x07")
z64 = struct.unpack("<Q", tail[i + 8:i + 16])[0]
n, cd_size, cd_off = struct.unpack("<QQQ", rng(z64, z64 + 55)[32:56])
cd = rng(cd_off, cd_off + cd_size - 1)
p = 0
info = None
while cd[p:p + 4] == b"PK\x01\x02":
    method = struct.unpack("<H", cd[p + 10:p + 12])[0]
    csize, usize = struct.unpack("<II", cd[p + 20:p + 28])
    nl, el, cl = struct.unpack("<HHH", cd[p + 28:p + 34])
    off = struct.unpack("<I", cd[p + 42:p + 46])[0]
    name = cd[p + 46:p + 46 + nl].decode(errors="replace")
    extra = cd[p + 46 + nl:p + 46 + nl + el]
    q = 0
    while q < len(extra) - 4:
        hid, hl = struct.unpack("<HH", extra[q:q + 4])
        if hid == 1:
            k = q + 4
            if usize == 0xFFFFFFFF: usize = struct.unpack("<Q", extra[k:k + 8])[0]; k += 8
            if csize == 0xFFFFFFFF: csize = struct.unpack("<Q", extra[k:k + 8])[0]; k += 8
            if off == 0xFFFFFFFF: off = struct.unpack("<Q", extra[k:k + 8])[0]
        q += 4 + hl
    if name == member:
        info = dict(method=method, csize=csize, usize=usize, offset=off)
    p += 46 + nl + el + cl
assert info, f"member {member} not found"
print(json.dumps(info))
if info["csize"] > max_mb * 1e6:
    sys.exit(f"BLOCKED: member is {info['csize'] / 1e6:.1f} MB > {max_mb} MB")
lh = rng(info["offset"], info["offset"] + 29)
nl, el = struct.unpack("<HH", lh[26:30])
start = info["offset"] + 30 + nl + el
comp = rng(start, start + info["csize"] - 1)
if info["method"] == 8:
    raw = zlib.decompress(comp, -15)
elif info["method"] == 0:
    raw = comp
else:
    sys.exit(f"BLOCKED: unsupported zip method {info['method']}")
dest = ROOT / "data" / f"CIC2018-{day}" / (member.split("/")[-1] + ".pcap")
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_bytes(raw)
man = dict(url=url, member=member, **info, bytes_fetched=fetched, sha256=hashlib.sha256(raw).hexdigest(),
           path=str(dest.relative_to(ROOT)), at=time.strftime("%Y-%m-%d %H:%M:%S"))
(dest.parent / "MEMBER_MANIFEST.json").write_text(json.dumps(man, indent=2), encoding="utf-8")
print(json.dumps(man))
