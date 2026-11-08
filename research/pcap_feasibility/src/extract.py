"""Packet/protocol feature extraction (feature set B) from a pcap, joined to Zeek flows.

Zeek/Tshark are not installed, so packets are parsed with dpkt. A packet is assigned to the Zeek flow
(uid) with the same 5-tuple (either direction) whose [ts - tol, ts + duration + tol] contains the packet
time; with several candidates the nearest start wins and the packet is counted as ambiguous. ICMP flows
are matched on (proto, hosts) only, because Zeek stores ICMP type/code in the port fields.

No raw payload bytes or text strings become features: only lengths, counts, entropies and enumerations.
"""
import bisect
import math
import socket
import time
from collections import Counter, defaultdict

import dpkt
import numpy as np
import pandas as pd

CAP = 2000          # per-direction cap for sample-based statistics (median/p90/std)
FIRST_BYTES = 2048  # bytes of the first payload kept in memory for protocol parsing (never stored)
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"PATCH ")
DNS_PORTS = {53, 5353, 5355}
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}


def entropy(b: bytes) -> float:
    if not b:
        return np.nan
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def str_entropy(s: str) -> float:
    return entropy(s.encode()) if s else np.nan


class Dir:
    __slots__ = ("n", "sizes", "iats", "last", "first_t", "flags", "pay_n", "first_payload")

    def __init__(self):
        self.n = 0
        self.sizes = []
        self.iats = []
        self.last = None
        self.first_t = None
        self.flags = Counter()
        self.pay_n = 0
        self.first_payload = b""


class Acc:
    __slots__ = ("o", "r", "first_n", "ambiguous")

    def __init__(self):
        self.o, self.r = Dir(), Dir()
        self.first_n = []
        self.ambiguous = 0


def build_index(flows: pd.DataFrame, tol: float):
    """key -> (sorted starts, ends, idxs). Non-ICMP key: (proto, orig_h, orig_p, resp_h, resp_p)."""
    groups = defaultdict(list)
    dur = flows["duration"].fillna(0.0).to_numpy()
    for i, (p, oh, op, rh, rp, ts) in enumerate(zip(flows["proto"], flows["orig_h"], flows["orig_p"],
                                                    flows["resp_h"], flows["resp_p"], flows["ts"])):
        key = (p, oh, rh) if p == "icmp" else (p, oh, int(op), rh, int(rp))
        groups[key].append((ts - tol, ts + dur[i] + tol, ts, i))
    index = {}
    for k, v in groups.items():
        v.sort(key=lambda x: x[2])
        index[k] = ([x[2] for x in v], v)
    return index


WINDOW = 64  # neighbours (by start time) examined on each side; dense same-5-tuple bursts are common


def lookup(index, key, t, tol):
    """Return (flow idx, n candidates). Flows whose [ts, ts+dur] contains t exactly are preferred over
    tolerance-only matches; ties broken by nearest start."""
    hit = index.get(key)
    if hit is None:
        return None, 0
    starts, rows = hit
    j = bisect.bisect_left(starts, t)
    cands = [r for r in rows[max(0, j - WINDOW):j + WINDOW] if r[0] <= t <= r[1]]
    if not cands:
        return None, 0
    best = min(cands, key=lambda r: (not (r[2] <= t <= r[1] - tol), abs(t - r[2])))
    return best[3], len(cands)


def parse_packets(pcap_path, flows: pd.DataFrame, tol: float, first_n: int):
    index = build_index(flows, tol)
    accs: dict[int, Acc] = {}
    frags: dict[tuple, tuple] = {}   # (src, dst, proto, ip.id) -> (flow idx, direction) from the first fragment
    st = Counter()
    t0 = time.perf_counter()
    with open(pcap_path, "rb") as fh:
        reader = dpkt.pcap.UniversalReader(fh)
        link = reader.datalink()
        for ts, buf in reader:
            st["packets"] += 1
            try:
                if link == dpkt.pcap.DLT_EN10MB:
                    l2 = dpkt.ethernet.Ethernet(buf)
                    ip = l2.data
                elif link == dpkt.pcap.DLT_LINUX_SLL:
                    ip = dpkt.sll.SLL(buf).data
                else:
                    ip = dpkt.ip.IP(buf)
            except Exception:
                st["undecodable"] += 1
                continue
            if not isinstance(ip, dpkt.ip.IP):
                st["non_ipv4"] += 1
                continue
            proto = PROTO.get(ip.p)
            if proto is None:
                st["other_l4"] += 1
                continue
            src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            l4 = ip.data
            frag_off = ip.offset
            more_frags = bool(ip.mf)
            if frag_off > 0:                       # non-first fragment: no L4 header, attach via IP-ID
                hit = frags.get((src, dst, ip.p, ip.id))
                if hit is None:
                    st["fragments_unattached"] += 1
                    continue
                idx, d = hit
                nc, payload, flags = 1, b"", None
                st["fragments_attached"] += 1
            elif proto == "icmp":
                k_f, k_r = ("icmp", src, dst), ("icmp", dst, src)
                payload, flags = b"", None
            else:
                if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    st["truncated_l4"] += 1
                    continue
                k_f = (proto, src, l4.sport, dst, l4.dport)
                k_r = (proto, dst, l4.dport, src, l4.sport)
                payload = bytes(l4.data)
                flags = l4.flags if proto == "tcp" else None
            if frag_off == 0:
                idx, nc = lookup(index, k_f, ts, tol)
                d = "o"
                if idx is None:
                    idx, nc = lookup(index, k_r, ts, tol)
                    d = "r"
                if idx is None:
                    st[f"unassigned_{proto}"] += 1
                    continue
                if more_frags:
                    frags[(src, dst, ip.p, ip.id)] = (idx, d)
            st["assigned"] += 1
            acc = accs.get(idx)
            if acc is None:
                acc = accs[idx] = Acc()
            if nc > 1:
                acc.ambiguous += 1
                st["ambiguous_packets"] += 1
            dd = acc.o if d == "o" else acc.r
            size = ip.len
            dd.n += 1
            if len(dd.sizes) < CAP:
                dd.sizes.append(size)
            if dd.last is not None and len(dd.iats) < CAP:
                dd.iats.append(ts - dd.last)
            if dd.first_t is None:
                dd.first_t = ts
            dd.last = ts
            if flags is not None:
                for name, bit in (("syn", 0x02), ("fin", 0x01), ("rst", 0x04), ("psh", 0x08), ("ack", 0x10),
                                  ("urg", 0x20)):
                    if flags & bit:
                        dd.flags[name] += 1
            if payload:
                dd.pay_n += 1
                if not dd.first_payload:
                    dd.first_payload = payload[:FIRST_BYTES]
            if len(acc.first_n) < first_n:
                acc.first_n.append(size if d == "o" else -size)
    st["parse_seconds"] = round(time.perf_counter() - t0, 2)
    return accs, st


def dns_meta(payload: bytes, tcp: bool) -> dict:
    out = {}
    try:
        msg = dpkt.dns.DNS(payload[2:] if tcp else payload)
    except Exception:
        return out
    if msg.qd:
        q = msg.qd[0]
        name = q.name or ""
        out.update(dns_qtype=str(q.type), dns_qname_len=len(name), dns_qname_labels=name.count(".") + 1,
                   dns_qname_entropy=str_entropy(name),
                   dns_qname_digit_frac=sum(ch.isdigit() for ch in name) / max(len(name), 1))
    if msg.qr == dpkt.dns.DNS_R:
        out.update(dns_rcode=float(msg.rcode), dns_ancount=float(len(msg.an)),
                   dns_min_ttl=float(min((a.ttl for a in msg.an), default=np.nan)))
    return out


def http_meta(o: bytes, r: bytes) -> dict:
    out = {}
    if o.startswith(HTTP_METHODS):
        head = o.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
        req = head[0].split(b" ")
        hdr = {}
        for line in head[1:]:
            k, _, v = line.partition(b":")
            hdr[k.strip().lower()] = v.strip()
        host = hdr.get(b"host", b"").split(b":")[0]
        out.update(http_method=req[0].decode(errors="replace"), http_uri_len=float(len(req[1]) if len(req) > 1 else 0),
                   http_n_headers=float(len(head) - 1), http_has_ua=float(b"user-agent" in hdr),
                   http_ua_len=float(len(hdr.get(b"user-agent", b""))),
                   http_host_is_ip=float(bool(host) and all(p.isdigit() for p in host.split(b"."))))
    if r.startswith(b"HTTP/"):
        parts = r.split(b"\r\n", 1)[0].split(b" ")
        try:
            out["http_status"] = float(parts[1])
        except (IndexError, ValueError):
            pass
    return out


def tls_meta(o: bytes, r: bytes) -> dict:
    out = {}
    if len(o) > 43 and o[0] == 0x16 and o[1] == 3 and o[5] == 1:
        out["tls_client_hello"] = 1.0
        out["tls_client_version"] = str(o[9] << 8 | o[10])
        try:
            p = 43
            p += 1 + o[p]                                    # session id
            cs = o[p] << 8 | o[p + 1]
            out["tls_n_ciphers"] = float(cs // 2)
            p += 2 + cs
            p += 1 + o[p]                                    # compression methods
            ext_end = p + 2 + (o[p] << 8 | o[p + 1])
            p += 2
            n_ext, sni = 0, 0
            while p + 4 <= min(ext_end, len(o)):
                et, el = o[p] << 8 | o[p + 1], o[p + 2] << 8 | o[p + 3]
                if et == 0 and p + 9 <= len(o):
                    sni = o[p + 7] << 8 | o[p + 8]
                n_ext += 1
                p += 4 + el
            out.update(tls_n_ext=float(n_ext), tls_sni_len=float(sni))
        except IndexError:
            out["tls_parse_error"] = 1.0
    if len(r) > 5 and r[0] == 0x16 and r[1] == 3 and r[5] == 2:
        out["tls_server_hello"] = 1.0
    return out


def ssh_meta(o: bytes, r: bytes) -> dict:
    for b in (o, r):
        if b.startswith(b"SSH-"):
            return {"ssh_banner": 1.0, "ssh_banner_len": float(len(b.split(b"\r\n")[0]))}
    return {}


def _stats(prefix, xs):
    if not xs:
        return {f"{prefix}_{s}": np.nan for s in ("mean", "std", "min", "max", "med", "p90")}
    a = np.asarray(xs, dtype=float)
    return {f"{prefix}_mean": a.mean(), f"{prefix}_std": a.std(), f"{prefix}_min": a.min(),
            f"{prefix}_max": a.max(), f"{prefix}_med": float(np.median(a)), f"{prefix}_p90": float(np.quantile(a, 0.9))}


def flow_features(acc: Acc, proto: str, resp_p, orig_p, service, first_n: int) -> dict:
    f = {}
    for d, dd in (("o", acc.o), ("r", acc.r)):
        f.update(_stats(f"{d}_size", dd.sizes))
        f.update(_stats(f"{d}_iat", dd.iats))
        for fl in ("syn", "fin", "rst", "psh", "ack", "urg"):
            f[f"{d}_{fl}"] = float(dd.flags[fl]) if proto == "tcp" else np.nan
        f[f"{d}_payload_pkt_frac"] = dd.pay_n / dd.n if dd.n else np.nan
        f[f"{d}_first_payload_len"] = float(len(dd.first_payload)) if dd.first_payload else 0.0
        f[f"{d}_first_payload_entropy"] = entropy(dd.first_payload)
    f["first_resp_delay"] = (acc.r.first_t - acc.o.first_t) if (acc.r.first_t and acc.o.first_t) else np.nan
    for i in range(first_n):
        f[f"first{i + 1}_signed_size"] = float(acc.first_n[i]) if i < len(acc.first_n) else np.nan
    o, r = acc.o.first_payload, acc.r.first_payload
    svc = str(service) if isinstance(service, str) else ""
    if proto in ("udp", "tcp") and (int(resp_p) in DNS_PORTS or "dns" in svc):
        f.update(dns_meta(o or r, proto == "tcp"))
        if r and "dns_rcode" not in f:
            f.update({k: v for k, v in dns_meta(r, proto == "tcp").items() if k.startswith("dns_r") or k in ("dns_ancount", "dns_min_ttl")})
    if proto == "tcp":
        f.update(http_meta(o, r))
        f.update(tls_meta(o, r))
        f.update(ssh_meta(o, r))
    f["zeek_service"] = svc or "none"
    f["b_ambiguous_pkts"] = float(acc.ambiguous)
    return f


def extract(pcap_path, flows: pd.DataFrame, tol: float, first_n: int):
    accs, st = parse_packets(pcap_path, flows, tol, first_n)
    t0 = time.perf_counter()
    rows = []
    for i, (p, rp, op, svc) in enumerate(zip(flows["proto"], flows["resp_p"], flows["orig_p"], flows["service"])):
        acc = accs.get(i)
        if acc is None:
            rows.append({"b_missing": 1.0, "zeek_service": str(svc) if isinstance(svc, str) else "none"})
        else:
            row = flow_features(acc, p, rp, op, svc, first_n)
            row["b_missing"] = 0.0
            rows.append(row)
    feats = pd.DataFrame(rows, index=flows.index)
    st["feature_seconds"] = round(time.perf_counter() - t0, 2)
    st["flows"] = len(flows)
    st["flows_with_packets"] = int((feats["b_missing"] == 0).sum())
    st["flows_ambiguous"] = int((feats.get("b_ambiguous_pkts", pd.Series(dtype=float)).fillna(0) > 0).sum())
    return feats, dict(st)
