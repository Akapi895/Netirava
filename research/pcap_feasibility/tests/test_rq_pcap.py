import socket
import struct
import sys
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import evaluate as E  # noqa: E402
import extract as X  # noqa: E402
import features as F  # noqa: E402
from zeeklog import read_conn_labeled  # noqa: E402

HDR = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
       "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
       "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]



def sep_join(parts, sep):
    return ("\t" if sep == "tab" else "   ").join(parts)


@pytest.mark.parametrize("sep", ["tab", "space"])
def test_conn_log_parser_handles_both_tail_separators(tmp_path, sep):
    tail_h = ["tunnel_parents", "label", "detailed-label"]
    lines = ["#separator \\x09", "#fields\t" + "\t".join(HDR) + "\t" + sep_join(tail_h, sep)]
    base = ["1.0", "C1", "10.0.0.1", "1234", "10.0.0.2", "80", "tcp", "-", "0.5", "10", "20", "SF", "-", "-",
            "0", "ShAD", "3", "100", "2", "90"]
    lines.append("\t".join(base) + "\t" + sep_join(["-", "Malicious", "C&C"], sep))
    lines.append("\t".join(base) + "\t" + sep_join(["(empty)", "Benign", "-"], sep))
    p = tmp_path / "conn.log.labeled"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    df = read_conn_labeled(p)
    assert list(df["is_malicious"]) == [1, 0]
    assert list(df["detailed_label"]) == ["C&C", "Benign"]
    assert df["orig_h"].iloc[0] == "10.0.0.1" and df["resp_p"].iloc[0] == 80


def _pkt(src, dst, sport, dport, flags=dpkt.tcp.TH_ACK, payload=b"", proto="tcp", ip_id=1, mf=0):
    if proto == "tcp":
        l4 = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
        p = dpkt.ip.IP_PROTO_TCP
    else:
        l4 = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        l4.ulen = 8 + len(payload)
        p = dpkt.ip.IP_PROTO_UDP
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=p, data=l4, id=ip_id, mf=mf)
    ip.len = 20 + len(bytes(l4))
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _write(path, pkts):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, b in pkts:
            w.writepkt(b, ts=ts)


def _flows(rows):
    return pd.DataFrame(rows, columns=["ts", "proto", "orig_h", "orig_p", "resp_h", "resp_p", "duration", "service"])


def test_join_direction_time_disambiguation_and_missing_flows(tmp_path):
    a, b = "10.0.0.1", "10.0.0.2"
    flows = _flows([[100.0, "tcp", a, 1111, b, 80, 1.0, np.nan],     # flow 0
                    [200.0, "tcp", a, 1111, b, 80, 1.0, np.nan],     # flow 1: same 5-tuple, later
                    [300.0, "tcp", a, 2222, b, 443, 1.0, np.nan]])   # flow 2: no packets in pcap
    pkts = [(100.0, _pkt(a, b, 1111, 80, dpkt.tcp.TH_SYN)),
            (100.1, _pkt(b, a, 80, 1111, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)),
            (100.2, _pkt(a, b, 1111, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"GET /x HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n")),
            (200.0, _pkt(a, b, 1111, 80, dpkt.tcp.TH_SYN)),
            (999.0, _pkt(a, b, 1111, 80, dpkt.tcp.TH_SYN))]  # outside every flow window -> unassigned
    _write(tmp_path / "t.pcap", pkts)
    feats, st = X.extract(tmp_path / "t.pcap", flows, tol=1.0, first_n=5)
    assert len(feats) == 3                                   # no flow silently dropped
    assert list(feats["b_missing"]) == [0.0, 0.0, 1.0]
    assert feats.loc[0, "o_syn"] == 1 and feats.loc[0, "r_syn"] == 1 and feats.loc[0, "o_psh"] == 1
    assert feats.loc[1, "o_syn"] == 1 and np.isnan(feats.loc[1, "r_size_mean"])
    assert feats.loc[0, "first1_signed_size"] > 0 and feats.loc[0, "first2_signed_size"] < 0
    assert feats.loc[0, "http_method"] == "GET" and feats.loc[0, "http_host_is_ip"] == 1.0
    assert st["unassigned_tcp"] == 1 and st["flows_with_packets"] == 2


def test_non_first_fragments_attach_to_first_fragment_flow(tmp_path):
    a, b = "10.0.0.1", "10.0.0.9"
    flows = _flows([[10.0, "udp", a, 5000, b, 80, 0.5, np.nan]])
    first = _pkt(a, b, 5000, 80, proto="udp", payload=b"x" * 40, ip_id=77, mf=1)
    ip = dpkt.ip.IP(src=socket.inet_aton(a), dst=socket.inet_aton(b), p=dpkt.ip.IP_PROTO_UDP, id=77, offset=6,
                    data=b"y" * 48)
    ip.len = 20 + 48
    frag = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
    _write(tmp_path / "f.pcap", [(10.0, first), (10.001, frag)])
    feats, st = X.extract(tmp_path / "f.pcap", flows, tol=1.0, first_n=5)
    assert st["fragments_attached"] == 1 and feats.loc[0, "o_size_max"] == 68


def test_protocol_parsers():
    q = dpkt.dns.DNS(id=1, qd=[dpkt.dns.DNS.Q(name="abc123.example.com", type=dpkt.dns.DNS_A)])
    m = X.dns_meta(bytes(q), tcp=False)
    assert m["dns_qname_len"] == len("abc123.example.com") and m["dns_qname_labels"] == 3
    hello = bytearray(b"\x16\x03\x01\x00\x00\x01\x00\x00\x00\x03\x03" + b"\x00" * 32)
    hello += b"\x00" + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00"
    sni = b"\x00\x00" + struct.pack(">H", 14) + struct.pack(">H", 12) + b"\x00" + struct.pack(">H", 9) + b"a.example"
    hello += struct.pack(">H", len(sni)) + sni
    t = X.tls_meta(bytes(hello), b"")
    assert t["tls_client_hello"] == 1.0 and t["tls_n_ciphers"] == 2 and t["tls_sni_len"] == 9 and t["tls_n_ext"] == 1
    assert X.ssh_meta(b"SSH-2.0-dropbear\r\n", b"")["ssh_banner"] == 1.0
    assert X.http_meta(b"", b"HTTP/1.1 404 Not Found\r\n\r\n")["http_status"] == 404.0


def _frame(n=40):
    rng = np.random.default_rng(0)
    d = {c: rng.random(n) for c in F.A_NUM}
    d.update(proto=["tcp"] * n, conn_state=["SF"] * n, o_size_mean=rng.random(n), r_syn=rng.random(n),
             dns_qtype=["1"] * n, zeek_service=["dns"] * n, orig_h=["10.0.0.1"] * n, ts=np.arange(n, dtype=float),
             b_ambiguous_pkts=0.0, b_missing=0.0, capture_id="c", is_malicious=rng.integers(0, 2, n),
             detailed_label="x", label="Benign", uid="u", service="dns")
    return pd.DataFrame(d)


def test_feature_sets_have_no_identifiers_labels_or_join_artefacts():
    df = _frame()
    a, _ = F.feature_set(df, "A")
    b, bc = F.feature_set(df, "B")
    c, _ = F.feature_set(df, "C")
    for cols in (a, b, c):
        assert not F.FORBIDDEN.intersection(cols)
    assert set(c) == set(a) | set(b) and not set(a) & set(b)
    assert {"dns_qtype", "zeek_service"} <= set(bc)


def test_controls_keep_shape_and_marginals():
    df = _frame()
    cols, cats = F.feature_set(df, "C")
    Xm = F.matrix(df, cols, cats)
    block = F.feature_set(df, "B")[0]
    P = F.permute_block(Xm, block, 0)
    assert P.shape == Xm.shape and sorted(P["o_size_mean"]) == sorted(Xm["o_size_mean"])
    assert (P[F.A_NUM].to_numpy() == Xm[F.A_NUM].to_numpy()).all()
    N = F.add_noise(Xm[F.feature_set(df, "A")[0]], len(block), 0)
    assert N.shape[1] == len(F.A_NUM) + len(F.A_CAT) + len(block)


def test_threshold_respects_target_fpr_on_calibration():
    s = np.linspace(0, 1, 1000)
    for fpr in (0.001, 0.01):
        thr = E.threshold_at_fpr(s, fpr)
        assert (s > thr).mean() <= fpr


def test_incidents_cooldown_and_false_incidents():
    df = pd.DataFrame({"ts": [0, 100, 2000, 2100], "orig_h": ["h"] * 4, "is_malicious": [0, 0, 1, 0]})
    out = E.incidents(df, np.array([True, True, True, True]), cooldown=900)
    assert out == {"incidents": 2, "false_incidents": 1}
