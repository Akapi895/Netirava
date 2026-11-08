"""Corrected labels for NF-CSE-CIC-IDS2018-v3 after Engelen et al., IEEE CNS 2022
(https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html).

The original labels (truth.parquet) are never modified. This writes
truth_cns2022.parquet with, per flow: label_original, label_corrected,
status, confidence, rule. Audited days: 2018-02-22 (web), 2018-02-28
(infiltration / portscan), 2018-03-02 (bot); rows of other days are
"not_audited" and keep their label.

Statuses
  unchanged      audited, no rule applies, original label kept
  confirmed      label set by a CNS2022 attack rule (IP pair + time window [+ ports])
  attempted      CNS2022 "Attempted" (startup / zero-payload / short flows): excluded from train/eval
  background     CNS2022 notes the pattern is not attack traffic (UDP/500, DHCP to the victim) -> Benign
  indeterminate  attack-labelled in NF-v3 but no CNS2022 rule supports or rejects it: excluded
  not_audited    day outside the audit
Approximation (declared): NetFlow has no payload length, so "zero forward payload"
is approximated by IN_PKTS <= 3 and IN_BYTES <= 180 (handshake/teardown only).
"""

import json

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, load_truth

UTC = lambda s: int(pd.Timestamp(s, tz="UTC").value // 1_000_000)
WEB_ATT, WEB_VIC = "18.218.115.60", "172.31.69.28"
WEB = {"Brute_Force_-Web", "Brute_Force_-XSS", "SQL_Injection"}
W = {  # CNS2022 windows, UTC
    "bf_start": (UTC("2018-02-22 14:13:44.965705"), UTC("2018-02-22 14:15:47.920399")),
    "bf": (UTC("2018-02-22 14:17:51.336902"), UTC("2018-02-22 15:23:59.858533")),
    "xss": (UTC("2018-02-22 17:51:39.783923"), UTC("2018-02-22 18:29:41.827037")),
    "sqli_start": (UTC("2018-02-22 20:14:30.169342"), UTC("2018-02-22 20:14:58.599986")),
    "sqli": (UTC("2018-02-22 20:16:30.418906"), UTC("2018-02-22 20:27:56.022793")),
    "scan": (UTC("2018-02-28 14:46:22"), UTC("2018-02-28 18:39:00.746247")),
    "c2_1": (UTC("2018-02-28 14:45:40"), UTC("2018-02-28 16:08:55")),
    "c2_2": (UTC("2018-02-28 17:43:59"), UTC("2018-02-28 18:40:00")),
    "bot": (UTC("2018-03-02 14:13:28"), UTC("2018-03-02 19:54:52")),
}
DAYS = {"2018-02-22", "2018-02-28", "2018-03-02"}


def _in(t, w):
    return (t >= W[w][0]) & (t <= W[w][1])


def relabel(df):
    """df: stream rows (identifiers + features) with column label_original. Returns the annotation frame."""
    t = df[F.TS_START].to_numpy(np.int64)
    src, dst = df[F.SRC].to_numpy(), df[F.DST].to_numpy()
    proto, dport, sport = df.PROTOCOL.to_numpy(), df[F.DPORT].to_numpy(), df[F.SPORT].to_numpy()
    inp, inb = df.IN_PKTS.to_numpy(), df.IN_BYTES.to_numpy()
    orig = df.label_original.to_numpy().astype(object)
    day = pd.to_datetime(t, unit="ms", utc=True).strftime("%Y-%m-%d").to_numpy()
    lab = orig.copy()
    status = np.where(np.isin(day, list(DAYS)), "unchanged", "not_audited").astype(object)
    conf = np.where(status == "unchanged", "high", "n/a").astype(object)
    rule = np.full(len(df), "", dtype=object)
    zero_pl = (inp <= 3) & (inb <= 180)

    def setv(m, l, s, c, r):
        lab[m], status[m], conf[m], rule[m] = l, s, c, r

    # ---------------- web, 02-22
    d22 = day == "2018-02-22"
    pair = d22 & (((src == WEB_ATT) & (dst == WEB_VIC)) | ((src == WEB_VIC) & (dst == WEB_ATT)))
    webl = d22 & np.isin(orig, list(WEB))
    # attack-labelled web flows outside the attacker pair: background vs indeterminate
    bg = webl & ~pair & (proto == 17) & np.isin(dport, [500, 67, 68])
    setv(bg, "Benign", "background", "medium", "CNS2022: UDP/500 and DHCP to the victim are not attack traffic")
    setv(webl & ~pair & ~bg, "Indeterminate", "indeterminate", "low",
         "web-labelled, not the CNS2022 attacker pair; no rule supports or rejects it")
    # attacker pair: label by window
    setv(pair, "Indeterminate", "indeterminate", "low", "attacker pair outside every CNS2022 web window")
    m = pair & _in(t, "bf_start"); setv(m, "Attempted", "attempted", "high", "CNS2022 BF startup (Attempted cat 2)")
    m = pair & _in(t, "bf")
    setv(m & (inp > 20), "Brute_Force_-Web", "confirmed", "medium", "CNS2022 BF: >20 forward packets")
    setv(m & (inp <= 20), "Attempted", "attempted", "medium", "CNS2022 BF: <=20 forward packets (Attempted cat 5/0)")
    m = pair & _in(t, "xss")
    setv(m, "Brute_Force_-XSS", "confirmed", "medium", "CNS2022 XSS window")
    setv(m & (zero_pl | np.isin(sport, [63782, 64144])), "Attempted", "attempted", "medium",
         "CNS2022 XSS: zero payload or page-load ports 63782/64144")
    m = pair & _in(t, "sqli_start"); setv(m, "Attempted", "attempted", "high", "CNS2022 SQLi startup (Attempted cat 2)")
    m = pair & _in(t, "sqli")
    setv(m, "SQL_Injection", "confirmed", "medium", "CNS2022 SQLi window")
    setv(m & zero_pl, "Attempted", "attempted", "medium", "CNS2022 SQLi: zero payload")
    setv(m & np.isin(sport, [64438, 64074, 56742]), "Indeterminate", "indeterminate", "medium",
         "CNS2022: last SQLi-window flows belong to other web attacks")
    # ---------------- infiltration / portscan, 02-28
    d28 = day == "2018-02-28"
    scan = d28 & (src == "172.31.69.24") & pd.Series(dst).str.startswith("172.31.").to_numpy() & _in(t, "scan") & (sport != 68)
    setv(scan & (dst == "172.31.69.15"), "Portscan", "confirmed", "high", "CNS2022 NMAP portscan by .24 (named target .15)")
    setv(scan & (dst != "172.31.69.15"), "Portscan", "confirmed", "medium",
         "CNS2022 NMAP portscan by .24 (internal target; full 21-host list not verified)")
    c2 = d28 & (((src == "172.31.69.24") & (dst == "13.58.225.34")) | ((dst == "172.31.69.24") & (src == "13.58.225.34"))) \
        & (_in(t, "c2_1") | _in(t, "c2_2"))
    setv(c2, "Infilteration", "confirmed", "high", "CNS2022 victim <-> attacker communication")
    setv(c2 & zero_pl, "Attempted", "attempted", "medium", "CNS2022 C2: zero payload")
    inf_other = d28 & (orig == "Infilteration") & ~scan & ~c2
    setv(inf_other, "Indeterminate", "indeterminate", "low", "NF-v3 Infilteration label not supported by a CNS2022 rule")
    # ---------------- bot, 02-03
    d02 = day == "2018-03-02"
    botr = d02 & ((src == "18.219.211.138") | (dst == "18.219.211.138")) & _in(t, "bot")
    setv(botr, "Bot", "confirmed", "high", "CNS2022 Ares botnet (18.219.211.138)")
    setv(d02 & (orig == "Bot") & ~botr, "Indeterminate", "indeterminate", "low",
         "NF-v3 Bot label without the CNS2022 C2 host")
    # ---------------- ARP artefacts
    arp = np.isin(day, list(DAYS)) & np.isin(src, ["8.6.0.1", "8.6.0.4"]) & np.isin(dst, ["8.6.0.1", "8.6.0.4"]) & (orig != "Benign")
    setv(arp, "Benign", "background", "high", "CNS2022: ARP artefacts misparsed as IP flows")
    # rows whose rule result equals the original label are not "changes"
    changed = lab != orig
    return pd.DataFrame({"flow_id": df.flow_id.to_numpy(), "label_original": orig, "label_corrected": lab,
                         "status": status, "confidence": conf, "rule": rule, "changed": changed})


def build(cfg):
    s = load_stream(cfg)
    t = load_truth(cfg)[["flow_id", F.LABEL]].rename(columns={F.LABEL: "label_original"})
    df = s.merge(t, on="flow_id", validate="one_to_one")
    ann = relabel(df)
    ann["segment"] = df.segment.to_numpy()
    out = K.path(cfg, "derived") / "truth_cns2022.parquet"
    ann.to_parquet(out, index=False)
    summ = {"rows": len(ann), "changed": int(ann.changed.sum()),
            "by_status": ann.status.value_counts().to_dict(),
            "transitions": ann[ann.changed].groupby(["label_original", "label_corrected"]).size().rename("n").reset_index().to_dict("records"),
            "support_corrected_by_segment": {s: g.label_corrected.value_counts().to_dict()
                                             for s, g in ann[ann.status != "not_audited"].groupby("segment")},
            "source": "Engelen et al., IEEE CNS 2022, CSE-CIC-IDS2018 corrected labelling rules",
            "sha1": K.sha1_file(out)}
    (K.path(cfg, "derived") / "truth_cns2022.summary.json").write_text(json.dumps(summ, indent=2, default=str), encoding="utf-8")
    return summ
