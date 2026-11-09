"""Small blinded triage trial with reference answers (docs/protocols/clean_ablation.md §C).

make   -> <task>/cards_C0.md, cards_C1.md (blinded: IP tokens, no dates, no labels), verdicts_*.csv templates,
          answers.json (reference, written separately; read only by `score`), manifest.json (sha1 of answers)
run    -> interactive terminal session for a human reviewer: one card at a time, timed per decision
score  -> accuracy vs reference, attack types surfaced / confirmed, benign items opened, time per condition

C0 = score-ranked flow queue (no grouping): top-k alerted flows per segment by attack score.
C1 = Netirava source-incident queue: first k incidents per segment by (review time, severity rank), with the
     evidence available at review time.
"""

import datetime as dt
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from netirava import config as K
from netirava import features as F

STATS = [F.DPORT, "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS"]


def _stream(cfg, ids):
    return pq.read_table(K.path(cfg, "derived") / "stream.parquet", columns=["flow_id"] + STATS,
                         filters=[("flow_id", "in", list(map(int, ids)))]).to_pandas()


def _reference(cfg, flow_ids):
    """Reference label per flow: adapted label where the day was audited, original otherwise; excluded -> None."""
    from netirava.ops import labels
    lab = labels(cfg)
    ref = (lab["corrected"] if "corrected" in lab else lab["original"]).reindex(flow_ids)
    return ref


def make(cfg, run_id, out, k=4, seed=7):
    from netirava.triage import incident_table
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    meta, inc, det = incident_table(cfg, run_id)
    seg_start = det.groupby("segment").decision_at.min()
    rng = np.random.default_rng(seed)
    ips = pd.unique(pd.concat([det.entity, det.dst]))
    tok = dict(zip(rng.permutation(ips), [f"H{i:04d}" for i in range(len(ips))]))
    tax = cfg["labels"]["taxonomy"]
    items, answers, n = [], {}, {"C0": 0, "C1": 0}

    def rel(seg, t):
        return f"+{(t - seg_start[seg]) / 60000:.1f} min"

    # C0: score-ranked alerted flows
    for seg, g in det.groupby("segment"):
        top = g.sort_values(["a0_score", "decision_at"], ascending=[False, True], kind="stable").head(k)
        s = _stream(cfg, top.flow_id).set_index("flow_id")
        for _, r in top.iterrows():
            x = s.loc[r.flow_id]
            n["C0"] += 1
            iid = f"C0-{n['C0']:02d}"
            card = (f"### {iid}\n- segment window: {seg.split('_')[0]} · time {rel(seg, r.decision_at)}\n"
                    f"- flow: {tok[r.entity]} → {tok[r.dst]} · dst port {int(x[F.DPORT])} · proto {int(x.PROTOCOL)} · "
                    f"L7 {x.L7_PROTO} · in {int(x.IN_BYTES)} B / {int(x.IN_PKTS)} pkt · out {int(x.OUT_BYTES)} B / "
                    f"{int(x.OUT_PKTS)} pkt · {int(x.FLOW_DURATION_MILLISECONDS)} ms\n"
                    f"- detector: attack score {r.a0_score:.4f} · predicted class {r.a0_pred}\n")
            items.append({"item": iid, "cond": "C0", "segment": seg, "card": card})
            answers[iid] = {"segment": seg, "flow_ids": [int(r.flow_id)]}
    # C1: Netirava source incidents, evidence at review time
    for seg, g in inc.groupby("segment"):
        top = g.sort_values(["review_at", "queue_rank_severity"], kind="stable").head(k)
        for _, r in top.iterrows():
            f = det[(det.incident_id == r.incident_id) & (det.decision_at <= r.review_at)].sort_values("decision_at")
            s = _stream(cfg, f.flow_id).set_index("flow_id").loc[f.flow_id]
            ports = s[F.DPORT].value_counts().head(5)
            tgt = f.dst.map(tok).value_counts().head(3)
            ex = s.head(5)
            n["C1"] += 1
            iid = f"C1-{n['C1']:02d}"
            lines = [f"### {iid}",
                     f"- segment window: {seg.split('_')[0]} · opened {rel(seg, f.decision_at.min())} · reviewed {rel(seg, r.review_at)}",
                     f"- source {tok[r.entity]} · {len(f):,} alerted flows at review time · {f.dst.nunique()} targets "
                     f"(top: {', '.join(f'{a} ×{b}' for a, b in tgt.items())})",
                     f"- dst ports: {', '.join(f'{int(a)} ×{b}' for a, b in ports.items())} · protocols "
                     f"{', '.join(f'{int(a)} ×{b}' for a, b in s.PROTOCOL.value_counts().head(3).items())}",
                     f"- family-aware label: {r.fine_label} ({r.fine_label_status}) · severity at review {r.severity_at_review} · "
                     f"max attack score {f.a0_score.max():.4f}",
                     f"- median in/out bytes {int(s.IN_BYTES.median())} / {int(s.OUT_BYTES.median())} · median duration "
                     f"{int(s.FLOW_DURATION_MILLISECONDS.median())} ms",
                     "- first flows: " + "; ".join(f"port {int(x[F.DPORT])} in {int(x.IN_BYTES)}B/{int(x.IN_PKTS)}p out "
                                                    f"{int(x.OUT_BYTES)}B/{int(x.OUT_PKTS)}p {int(x.FLOW_DURATION_MILLISECONDS)}ms"
                                                    for _, x in ex.iterrows())]
            items.append({"item": iid, "cond": "C1", "segment": seg, "card": "\n".join(lines) + "\n"})
            answers[iid] = {"segment": seg, "flow_ids": f.flow_id.astype(int).tolist()}
    ref = _reference(cfg, sorted({i for a in answers.values() for i in a["flow_ids"]}))
    for iid, a in answers.items():
        labs = ref.reindex(a["flow_ids"])
        att = labs[labs.notna() & (labs != "Benign")]
        a.update(attack=bool(len(att)), n_attack_flows=int(len(att)), n_excluded=int(labs.isna().sum()),
                 attack_labels=att.value_counts().to_dict(),
                 family=(tax.get(att.value_counts().index[0], att.value_counts().index[0]) if len(att) else None))
        del a["flow_ids"]
    intro = ("Decide for each card: is this an attack (true positive) or benign (false positive)? "
             "Optionally name the attack family (BruteForce, DoS, DDoS, Web, Bot, Infiltration, Portscan, Unknown).\n"
             "IP addresses are replaced by tokens; times are relative to the start of the segment window.\n\n")
    for c in ("C0", "C1"):
        (out / f"cards_{c}.md").write_text(f"# Condition {c}\n\n" + intro +
                                           "\n".join(i["card"] for i in items if i["cond"] == c), encoding="utf-8")
        pd.DataFrame({"item": [i["item"] for i in items if i["cond"] == c], "verdict": "", "family": "",
                      "note": ""}).to_csv(out / f"verdicts_{c}.csv", index=False)
    (out / "answers.json").write_text(json.dumps(answers, indent=1), encoding="utf-8")
    man = {"run_id": run_id, "config": cfg["_path"], "model": meta["a0"]["model_dir"], "k_per_segment": k, "seed": seed,
           "items": {c: sum(i["cond"] == c for i in items) for c in ("C0", "C1")},
           "answers_sha1": hashlib.sha1((out / "answers.json").read_bytes()).hexdigest(),
           "created_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
    (out / "manifest.json").write_text(json.dumps(man, indent=1), encoding="utf-8")
    return man


def run_interactive(task, cond, reviewer):
    """Human session: shows one card at a time and records verdict and seconds per decision."""
    task = Path(task)
    text = (task / f"cards_{cond}.md").read_text(encoding="utf-8").split("\n### ")[1:]
    rows = []
    for card in text:
        print("\n### " + card)
        t0 = dt.datetime.now(dt.timezone.utc)
        v = ""
        while v not in ("tp", "fp"):
            v = input("verdict [tp/fp]: ").strip().lower()
        fam = input("family (optional): ").strip()
        t1 = dt.datetime.now(dt.timezone.utc)
        rows.append({"item": card.split("\n")[0].strip(), "verdict": v, "family": fam, "reviewer": reviewer,
                     "started_utc": t0.isoformat(), "finished_utc": t1.isoformat(), "seconds": (t1 - t0).total_seconds()})
    pd.DataFrame(rows).to_csv(task / f"verdicts_{cond}_{reviewer}.csv", index=False)
    return len(rows)


def score(task, verdict_files):
    task = Path(task)
    ans = json.loads((task / "answers.json").read_text(encoding="utf-8"))
    man = json.loads((task / "manifest.json").read_text(encoding="utf-8"))
    assert hashlib.sha1((task / "answers.json").read_bytes()).hexdigest() == man["answers_sha1"], "answers changed"
    out = {}
    for vf in verdict_files:
        v = pd.read_csv(task / vf)
        cond = v["item"].iloc[0].split("-")[0]
        v["ref_attack"] = v["item"].map(lambda i: ans[i]["attack"])
        v["ref_family"] = v["item"].map(lambda i: ans[i]["family"])
        v["said_attack"] = v.verdict.str.lower().isin(["tp", "true_positive", "attack"])
        v["correct"] = v.said_attack == v.ref_attack
        types_seen = {f"{ans[i]['segment']}|{l}" for i in v["item"] for l in ans[i]["attack_labels"]}
        types_conf = {f"{ans[i]['segment']}|{l}" for i, s in zip(v["item"], v.said_attack) if s for l in ans[i]["attack_labels"]}
        r = {"items": int(len(v)), "accuracy": float(v.correct.mean()),
             "attack_items": int(v.ref_attack.sum()), "benign_items_opened": int((~v.ref_attack).sum()),
             "true_positive_verdicts": int((v.said_attack & v.ref_attack).sum()),
             "false_alarm_verdicts": int((v.said_attack & ~v.ref_attack).sum()),
             "missed_attack_verdicts": int((~v.said_attack & v.ref_attack).sum()),
             "attack_types_surfaced": sorted(types_seen), "attack_types_confirmed": sorted(types_conf),
             "family_correct_on_true_attacks": (float((v.family.fillna("").str.lower() == v.ref_family.fillna("").str.lower())[v.ref_attack].mean())
                                                if v.ref_attack.any() else None),
             "attack_flows_in_reviewed_items": int(sum(ans[i]["n_attack_flows"] for i in v["item"]))}
        if "seconds" in v:
            r["seconds_total"] = float(v.seconds.sum())
            r["seconds_median_per_item"] = float(v.seconds.median())
        out[f"{cond}:{vf}"] = r
    (task / "SCORE.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return out
