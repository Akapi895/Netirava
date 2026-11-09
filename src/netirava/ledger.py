"""Unified evidence ledger for the final system and its baseline (docs/cic_evidence.md).

One tuple per model: model dir + hash, locked threshold (alpha 0.1% on C1 benign), stored replay runs.
Every row = (model, cohort) with: label policy, support (benign / attack by label / excluded /
not audited), benign FPR + Wilson, recall by label, source incidents and false source incidents
(counts) and the configured exposure, computed twice: on the raw stream (as replayed) and after
exact-duplicate removal (fe.drop_exact_duplicates; incidents regrouped with the same rule).
Labels: CNS2022-adapted where the day was audited, original NF-v3 elsewhere; attempted /
indeterminate rows are excluded from both attack and benign. K5 keeps only the pilot's eval rows
(the pilot trained on the first 60% of each CNS2022 web window inside K5). No model is re-run.
"""

import json

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, window_bounds
from netirava.decision import incidents
from netirava.detectors import wilson
from netirava.fe import EXACT_KEY
from netirava.storage import RunStore

SYSTEMS = {
    "final: pilot_cns/s0": {"dev": ("configs/demo.yaml", "20261108T190143_a0_fast"),
                            "ho": ("configs/ops_holdout.yaml", "20261108T211057_a0_fast")},
    "baseline: A0 v2": {"dev": ("configs/demo.yaml", "20261108T190136_a0_fast"),
                        "ho": ("configs/ops_holdout.yaml", "20261108T211051_a0_fast")},
}
COHORTS = {"dev": {"K1-K4 known tails (within-episode)": ["K1_0214_ftp_tail", "K2_0214_ssh_tail", "K3_0215_gold_tail", "K4_0215_slow_tail"],
                   "K5 web, pilot-eval rows only (within-episode)": ["K5_0222_web_tail"],
                   "S1 28/02 (dev, seen)": ["S1_0228_infil"], "R1 02/03 (dev, seen)": ["R1_0302_bot"]},
           "ho": {"H5 HOIC 21/02": ["H5_0221_hoic"], "H6 01/03": ["H6_0301_infil"], "H7 benign 16/02": ["H7_0216_benign"],
                  "H8 benign 20/02": ["H8_0220_benign"], "H9 28/02 19:00": ["H9_0228_late"],
                  "H5-H9 pooled (post-selection)": ["H5_0221_hoic", "H6_0301_infil", "H7_0216_benign", "H8_0220_benign", "H9_0228_late"]}}
RARE = ["Brute_Force_-Web", "Brute_Force_-XSS", "SQL_Injection"]


def _frame(cfg, run_id):
    from netirava.pilot import pilot_role
    st = RunStore(cfg, run_id)
    meta = st.meta()
    p_cols = [f"p_{c}" for c in meta["a0"]["classes"]]
    det = st.detections(columns=["flow_id", "segment", "entity", "decision_at", "a0_score", "a0_candidate", "a0_pred"] + p_cols)
    s = load_stream(cfg, segments=sorted(det.segment.unique()))
    s = s[["flow_id", "role", "segment", F.TS_START] + [c for c in EXACT_KEY if c != F.TS_START]]
    order = s.sort_values("flow_id")
    s["dup"] = order.duplicated(EXACT_KEY, keep="first").reindex(s.index)
    s["pilot_role"] = "n/a"
    k5 = s.segment == "K5_0222_web_tail"
    if k5.any():
        s.loc[k5, "pilot_role"] = pilot_role(s[k5])
    d = det.merge(s[["flow_id", "dup", "pilot_role"]], on="flow_id", validate="one_to_one")
    ann_p = K.path(cfg, "derived") / "truth_cns2022.parquet"
    ann = pd.read_parquet(ann_p, columns=["flow_id", "label_original", "label_corrected", "status"])
    d = d.merge(ann, on="flow_id", validate="one_to_one")
    d["y"] = d.label_corrected.where(~d.status.isin(["attempted", "indeterminate"]))
    return meta, d


def _metrics(g, cfg, segs):
    wb = {w["id"]: w for w in window_bounds(cfg)}
    exposure = sum((wb[s]["end_ms"] - wb[s]["start_ms"]) / 3_600_000 for s in segs)
    lab = g[g.y.notna()]
    ben = lab.y == "Benign"
    fp, nb = int((lab.a0_candidate & ben).sum()), int(ben.sum())
    att = lab[~ben]
    r = {"n_flows": int(len(g)), "excluded_attempted_indeterminate": int(g.y.isna().sum()),
         "not_audited": int((g.status == "not_audited").sum()), "n_benign": nb, "fp": fp,
         "benign_fpr": fp / nb if nb else None, "benign_fpr_wilson95": wilson(fp, nb) if nb else None,
         "attack_support": att.y.value_counts().to_dict(),
         "recall_by_label": {k: float(x.a0_candidate.mean()) for k, x in att.groupby("y")},
         "recall_wilson95_by_label": {k: wilson(int(x.a0_candidate.sum()), len(x)) for k, x in att.groupby("y")},
         "exposure_hours": exposure}
    gg = g.reset_index(drop=True)
    inc = incidents(gg, gg.a0_candidate.to_numpy(), 900_000)
    a = gg.assign(inc=inc)[inc >= 0]
    is_att = a.y.notna() & (a.y != "Benign")
    has_att = is_att.groupby(a.inc).any()
    has_ben = (a.y == "Benign").groupby(a.inc).any()
    r["source_incidents"] = int(len(has_att))
    r["false_source_incidents"] = int((~has_att & has_ben).sum())
    r["false_source_incidents_per_exposure_hour"] = r["false_source_incidents"] / exposure if exposure else None
    return r


def per_class(g, classes):
    lab = g[g.y.notna()]
    pred = np.asarray(classes, dtype=object)[lab[[f"p_{c}" for c in classes]].to_numpy().argmax(1)]
    out = {}
    for c in classes:
        t, p = (lab.y == c).to_numpy(), pred == c
        n = int(t.sum())
        if not n:
            continue
        tp = int((t & p).sum())
        P_, R_ = (tp / p.sum() if p.sum() else 0.0), tp / n
        out[c] = {"support": n, "precision": float(P_), "recall": float(R_), "f1": float(2 * P_ * R_ / (P_ + R_)) if P_ + R_ else 0.0,
                  "recall_wilson95": wilson(tp, n), "inconclusive_n_lt_30": n < 30}
    return out


def build():
    out = {"definition": __doc__.strip(), "systems": {}}
    for name, runs in SYSTEMS.items():
        sysr = {"cohorts": {}}
        for part, (cfgp, rid) in runs.items():
            cfg = K.load(cfgp)
            meta, d = _frame(cfg, rid)
            sysr.setdefault("model", {"model_dir": meta["a0"]["model_dir"], "model_hash": meta["a0"]["model_hash"],
                                      "threshold": meta["a0"]["threshold"], "alpha": 0.001})
            sysr[f"run_{part}"] = {"run_id": rid, "config": cfgp, "stream_sha1": meta["stream_sha1"],
                                   "active_decisions_sha1": meta["active_decisions_sha1"]}
            for cname, segs in COHORTS[part].items():
                g = d[d.segment.isin(segs)]
                if cname.startswith("K5"):
                    g = g[g.pilot_role == "eval"]
                row = {"segments": segs, "raw": _metrics(g, cfg, segs), "dedup": _metrics(g[~g.dup], cfg, segs),
                       "exact_duplicates": int(g.dup.sum())}
                if cname.startswith(("K1", "K5")):
                    row["per_class_raw"] = per_class(g, meta["a0"]["classes"])
                    row["per_class_dedup"] = per_class(g[~g.dup], meta["a0"]["classes"])
                sysr["cohorts"][cname] = row
        out["systems"][name] = sysr
    res = K.path(K.load("configs/demo.yaml"), "runs") / "final_evidence"
    res.mkdir(parents=True, exist_ok=True)
    (res / "LEDGER.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    return out


def markdown(led):
    f = lambda x, n=3: "–" if x is None else f"{x:.{n}f}"
    pct = lambda x: "–" if x is None else f"{100 * x:.3f}%"
    ci = lambda w: "" if not w or w[0] is None else f" [{100 * w[0]:.3f}, {100 * w[1]:.3f}]"
    L = ["| System | Cohort | Benign n | FP | Benign FPR [Wilson 95%] | Attack support | Recall by label | Source incidents (false) | Exposure h | Excluded / not audited |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for sname, s in led["systems"].items():
        for cname, c in s["cohorts"].items():
            for kind in ("raw", "dedup"):
                m = c[kind]
                rec = ", ".join(f"{k} {f(v)}" for k, v in m["recall_by_label"].items()) or "–"
                sup = ", ".join(f"{k} {v:,}" for k, v in m["attack_support"].items()) or "–"
                L.append(f"| {sname} | {cname} ({kind}) | {m['n_benign']:,} | {m['fp']:,} | {pct(m['benign_fpr'])}{ci(m['benign_fpr_wilson95'])} | "
                         f"{sup} | {rec} | {m['source_incidents']} ({m['false_source_incidents']}) | {f(m['exposure_hours'], 2)} | "
                         f"{m['excluded_attempted_indeterminate']:,} / {m['not_audited']:,} |")
    P = ["| System | Cohort | Class | Support | Precision | Recall [Wilson 95%] | F1 | n < 30 |", "|---|---|---|---|---|---|---|---|"]
    for sname, s in led["systems"].items():
        for cname, c in s["cohorts"].items():
            for cls, m in c.get("per_class_dedup", {}).items():
                w = m["recall_wilson95"]
                P.append(f"| {sname} | {cname} | {cls} | {m['support']:,} | {f(m['precision'])} | {f(m['recall'])} [{f(w[0])}, {f(w[1])}] | "
                         f"{f(m['f1'])} | {'INCONCLUSIVE' if m['inconclusive_n_lt_30'] else ''} |")
    return "\n".join(L), "\n".join(P)
