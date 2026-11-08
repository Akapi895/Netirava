"""Corrected-label pilot: A0 recipe re-fitted on CNS2022-corrected labels (3 seeds),
compared with A0 v2 (original labels) on the same evaluation rows, under both
label versions. No HPO; LOIC-HTTP / DoS-Hulk holdouts are not read.

Pilot split (declared before fitting). Rows of the scoped web segments T5/K5:
  inside a CNS2022 web window (incl. startup): first 60% of the window -> train, rest -> eval
  outside every window: T5 -> train, K5 -> eval (as before)
Other train/known_replay/stress/replay segments keep their roles. Rows with
corrected status attempted / indeterminate are excluded from training and from
the corrected-label evaluation. Portscan (02-28) is not a known class: in the
corrected binary view it counts as attack.
"""

import json
import time

import numpy as np
import pandas as pd

from netirava import config as K
from netirava import features as F
from netirava.dataset import load_stream, load_truth, training_frame
from netirava.detectors import (A0, _StopAfterFirst, apply_smote, catboost_params, reference_recipe,
                                threshold_at_fpr, wilson)
from netirava.family import UNCERTAIN, render
from netirava.relabel import W

SPLIT = 0.6
WEB_WINDOWS = ("bf_start", "bf", "xss", "sqli_start", "sqli")
EXCLUDE = {"attempted", "indeterminate"}


def pilot_role(df):
    """Pilot role of every stream row (train / eval / other); see module docstring."""
    role = np.where(df.role == "train", "train", np.where(np.isin(df.role, ["known_replay", "stress", "replay"]), "eval", "other")).astype(object)
    t = df[F.TS_START].to_numpy(np.int64)
    web = df.segment.isin(["T5_0222_web_head", "K5_0222_web_tail"]).to_numpy()
    in_any = np.zeros(len(df), bool)
    for w in WEB_WINDOWS:
        a, b = W[w]
        m = web & (t >= a) & (t <= b)
        in_any |= m
        cut = a + SPLIT * (b - a)
        role[m & (t < cut)] = "train"
        role[m & (t >= cut)] = "eval"
    role[web & ~in_any & (df.segment == "T5_0222_web_head").to_numpy()] = "train"
    role[web & ~in_any & (df.segment == "K5_0222_web_tail").to_numpy()] = "eval"
    return role


def _frame(cfg):
    s = load_stream(cfg)
    ann = pd.read_parquet(K.path(cfg, "derived") / "truth_cns2022.parquet")
    d = s.merge(ann[["flow_id", "label_original", "label_corrected", "status"]], on="flow_id", validate="one_to_one")
    d = d[~d.role.isin(["holdout", "calibration"])].reset_index(drop=True)
    d["pilot_role"] = pilot_role(d)
    return d


def train_pilot(cfg, seeds=(0, 1, 2)):
    from catboost import CatBoostClassifier
    classes = list(cfg["a0"]["known_classes"])
    d = _frame(cfg)
    tr = d[(d.pilot_role == "train") & ~d.status.isin(EXCLUDE)]
    assert set(tr.label_corrected) <= set(classes), sorted(set(tr.label_corrected) - set(classes))
    y = tr.label_corrected.map({c: i for i, c in enumerate(classes)}).to_numpy(np.int64)
    X = F.matrix(tr)
    cal = training_frame(cfg, ["calibration"])
    Xc, cb = F.matrix(cal), cal[F.LABEL].to_numpy() == "Benign"
    out = {}
    for s in seeds:
        rec = reference_recipe(cfg)
        rec["seed"] = int(s)
        Xf, yf, sm = apply_smote(X, y, rec, classes)
        params = catboost_params(rec)
        if rec["device"] == "GPU" and rec.get("lr_rule") == "cpu_auto_probe":
            probe = CatBoostClassifier(**catboost_params(rec, device="CPU"))
            probe.fit(Xf, yf, callbacks=[_StopAfterFirst()])
            params["learning_rate"] = float(probe.get_all_params()["learning_rate"])
        m = CatBoostClassifier(**params)
        t0 = time.perf_counter()
        m.fit(Xf, yf)
        d_out = K.path(cfg, "models") / "pilot_cns" / f"s{s}"
        d_out.mkdir(parents=True, exist_ok=True)
        m.save_model(str(d_out / "a0.cbm"))
        thr, real = threshold_at_fpr(1 - m.predict_proba(Xc)[:, 0][cb], float(cfg["a0"]["target_fpr"]))
        meta = {"detector": "a0", "variant": "pilot_cns", "model_hash": K.sha1_file(d_out / "a0.cbm")[:12],
                "classes": classes, "threshold": {"value": thr, "realised_fpr_calibration": real},
                "train_counts_corrected": {c: int((y == i).sum()) for i, c in enumerate(classes)}, "smote": sm,
                "seed": int(s), "fit_seconds": time.perf_counter() - t0,
                "labels": "truth_cns2022.parquet (attempted/indeterminate excluded)", "split": f"CNS window first {SPLIT:.0%} -> train"}
        (d_out / "a0_meta.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        out[s] = {"model_hash": meta["model_hash"], "threshold": thr, "train_counts": meta["train_counts_corrected"]}
    return out


def _metrics(y, pred, alert, classes, rare, ent=None, t=None, cooldown=900_000):
    att = y != "Benign"
    out = {"per_class": {}}
    for c in classes:
        tt, pp = y == c, pred == c
        tp = int((tt & pp).sum())
        P_, R_ = (tp / pp.sum() if pp.sum() else 0.0), (tp / tt.sum() if tt.sum() else 0.0)
        out["per_class"][c] = {"support": int(tt.sum()), "precision": P_, "recall": R_, "f1": 2 * P_ * R_ / (P_ + R_) if P_ + R_ else 0.0,
                               "recall_wilson95": wilson(tp, int(tt.sum())) if tt.sum() else None}
    present = [c for c in classes if out["per_class"][c]["support"]]
    out["macro_f1_known_present"] = float(np.mean([out["per_class"][c]["f1"] for c in present]))
    rp = [c for c in rare if out["per_class"][c]["support"]]
    out["macro_f1_rare_present"] = float(np.mean([out["per_class"][c]["f1"] for c in rp])) if rp else None
    nb = int((~att).sum())
    out["benign"] = nb
    out["binary_fp"] = int((alert & ~att).sum())
    out["benign_fpr"] = out["binary_fp"] / nb if nb else None
    out["benign_fpr_wilson95"] = wilson(out["binary_fp"], nb) if nb else None
    out["attack_recall"] = float(alert[att].mean()) if att.any() else None
    out["multiclass_false_classification_of_alerted_attacks"] = float((pred[alert & att] != y[alert & att]).mean()) if (alert & att).any() else None
    if ent is not None:
        fp = alert & ~att
        o = np.lexsort((t[fp], ent[fp]))
        e, tt_ = ent[fp][o], t[fp][o]
        new = np.r_[True, (e[1:] != e[:-1]) | (np.diff(tt_) > cooldown)] if len(e) else np.array([], bool)
        hours = max(1, len(np.unique(t // 3_600_000)))
        out["false_incidents"] = int(new.sum())
        out["false_incidents_per_hour"] = float(new.sum() / hours)
    return out


def evaluate_pilot(cfg, taus=(0.6, 0.7, 0.8, 0.9)):
    classes = list(cfg["a0"]["known_classes"])
    rare = list(cfg["a0"]["rare_classes"])
    fams = {"Web": rare}
    d = _frame(cfg)
    ev = d[d.pilot_role == "eval"].reset_index(drop=True)
    X = F.matrix(ev)
    mdir = K.path(cfg, "models")
    models = {f"orig_s{s}": mdir / (f"a0" if s == 0 else f"a0_s{s}") for s in (0, 1, 2)}
    models.update({f"cns_s{s}": mdir / "pilot_cns" / f"s{s}" for s in (0, 1, 2)})
    groups = {"web_scoped": ev.segment.isin(["T5_0222_web_head", "K5_0222_web_tail"]).to_numpy(),
              "known_K1_K4": ev.segment.isin(["K1_0214_ftp_tail", "K2_0214_ssh_tail", "K3_0215_gold_tail", "K4_0215_slow_tail"]).to_numpy(),
              "S1_0228_infil": (ev.segment == "S1_0228_infil").to_numpy(), "R1_0302_bot": (ev.segment == "R1_0302_bot").to_numpy()}
    ent, t = ev[F.SRC].to_numpy(), ev.available_at.to_numpy(np.int64)
    rep = {"eval_rows": len(ev), "support": {}, "models": {}}
    keep_c = ~ev.status.isin(EXCLUDE).to_numpy()
    for gname, gm in groups.items():
        rep["support"][gname] = {"original": ev.label_original[gm].value_counts().to_dict(),
                                 "corrected_used": ev.label_corrected[gm & keep_c].value_counts().to_dict()}
    for name, path in models.items():
        m = A0.load(path)
        P, att_score, pr = m.score(X)
        pred = np.asarray(m.classes, dtype=object)[pr]
        alert = att_score >= m.threshold
        r = {"model_hash": m.version, "threshold": m.threshold, "groups": {}}
        for gname, gm in groups.items():
            r["groups"][gname] = {}
            for lv, ycol, mask in (("original_labels", "label_original", gm), ("corrected_labels", "label_corrected", gm & keep_c)):
                y = ev[ycol].to_numpy()[mask]
                # Portscan / Infilteration are attacks the model cannot name: binary only
                r["groups"][gname][lv] = _metrics(y, pred[mask], alert[mask], classes, rare, ent[mask], t[mask])
            if gname == "web_scoped":
                fa = {}
                for tau in taus:
                    for lv, ycol, mask in (("original_labels", "label_original", gm), ("corrected_labels", "label_corrected", gm & keep_c)):
                        y = ev[ycol].to_numpy()[mask]
                        lab = render(P[mask], m.classes, fams, tau)
                        in_fam_pred = np.isin(lab, rare) | (lab == UNCERTAIN.format(fam="Web"))
                        fine = np.isin(lab, rare)
                        yt_fam = np.isin(y, rare)
                        fa[f"{lv}@tau{tau}"] = {
                            "web_family_precision": float((in_fam_pred & yt_fam).sum() / max(in_fam_pred.sum(), 1)),
                            "web_family_recall": float((in_fam_pred & yt_fam).sum() / max(yt_fam.sum(), 1)),
                            "fine_label_rejection_rate": float((in_fam_pred & ~fine).sum() / max(in_fam_pred.sum(), 1)),
                            "fine_accuracy_when_emitted": float((lab[fine] == y[fine]).mean()) if fine.any() else None,
                            "fine_accuracy_argmax_on_same_family_preds": float((pred[mask][in_fam_pred] == y[in_fam_pred]).mean()) if in_fam_pred.any() else None,
                            "wrong_fine_labels_argmax": int((in_fam_pred & (pred[mask] != y) & yt_fam).sum()),
                            "wrong_fine_labels_family_aware": int((fine & (lab != y) & yt_fam).sum()),
                            "binary_alerts_unchanged": True}
                r["family_aware"] = fa
        rep["models"][name] = r
    out = K.path(cfg, "runs") / "pilot_cns_results.json"
    out.write_text(json.dumps(rep, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o)), encoding="utf-8")
    return rep
