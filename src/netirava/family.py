"""Family-aware labelling: the single implementation used by replay, export,
evaluation and the triage UI.

Contract (see docs/FAMILY_AWARE_FINAL_REPORT.md):
- The probability vector is never modified, so p(Benign), every family mass
  and the binary alert (attack_score = 1 - p(Benign) vs the locked threshold)
  are unchanged. Family-aware never turns Benign into Attack or vice versa.
- Only flows whose argmax class belongs to a configured ambiguous family
  (cfg family.ambiguous, e.g. Web = Brute_Force_-Web/XSS/SQLi) can lose their
  fine label: it is kept if its share of the family mass >= tau, otherwise
  fine_label = "<family> attack — fine class uncertain".
- Every other flow keeps its argmax class as fine label (status "fine"), or
  "benign" when the argmax is Benign.

Per flow it returns: predicted_family, fine_label, fine_label_status
(fine | uncertain | benign), fine_confidence (share of the argmax class in its
family mass; 1.0 outside ambiguous families), family_mass, uncertainty_reason.
"""

import numpy as np
import pandas as pd

BENIGN = "Benign"
UNCERTAIN = "{fam} attack — fine class uncertain"
FIELDS = ["predicted_family", "fine_label", "fine_label_status", "fine_confidence", "family_mass", "uncertainty_reason"]


def settings(cfg):
    """(families: {name: [classes]}, taxonomy: {class: family}, tau) from the config."""
    fc = cfg.get("family", {})
    fams = {k: list(v) for k, v in fc.get("ambiguous", {}).items()}
    tax = dict(cfg.get("labels", {}).get("taxonomy", {}))
    return fams, tax, float(fc.get("tau", 0.8))


def annotate(P, classes, families, taxonomy, tau):
    """Family-aware fields for a probability matrix P (n x len(classes)). Does not modify P."""
    classes = list(classes)
    n = len(P)
    am = P.argmax(1)
    am_lab = np.asarray(classes, dtype=object)[am]
    fam = np.array([taxonomy.get(c, c) for c in am_lab], dtype=object)
    fine = am_lab.copy()
    status = np.where(am_lab == BENIGN, "benign", "fine").astype(object)
    conf = np.ones(n)
    mass = P[np.arange(n), am].astype(float)
    reason = np.full(n, "", dtype=object)
    for fname, members in families.items():
        idx = [classes.index(c) for c in members if c in classes]
        if not idx:
            continue
        in_f = np.isin(am, idx)
        fm = P[:, idx].sum(1)
        share = P[np.arange(n), am] / np.maximum(fm, 1e-12)
        fam[in_f] = fname
        mass[in_f] = fm[in_f]
        conf[in_f] = share[in_f]
        unc = in_f & (share < tau)
        fine[unc] = UNCERTAIN.format(fam=fname)
        status[unc] = "uncertain"
        reason[unc] = [f"top class share {s:.2f} of {fname} mass < tau {tau:g}" for s in share[unc]]
    return {"predicted_family": fam, "fine_label": fine, "fine_label_status": status,
            "fine_confidence": conf, "family_mass": mass, "uncertainty_reason": reason}


def annotate_frame(df, classes, cfg):
    """Annotate a detections frame that carries p_<class> columns (backward compatible with old runs)."""
    fams, tax, tau = settings(cfg)
    P = df[[f"p_{c}" for c in classes]].to_numpy(dtype=float)
    return pd.DataFrame(annotate(P, classes, fams, tax, tau), index=df.index)


def incident_labels(df, incident_col="incident_id"):
    """Incident-level family-aware label: most frequent (family, fine_label) among the incident's flows;
    status 'uncertain' if that fine label is an uncertain one. Same rule everywhere (UI, export)."""
    d = df[df[incident_col] > 0]
    if d.empty:
        return pd.DataFrame(columns=["predicted_family", "fine_label", "fine_label_status", "share_uncertain"])
    g = d.groupby(incident_col)
    top = g.fine_label.agg(lambda s: s.value_counts().index[0])
    fam = g.predicted_family.agg(lambda s: s.value_counts().index[0])
    unc = g.fine_label_status.agg(lambda s: float((s == "uncertain").mean()))
    st = np.where(top.str.contains("fine class uncertain"), "uncertain", np.where(top == BENIGN, "benign", "fine"))
    return pd.DataFrame({"predicted_family": fam, "fine_label": top, "fine_label_status": st, "share_uncertain": unc})


# kept for the earlier evaluation code path (pilot.py)
def render(P, classes, families, tau):
    return annotate(P, classes, families, {}, tau)["fine_label"]
