"""Family-aware output (post-hoc, label rendering only).

Probabilities are NOT modified: p(Benign), the family mass and every class
probability stay as the model produced them, so the binary alert decision
(attack_score = 1 - p(Benign) vs the locked threshold) cannot change.
Only flows whose argmax class belongs to a family are re-rendered: the fine
class is kept if its share of the family mass is >= tau, otherwise the flow
is labelled "<family> attack - fine class uncertain".
"""

import numpy as np

UNCERTAIN = "{fam} attack - fine class uncertain"


def render(P, classes, families, tau):
    classes = list(classes)
    argmax = P.argmax(1)
    labels = np.asarray(classes, dtype=object)[argmax].copy()
    for fam, members in families.items():
        idx = [classes.index(c) for c in members if c in classes]
        mass = P[:, idx].sum(1)
        in_fam = np.isin(argmax, idx)
        share = np.where(mass > 0, P[np.arange(len(P)), argmax] / np.maximum(mass, 1e-12), 0.0)
        labels[in_fam & (share < tau)] = UNCERTAIN.format(fam=fam)
    return labels


def family_of(labels, families):
    out = np.asarray(labels, dtype=object).copy()
    for fam, members in families.items():
        out[np.isin(out, list(members)) | (out == UNCERTAIN.format(fam=fam))] = fam
    return out
