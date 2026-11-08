"""Detectors: a0 (supervised CatBoost, active) and anomaly (IsolationForest, shadow)."""

import numpy as np


def threshold_at_fpr(benign_scores, target_fpr):
    """Smallest threshold t such that the share of benign scores >= t is <= target.
    Alerting rule everywhere: score >= t. Returns t and the realised share."""
    s = np.sort(np.asarray(benign_scores, float))[::-1]
    n = len(s)
    k = int(np.floor(target_fpr * n))           # number of benign allowed at or above t
    t = float(np.nextafter(s[k], np.inf)) if k < n else float(s[-1])
    realised = float((s >= t).mean())
    return t, realised


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [float(max(0.0, c - h)), float(min(1.0, c + h))]
