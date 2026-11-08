"""Shadow anomaly detector: IsolationForest fitted on TRAIN benign flows (source labels).

Score = -score_samples (higher = more anomalous). predict() is never used for
alerting; would_alert = score >= threshold chosen on CALIBRATION benign flows.
"""

import json
import pickle
import time

import numpy as np

from netirava import config as K
from netirava import features as F
from netirava.detectors import threshold_at_fpr, wilson


class Anomaly:
    def __init__(self, model, threshold, meta):
        self.model, self.threshold, self.meta = model, float(threshold), meta
        self.version = meta["model_hash"]

    def score(self, X):
        return -self.model.score_samples(F.log1p_signed(X))

    @staticmethod
    def load(path):
        with open(path / "anomaly.pkl", "rb") as f:
            m = pickle.load(f)
        meta = json.loads((path / "anomaly_meta.json").read_text(encoding="utf-8"))
        return Anomaly(m, meta["threshold"]["value"], meta)


def train(cfg):
    from sklearn.ensemble import IsolationForest
    from netirava.dataset import training_frame
    c = cfg["anomaly"]
    t0 = time.perf_counter()
    tr = training_frame(cfg, ["train"])
    ben = tr[tr[F.LABEL] == "Benign"].sort_values("row_id")
    n_avail = len(ben)
    if n_avail > c["max_train_rows"]:
        rng = np.random.default_rng(0)
        ben = ben.iloc[np.sort(rng.choice(n_avail, c["max_train_rows"], replace=False))]
    X = F.log1p_signed(F.matrix(ben))
    m = IsolationForest(n_estimators=c["n_estimators"], max_samples=c["max_samples"], contamination=c["contamination"],
                        random_state=c["random_state"], n_jobs=c["n_jobs"])
    m.fit(X)
    out = K.path(cfg, "models") / "anomaly"
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "anomaly.pkl", "wb") as f:
        pickle.dump(m, f)
    cal = training_frame(cfg, ["calibration"])
    cb = cal[F.LABEL].to_numpy() == "Benign"
    s = -m.score_samples(F.log1p_signed(F.matrix(cal)))
    thr, realised = threshold_at_fpr(s[cb], c["target_fpr"])
    nb = int(cb.sum())
    meta = {"detector": "anomaly", "model_hash": K.sha1_file(out / "anomaly.pkl")[:12],
            "algorithm": "sklearn IsolationForest", "params": {k: c[k] for k in ("n_estimators", "max_samples", "contamination", "random_state", "n_jobs")},
            "train_rows": int(len(ben)), "train_benign_available": int(n_avail),
            "sampling": f"uniform without replacement, numpy seed 0, cap {c['max_train_rows']} (train-role benign rows, source labels)",
            "transform": "sign(x)*log1p(|x|) on the 49 allowlisted features (fixed, not learned)",
            "score": "-score_samples (higher = more anomalous); predict() not used",
            "threshold": {"value": thr, "target_fpr": c["target_fpr"], "realised_fpr_calibration": realised,
                          "n_benign_calibration": nb, "wilson95": wilson(int(round(realised * nb)), nb),
                          "uncertain": bool(nb < 10 / c["target_fpr"])},
            "feature_schema_hash": F.schema_hash(), "fit_seconds": time.perf_counter() - t0,
            "sklearn_version": __import__("sklearn").__version__, "config_sha1": cfg["_sha1"]}
    (out / "anomaly_meta.json").write_text(json.dumps(meta, indent=2))
    return meta
