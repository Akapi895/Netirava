"""Synthetic NetFlow-v3-shaped dataset and config for integration tests."""

import numpy as np
import pandas as pd
import pytest
import yaml

from netirava import config as K
from netirava import features as F

COLS = [F.TS_START, F.TS_END, F.SRC, "L4_SRC_PORT", F.DST, "L4_DST_PORT"] + \
       [c for c in F.FEATURES if c not in ("L4_SRC_PORT", "L4_DST_PORT")] + [F.LABEL_BIN, F.LABEL]
T0 = int(pd.Timestamp("2018-02-14 12:00", tz="UTC").value // 1_000_000)
MIN = 60_000


def make_csv(path, flip_replay_labels=False, seed=0):
    rng = np.random.default_rng(seed)
    rows = []

    def block(t_start_min, t_end_min, n, label, src_pool, shift):
        s = T0 + rng.integers(t_start_min * MIN, t_end_min * MIN, n)
        dur = rng.integers(0, 5000, n)
        df = pd.DataFrame({c: rng.integers(0, 50, n) for c in F.FEATURES})
        for c in ("IN_BYTES", "OUT_BYTES", "IN_PKTS", "FLOW_DURATION_MILLISECONDS"):
            df[c] = (df[c] + shift * 40 + rng.integers(0, 10, n)).astype(int)
        df[F.TS_START], df[F.TS_END] = s, s + dur
        df[F.SRC] = rng.choice(src_pool, n)
        df[F.DST] = rng.choice(["10.0.0.1", "10.0.0.2", "10.0.0.3"], n)
        df[F.LABEL] = label
        df[F.LABEL_BIN] = int(label != "Benign")
        rows.append(df)

    ben_src = [f"172.31.1.{i}" for i in range(20)]
    block(0, 60, 3000, "Benign", ben_src, 0)                 # train window 0-60
    block(5, 55, 1200, "FTP-BruteForce", ["18.0.0.9"], 3)
    block(60, 90, 2000, "Benign", ben_src, 0)                # calibration 60-90
    block(90, 150, 2500, "Benign", ben_src + ["172.31.9.9"], 0)  # replay 90-150
    block(110, 140, 400, "Bot" if not flip_replay_labels else "Benign", ["172.31.9.9"], 6)
    block(150, 160, 300, "FTP-BruteForce" if not flip_replay_labels else "Benign", ["18.0.0.9"], 3)
    df = pd.concat(rows, ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)   # raw file order != time order
    df[COLS].to_csv(path, index=False)


def make_cfg(tmp, csv):
    def ts(m):
        return str(pd.to_datetime(T0 + m * MIN, unit="ms", utc=True).tz_localize(None))
    cfg = {
        "dataset": {"name": "synthetic", "sha1": None, "max_rows": 100000},
        "paths": {"raw_csv": str(csv), "derived": str(tmp / "derived"), "models": str(tmp / "models"), "runs": str(tmp / "runs")},
        "windows": [
            {"id": "T1", "role": "train", "start_utc": ts(0), "end_utc": ts(60), "scenario": "known-train"},
            {"id": "C1", "role": "calibration", "start_utc": ts(60), "end_utc": ts(90), "scenario": "calibration"},
            {"id": "R1", "role": "replay", "start_utc": ts(90), "end_utc": ts(150), "scenario": "unknown-bot"},
            {"id": "K1", "role": "known_replay", "start_utc": ts(150), "end_utc": ts(160), "scenario": "known-within-episode"},
        ],
        "labels": {"flagged_classes": [], "taxonomy": {}},
        "a0": {"known_classes": ["Benign", "FTP-BruteForce"], "reference_config": None, "seed": 0, "target_fpr": 0.01,
               "device": "CPU", "params_override": {"iterations": 30, "thread_count": 2}},
        "anomaly": {"n_estimators": 20, "max_samples": 64, "contamination": "auto", "random_state": 0, "n_jobs": 1,
                    "max_train_rows": 1000, "transform": "log1p_signed", "target_fpr": 0.01},
        "replay": {"export_delay_ms": 0, "decision_tick_ms": 1000, "chunk_events": 500, "default_speed": 1e9,
                   "shadow_deadline_ms_per_event": 1000.0},
        "policy": {"version": "test", "entity": F.SRC, "cooldown_ms": 600000, "budget_per_hour": 2},
        "evaluation": {"episode_gap_ms": 1800000},
    }
    p = tmp / "cfg.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return K.load(p)


@pytest.fixture(scope="session")
def synth(tmp_path_factory):
    from netirava.dataset import prepare
    from netirava.detectors import a0, anomaly
    tmp = tmp_path_factory.mktemp("synth")
    csv = tmp / "flows.csv"
    make_csv(csv)
    cfg = make_cfg(tmp, csv)
    prepare(cfg)
    a0.train(cfg)
    anomaly.train(cfg)
    return cfg
