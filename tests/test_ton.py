"""NF-ToN-IoT-v3 pipeline pieces that do not fit a model (sampling, windows, single-fit guard, stream contract)."""

import json
from pathlib import Path

import numpy as np
import pytest

from netirava import config as K
from netirava import features as F
from netirava import ton


def test_sampling_hash_is_deterministic_and_uniform():
    rid = np.arange(200_000, dtype=np.int64)
    a, b = ton._u01(rid, 2026), ton._u01(rid, 2026)
    assert (a == b).all() and 0 <= a.min() and a.max() < 1
    assert abs(a.mean() - 0.5) < 0.01 and abs((a < 0.2).mean() - 0.2) < 0.01
    assert not (ton._u01(rid, 7) == a).all()


def test_window_index_respects_half_open_windows():
    wins = [{"start_ms": 0, "end_ms": 10}, {"start_ms": 20, "end_ms": 30}]
    assert ton._window_index(np.array([0, 9, 10, 15, 20, 29, 30]), wins).tolist() == [0, 0, -1, -1, 1, 1, -1]


def test_single_fit_guard_refuses_when_marker_exists(tmp_path):
    cfg = {"paths": {"models": str(tmp_path)}, "a0": {"known_classes": ["Benign"], "recipe": {}}}
    (tmp_path / "a0").mkdir()
    (tmp_path / "a0" / "FIT_STARTED.json").write_text("{}")
    with pytest.raises(RuntimeError, match="single-fit budget"):
        ton.train_once(cfg)


@pytest.mark.skipif(not (K.ROOT / "artifacts/ton_iot_v1/stream.parquet").exists(), reason="ToN-IoT derived data not prepared")
def test_ton_stream_has_no_labels_and_full_feature_contract():
    import pyarrow.parquet as pq
    cfg = K.load("configs/ton_iot.yaml")
    names = pq.read_schema(K.path(cfg, "derived") / "stream.parquet").names
    # labels never in the stream; `role` is stored for filtering (as for CIC) and dropped before the runtime contract
    assert not {F.LABEL, F.LABEL_BIN, "label_quality", "unknown_to_model", "scenario"} & set(names)
    import inspect
    from netirava import replay
    assert 'drop(columns=["_seg_order", "role"])' in inspect.getsource(replay.replay_frame)
    assert all(c in names for c in F.FEATURES + ["flow_id", "segment", "available_at", F.SRC, F.DST])
    man = json.loads((K.path(cfg, "derived") / "manifest.json").read_text(encoding="utf-8"))
    assert man["stream_sha1"] == K.sha1_file(K.path(cfg, "derived") / "stream.parquet")
