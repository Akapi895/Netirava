"""Runtime contracts. The runtime works on columnar batches; the dataclasses
document (and validate) the record shapes that cross module boundaries.

FlowEvent never carries labels, roles, quality flags or scenario names.
"""

from dataclasses import dataclass, field
from typing import Optional

from netirava import features as F

SCHEMA_VERSION = "netirava-contracts-v1"
# columns a FlowEvent batch may contain (identifiers are for policy/logging, not model input)
FLOW_EVENT_COLUMNS = ["flow_id", "segment", F.TS_START, F.TS_END, "available_at", F.SRC, F.DST] + F.FEATURES
FORBIDDEN_IN_RUNTIME = [F.LABEL, F.LABEL_BIN, "role", "label_quality", "unknown_to_model", "scenario"]


def flow_event_batch(df):
    """Project a stream frame onto the FlowEvent contract; fail on any label-like column."""
    bad = [c for c in FORBIDDEN_IN_RUNTIME if c in df.columns]
    if bad:
        raise ValueError(f"label/evaluator columns reached the runtime: {bad}")
    return df[FLOW_EVENT_COLUMNS]


@dataclass(frozen=True)
class FlowEvent:
    flow_id: int
    segment: str
    start_ms: int
    end_ms: int
    available_at: int
    src_ip: str
    dst_ip: str
    features: tuple


@dataclass(frozen=True)
class DetectionResult:
    flow_id: int
    detector: str              # "a0" | "anomaly"
    version: str               # model hash
    score: float               # higher = more suspicious (a0: 1 - p(Benign); anomaly: -score_samples)
    would_alert: bool
    predicted_class: Optional[str] = None
    proba: Optional[tuple] = None
    status: str = "ok"         # ok | missing | late
    runtime_ms: float = 0.0


@dataclass(frozen=True)
class Alert:
    alert_id: int
    incident_id: int
    flow_id: int
    entity: str
    detector: str
    created_at: int            # simulated event time (ms)
    reason: str
    policy_version: str
    status: str = "open"


@dataclass(frozen=True)
class Feedback:
    alert_id: int
    status: str                # true_positive | false_positive | uncertain
    source: str
    confirmed_by: str
    confirmed_at: str          # wall clock ISO time
    attack_label: Optional[str] = None
    corrects: Optional[int] = None
    provenance: str = "analyst"
