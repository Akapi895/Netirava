"""Run storage: run.json (metadata), detections.parquet (one row per flow,
all detector outputs and policy actions), alerts.db (SQLite: incidents,
alerts, append-only feedback)."""

import datetime as dt
import json
import sqlite3
from pathlib import Path

import pandas as pd

from netirava import config as K

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (incident_id INTEGER PRIMARY KEY, detector TEXT, entity TEXT, segment TEXT,
  opened_at INTEGER, first_flow_id INTEGER, last_at INTEGER, n_candidates INTEGER, notified INTEGER, open_reason TEXT);
CREATE TABLE IF NOT EXISTS alerts (alert_id INTEGER PRIMARY KEY, incident_id INTEGER, flow_id INTEGER, entity TEXT,
  detector TEXT, created_at INTEGER, reason TEXT, policy_version TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS feedback (feedback_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('true_positive','false_positive','uncertain')), source TEXT, confirmed_by TEXT,
  confirmed_at TEXT, attack_label TEXT, corrects INTEGER REFERENCES feedback(feedback_id), provenance TEXT);
CREATE TRIGGER IF NOT EXISTS feedback_no_update BEFORE UPDATE ON feedback BEGIN SELECT RAISE(ABORT, 'feedback is append-only'); END;
CREATE TRIGGER IF NOT EXISTS feedback_no_delete BEFORE DELETE ON feedback BEGIN SELECT RAISE(ABORT, 'feedback is append-only'); END;
"""


class RunStore:
    def __init__(self, cfg, run_id, create=False):
        self.dir = K.path(cfg, "runs") / run_id
        if create:
            self.dir.mkdir(parents=True, exist_ok=False)
        elif not self.dir.exists():
            raise FileNotFoundError(self.dir)
        self.db = self.dir / "alerts.db"
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        return sqlite3.connect(self.db)

    def write_meta(self, meta):
        (self.dir / "run.json").write_text(json.dumps(meta, indent=2, default=str))

    def meta(self):
        return json.loads((self.dir / "run.json").read_text(encoding="utf-8"))

    def write_detections(self, df):
        df.to_parquet(self.dir / "detections.parquet", index=False)

    def detections(self, columns=None):
        return pd.read_parquet(self.dir / "detections.parquet", columns=columns)

    def write_incidents(self, incidents, alerts):
        with self._conn() as c:
            c.executemany("INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?)",
                          [(i["incident_id"], i["detector"], i["entity"], i["segment"], i["opened_at"], i["first_flow_id"],
                            i["last_at"], i["n_candidates"], int(i["notified"]), i["open_reason"]) for i in incidents])
            c.executemany("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
                          [(a["alert_id"], a["incident_id"], a["flow_id"], a["entity"], a["detector"], a["created_at"],
                            a["reason"], a["policy_version"], a["status"]) for a in alerts])

    def add_feedback(self, alert_id, status, source, confirmed_by, attack_label=None, corrects=None,
                     provenance="analyst"):
        with self._conn() as c:
            if not c.execute("SELECT 1 FROM alerts WHERE alert_id=?", (alert_id,)).fetchone():
                raise ValueError(f"alert {alert_id} not found in this run")
            if corrects is not None and not c.execute("SELECT 1 FROM feedback WHERE feedback_id=?", (corrects,)).fetchone():
                raise ValueError(f"feedback {corrects} to correct not found")
            cur = c.execute("INSERT INTO feedback (alert_id,status,source,confirmed_by,confirmed_at,attack_label,corrects,provenance) "
                            "VALUES (?,?,?,?,?,?,?,?)",
                            (alert_id, status, source, confirmed_by, dt.datetime.now(dt.timezone.utc).isoformat(),
                             attack_label, corrects, provenance))
            return {"feedback_id": cur.lastrowid, "alert_id": alert_id, "status": status, "corrects": corrects}

    def feedback(self):
        with self._conn() as c:
            return pd.read_sql("SELECT * FROM feedback ORDER BY feedback_id", c)

    def list_incidents(self, limit=20):
        with self._conn() as c:
            q = ("SELECT a.alert_id, i.incident_id, i.detector, i.entity, i.segment, "
                 "datetime(i.opened_at/1000,'unixepoch') AS opened_utc, i.n_candidates, i.notified, i.open_reason "
                 "FROM incidents i LEFT JOIN alerts a ON a.incident_id=i.incident_id "
                 "WHERE i.detector='a0' ORDER BY i.opened_at LIMIT ?")
            return c.execute(q, (limit,)).fetchall()
