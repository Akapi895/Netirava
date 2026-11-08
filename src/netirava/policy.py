"""Alert policy in simulated event time.

Active policy (A0 only): a flow is a candidate when a0 attack_score >= the
A0 threshold. Candidates of the same entity (source IP by default) within
`cooldown_ms` of that entity's previous candidate join the same incident.
A new incident produces one notification if the hourly budget (per
simulated clock hour) is not exhausted; otherwise it is kept and logged as
suppressed by budget. Every candidate is logged with action and reason.

Shadow policy: same grouping on anomaly would_alert, no budget, no
notifications; never touches active state.
State is reset at capture-segment boundaries.
"""

from dataclasses import dataclass, field

HOUR_MS = 3_600_000


@dataclass
class Decision:
    action: str          # notify | suppressed | shadow_incident | shadow_dedup
    reason: str          # new_incident | cooldown_dedup | budget_exceeded
    incident_id: int
    new_incident: bool


class Policy:
    def __init__(self, cooldown_ms, budget_per_hour=None, shadow=False, id_start=1):
        self.cooldown_ms = int(cooldown_ms)
        self.budget = budget_per_hour
        self.shadow = shadow
        self.next_id = id_start
        self._base = id_start
        self.incidents = []          # dicts (for storage)
        self.reset()

    def reset(self):
        self.state = {}              # entity -> (incident_id, last_candidate_at)
        self.notified_in_hour = {}   # hour bucket -> count

    def step(self, t, entity, flow_id, segment):
        st = self.state.get(entity)
        if st is not None and t - st[1] <= self.cooldown_ms:
            inc_id = st[0]
            self.state[entity] = (inc_id, t)
            inc = self.incidents[inc_id - self._base]
            inc["last_at"] = t
            inc["n_candidates"] += 1
            return Decision("shadow_dedup" if self.shadow else "suppressed", "cooldown_dedup", inc_id, False)
        inc_id = self.next_id
        self.next_id += 1
        self.state[entity] = (inc_id, t)
        notify = False
        reason = "new_incident"
        if not self.shadow:
            h = t // HOUR_MS
            used = self.notified_in_hour.get(h, 0)
            if self.budget is None or used < self.budget:
                self.notified_in_hour[h] = used + 1
                notify = True
            else:
                reason = "budget_exceeded"
        self.incidents.append({"incident_id": inc_id, "detector": "anomaly" if self.shadow else "a0", "entity": entity,
                               "segment": segment, "opened_at": t, "first_flow_id": int(flow_id), "last_at": t,
                               "n_candidates": 1, "notified": notify, "open_reason": reason})
        if self.shadow:
            return Decision("shadow_incident", "new_incident", inc_id, True)
        return Decision("notify" if notify else "suppressed", reason, inc_id, True)
