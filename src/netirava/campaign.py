"""Campaign-level incident correlation and the shared review queue (runtime side, label-free).

Pre-registered in docs/OPS_STUDY_PREREG.md §3. A *campaign* links source incidents
(source IP + 15-min cooldown, the existing unit) that hit the same target host with the
same predicted attack family:

- When a source incident opens (its first alerted flow) with key k = (dst, family), it
  joins the active campaign that holds k (last alerted flow on k within cooldown);
  otherwise it opens a new campaign that holds k.
- Every later alerted flow of that source incident registers its own key for the
  incident's campaign, unless an *other* active campaign already holds that key.
  Two existing campaigns are never merged (no transitive blow-up, fully causal).
- State resets at capture-segment boundaries. No label, no future flow is used.

The binary alert, the source incidents and the notification budget are unchanged: a
campaign is only a coarser *review unit*. `review_queue` is the one queue function used
for every unit (source incident or campaign), so comparisons differ only in the unit.
"""

import numpy as np
import pandas as pd

HOUR_MS = 3_600_000
UNKNOWN = "Unknown"


class Correlator:
    def __init__(self, cooldown_ms, key=("dst", "family"), id_start=1):
        self.cooldown_ms = int(cooldown_ms)
        self.key = tuple(key)
        self.next_id = id_start
        self.reset()

    def reset(self):
        self.owner = {}          # key -> [campaign_id, last_t]
        self.of_incident = {}    # source incident id -> campaign id

    def _k(self, dst, family):
        return (dst, family) if "family" in self.key else (dst,)

    def step(self, t, src_incident, dst, family):
        k = self._k(dst, family)
        own = self.owner.get(k)
        live = own is not None and t - own[1] <= self.cooldown_ms
        c = self.of_incident.get(src_incident)
        if c is None:                                   # source incident opens: join or create
            if live:
                c = own[0]
            else:
                c = self.next_id
                self.next_id += 1
            self.of_incident[src_incident] = c
        if not live or own[0] == c:                     # register / refresh the key for this campaign
            self.owner[k] = [c, t]
        return c


def flow_family(predicted_family, fine_label_status):
    """Family used by the campaign key; alerts whose argmax is Benign have no attack family."""
    fam = np.asarray(predicted_family, dtype=object).copy()
    fam[np.asarray(fine_label_status, dtype=object) == "benign"] = UNKNOWN
    return fam


def assign(fl, cooldown_ms, key=("dst", "family")):
    """Campaign id per alerted flow. fl: alerted flows with columns segment, decision_at, available_at,
    flow_id, src_incident, dst, family. Processed in replay order (segment start, available_at, flow_id),
    state reset per segment. Returns an int64 array aligned with fl's rows."""
    if fl.empty:
        return np.zeros(0, np.int64)
    seg_start = fl.groupby("segment").decision_at.transform("min").to_numpy()
    order = np.lexsort((fl.flow_id.to_numpy(), fl.available_at.to_numpy(), seg_start))
    cor = Correlator(cooldown_ms, key)
    out = np.zeros(len(fl), np.int64)
    seg, t = fl.segment.to_numpy(), fl.decision_at.to_numpy(np.int64)
    inc, dst, fam = fl.src_incident.to_numpy(), fl.dst.to_numpy(), fl.family.to_numpy()
    cur = None
    for i in order:
        if seg[i] != cur:
            cur = seg[i]
            cor.reset()
        out[i] = cor.step(int(t[i]), inc[i], dst[i], fam[i])
    return out


def review_queue(fl, unit_col, budgets, policies=("fifo", "volume", "severity"), sev_col="severity", hour_ms=HOUR_MS):
    """Hourly review queue shared by every unit. fl: alerted flows (unit_col, decision_at, sev_col).
    An item opens at its first alerted flow (hour h) and is reviewed at the end of h (r = (h+1)*H),
    competing only with items opened in h. Ranking uses only flows decided up to r (causal):
      fifo     earliest opened
      volume   most alerted flows up to r (ties: earlier)
      severity highest flow severity up to r, then volume, then earlier.
    Returns (items, selected): items = DataFrame indexed by item id (t0, hour, review_at, n_at_review,
    sev_at_review, n_total, rank_<policy>); selected[(policy, B)] = set of reviewed item ids."""
    if fl.empty:
        return pd.DataFrame(columns=["t0", "hour", "review_at", "n_at_review", "sev_at_review", "n_total"]), \
            {(p, B): set() for p in policies for B in budgets}
    g = fl[[unit_col, "decision_at", sev_col]].rename(columns={unit_col: "item", sev_col: "sev"})
    t0 = g.groupby("item").decision_at.min()
    hour = t0 // hour_ms
    rev = (hour + 1) * hour_ms
    g = g.join(rev.rename("review_at"), on="item")
    upto = g[g.decision_at <= g.review_at]
    items = pd.DataFrame({"t0": t0, "hour": hour, "review_at": rev,
                          "n_at_review": upto.groupby("item").size(), "sev_at_review": upto.groupby("item").sev.max(),
                          "n_total": g.groupby("item").size()})
    keys = {"fifo": (["hour", "t0"], [True, True]),
            "volume": (["hour", "n_at_review", "t0"], [True, False, True]),
            "severity": (["hour", "sev_at_review", "n_at_review", "t0"], [True, False, False, True])}
    selected = {}
    for p in policies:
        cols, asc = keys[p]
        o = items.sort_values(cols, ascending=asc, kind="stable")
        rank = o.groupby("hour").cumcount()
        items[f"rank_{p}"] = rank.reindex(items.index).astype(int) + 1
        for B in budgets:
            selected[(p, B)] = set(o.index[rank.to_numpy() < B])
    return items, selected


def campaign_table(fl, unit_col="campaign_id"):
    """Analyst-facing campaign summary (label-free): sources, targets, families, flows, time span."""
    if fl.empty:
        return pd.DataFrame()
    g = fl.groupby(unit_col)
    top = lambda s: s.value_counts().index[0]
    return pd.DataFrame({
        "n_flows": g.size(), "n_sources": g.entity.nunique(), "n_source_incidents": g.src_incident.nunique(),
        "n_targets": g.dst.nunique(), "family": g.family.agg(top), "top_target": g.dst.agg(top),
        "sources": g.entity.agg(lambda s: ", ".join(s.value_counts().index[:5]) + (" …" if s.nunique() > 5 else "")),
        "max_score": g.a0_score.max(), "first": g.decision_at.min(), "last": g.decision_at.max(),
        "segment": g.segment.first()})
