# External UNSW evaluation and final-fit gate

**English translation of the original pre-registration dated 2026-11-09, commit `6ad5206`.** The original preceded reading UNSW labels or running a Netirava model on that source. This translation is not a new pre-registration; original hashes/bytes are documented in [provenance](README.md). Final `pilot_cns/s0` and the demo are not changed by these results.

## Source and project history

Original source path: `../GraphIDS/data/NF-UNSW-NB15-v3/NF-UNSW-NB15-v3.csv`. Same UQ NetFlow v3 49-feature schema as CIC; IXIA PerfectStorm traffic in two captures. Earlier GraphIDS/Run 1 used random splits; NP-v1 used period B (February 18, 2015) for development and A (January 22) for evaluation before keeping A0. Therefore new to the CIC checkpoint, not independent of the project's recipe selection.

## E1. Frozen-checkpoint evaluation

- Pilot and A0 v2 unchanged; thresholds selected on CIC C1 at α=0.1% and 1%; no UNSW recalibration.
- All rows, reported by FLOW_START UTC calendar date; exact duplicates removed using timestamps/IPs/49 features, keeping first; raw counts also reported.
- Metrics: benign FPR/Wilson; per-UNSW-class recall/support, source/destination counts, label+src+dst episodes with >30-minute gaps receiving an alert; descriptive CIC predicted labels; per-class AUROC against benign.
- A threshold is maintained only if FPR≤2α on **every** date. Recall describes score transfer; UNSW classes are not known training classes of the CIC checkpoint.

## E2. Gate for the single remaining fit

Use labels/host/time/hashes before fitting:

| Gate | Original requirement |
|---|---|
| G1 | Minority=<1% of deduplicated attack flows; at least two minority classes with ≥30 deduplicated flows on **both** capture dates, and source hosts or episodes on each side |
| G2 | Source documentation matches captures, attacker/victim subnets, timestamp meanings, and IXIA ground-truth labels |
| G3 | Zero exact duplicates between dates; report shared minority model-input fingerprints as a risk |
| G4 | Separate benign calibration: final 20% of the training date, ≥100,000 flows, plus benign test |
| G5 | Estimated RAM<8 GB and fit<10 minutes on the available machine |
| G6 | Test not used in NP-v1 periods A/B or Run 1/GraphIDS random splits that influenced recipe selection |

Fit only if all six pass. G6 was added because the question is performance of a locked recipe on a new source, not mere repeat fitting. If any gate fails, do not train; record reasons and preserve the slot.

If gates pass: one CatBoost multiclass A0 recipe with Balanced weights, no SMOTENC, seed0; train one capture day, benign calibration from its last20%, test the other day; UNSW taxonomy; per-class support/P/R/F1/host/episode and recall at α=0.1%/1%.

The original calendar-day partition later required interpretation by actual capture session because January22 extends into January23 UTC. This correction and the NO-GO outcome are in [monitoring/transfer](../monitoring_and_transfer.md), not rewritten into the original plan.

## E3. Human formative task

Use `task-make`, `task-run`, and `task-score` only when human participants are available. Counterbalance C0/C1 order across people, record count/experience, call results formative. No human results were produced in this round.
