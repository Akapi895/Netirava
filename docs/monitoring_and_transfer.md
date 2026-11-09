# Monitoring and cross-environment transfer

## 1. Label-free monitor

The [ops protocol](protocols/ops_study.md) asks whether model-output/feature signals track the realized benign FPR of a frozen threshold. `drift.py` is parallel to detection: it never changes predictions, thresholds, or incident assignments. Ground truth is used only in the evaluator.

Reference C1 is scored by the same checkpoint; the adjacent `drift_reference.json` stores score quantiles and feature bins. Monitor windows are 15 minutes of event time, with at least 2,000 flows. Evaluation requires at least 5,000 benign flows; an exceedance E means realized benign FPR>2α.

| Signal | Definition | Fixed alarm |
|---|---|---|
| AR | Alerted fraction divided by α | Ratio≥2 and one-sided binomial p<0.001 |
| TR, primary | Mass in `[q_ref(1−10α),tα)` relative to reference band mass | Ratio≥2 and p<0.001 |
| Score PSI | Score-distribution PSI using reference quantile bins | ≥0.25 |
| Feature PSI | Median PSI across 49 features | ≥0.25 |

The wider sub-threshold band was hypothesized to be more stable than the thin alert tail. It can still contain attacks. “Useful” requires Spearman(TR,FPR)≥0.5 with positive lower CI, exceedance recall≥80%, and non-exceedance alarm rate≤20%. Fewer than five exceedance windows makes recall inconclusive.

## 2. CIC evidence

At primary α=0.1%, adapted labels where available:

| Pool | Model | Windows | Exceedances | Spearman(TR,FPR), 95% CI | Spearman(AR,FPR), 95% CI |
|---|---|---:|---:|---|---|
| H5–H9 only | A0 v2 | 18 | 0 | 0.33 [−0.25,0.73] | 0.61 [0.09,0.93] |
| H5–H9 only | Pilot | 18 | 1 | **0.06 [−0.45,0.57]** | 0.54 [0.01,0.93] |
| DEV+holdout | A0 v2 | 46 | 2 | 0.32 [0.01,0.58] | 0.24 [−0.13,0.63] |
| DEV+holdout | Pilot | 46 | 1 | 0.56 [0.32,0.73] | 0.50 [0.18,0.78] |

The primary pilot number is **0.06 on holdout**, not the DEV+holdout 0.56. Development windows have been inspected repeatedly. The small exceedance count does not validate monitor sensitivity. On pilot holdout, TR non-exceedance alarm rates are 0 on benign-only windows and 0.80 on attack-containing windows; alarms cannot simply be interpreted as false-positive degradation.

Score/feature PSI correlate weakly with FPR. `α×TR` is not a validated estimate: median log10 error is about 0.30 for A0 v2 and 0.58 for pilot; only 48%/20% of windows are within a factor of two. The UI labels it unvalidated. Conclusion: **INCONCLUSIVE**, distribution indicators only.

## 3. Frozen CIC models on NF-UNSW-NB15-v3

Original preregistration: commit `6ad5206`, translated [external protocol](protocols/external_evaluation.md). Dataset schema matches 49 NetFlow v3 features; original 2,365,424 rows become 2,350,609 after exact deduplication. IXIA PerfectStorm generated two sessions, January 22 (continuing into January 23 UTC) and February 18, 2015. Four attack-source hosts do not send benign flows.

This is new to the CIC **checkpoint**, but not independent of this project's earlier **recipe selection**: GraphIDS/Run 1 and NP-v1 had used these captures outside the repo. This is project-specific selection history, not a ban on benchmarking publicly studied datasets.

Models/thresholds remain frozen on CIC; no target-domain recalibration:

| Checkpoint | Capture | Benign n | FPR at CIC α=0.1% | FPR at CIC α=1% | Per-attack AUROC |
|---|---|---:|---:|---:|---|
| Pilot | Jan 22 | 1,074,674 | **25.1%** | 80.3% | 0.06–0.27 |
| Pilot | Jan 23 tail | 39,775 | 27.0% | 80.5% | — |
| Pilot | Feb 18 | 1,108,481 | **24.3%** | 80.1% | 0.10–0.25 |
| A0 v2 | Jan 22 | 1,074,674 | 2.03% | 61.7% | 0.23–0.44 |
| A0 v2 | Feb 18 | 1,108,481 | 2.07% | 62.2% | 0.27–0.42 |

Every attack-class AUROC is below 0.5: attack scores are ranked below benign scores. Almost all attack flows receive argmax Benign. A monotonic threshold change does not repair reversed ranking.

Checks confirm column-name alignment and comparable numeric dtypes. Observed shifts include benign TTL median 31–32 versus CIC 100, TCP window 13,032 versus 258, 21% benign FTP traffic, and a high benign-score tail. These are consistent with domain shift, not an isolated proof of which feature caused failure or exclusion of every possible semantic pipeline issue.

**Conclusion:** the tested CIC checkpoints cannot be used directly on this UNSW environment. Retraining/adaptation and calibration are hypotheses to verify, not guaranteed remedies.

## 4. Exploratory monitor result on UNSW

After seeing the transfer failure, the monitor was run using the pilot C1 reference, without labels. **99/99 windows** raise threshold-reliability warnings; all four signals flag every window. Median AR=232, TR=62.5, score PSI=6.35, feature PSI=1.81. TCP/L7 flag features shift most.

This establishes that the monitor flags a very large shift in this exploratory analysis. It is not prospective validation that it warned before the failure was known, and says little about subtle harmful shifts.

## 5. Why no UNSW training was performed

The final-fit gate uses labels, host/time metadata, and hashes, not favorable model scores:

| Gate | Outcome |
|---|---|
| Minority support/diversity | FAIL: Worms has 20 flows in the January session; Analysis has one source/episode there |
| Timestamp/session interpretation | PASS by actual session; code initially misread the January UTC tail as a third session |
| Cross-split exact duplicates | PASS: zero between calendar-day partitions |
| Benign calibration/test support | PASS by session; tail-only calendar-day check was misleading |
| Resources | PASS, approximately 2.37 million rows |
| Test independent of project recipe selection | FAIL: both sessions had influenced earlier recipe selection |

The training slot was not spent on UNSW. It was subsequently used for the separate [ToN experiment](ton_iot_evaluation.md). No result here changes the final CIC checkpoint.

## 6. ToN monitor scope and sources

ToN monitor tables are computed for UI display, but reliability against realized FPR has not been evaluated in that experiment. Do not transfer the UNSW 99/99 observation into a general monitor-performance claim.

Sources: [UQ dataset catalog](https://staff.itee.uq.edu.au/marius/NIDS_datasets/), [NetFlow v3 paper](https://arxiv.org/abs/2503.04404); conceptual references in the original ops protocol include NoDoze, CADE, and black-box shift detection. Netirava does not reproduce their algorithms or claim comparative performance against them.
