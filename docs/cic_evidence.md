# Primary CIC evidence ledger

This is the authoritative ledger for **CIC** headlines. `runs/final_evidence/{LEDGER.json,LEDGER_flows.md,LEDGER_classes.md}` are generated from saved runs by `python -m netirava ledger`, without scoring or fitting. [ToN evidence](ton_iot_evidence.json) belongs to a separately fitted checkpoint.

## 1. Frozen primary system

| Field | Value |
|---|---|
| Final model | `pilot_cns/s0`, hash `f964bde1ef5c`; eight classes, CNS2022-adapted labels, historical SMOTENC rule; training not exactly deduplicated |
| Operating point | α=0.1%, threshold **0.00924223068597019**, selected on 278,255 C1 benign flows |
| Review unit | Source IP + 15-minute cooldown; family-aware severity; B=10 items/hour; campaign experimental |
| DEV run | `20261108T190143_a0_fast`, `configs/demo.yaml`, K1–K5/S1/R1 |
| H5–H9 run | `20261108T211057_a0_fast`, `configs/ops_holdout.yaml` |
| Baseline | A0 v2 `f32899bde8b4`, threshold 0.867873; runs `20261108T190136_a0_fast` and `20261108T211051_a0_fast` |
| Selection rule | Pilot FPR≤baseline; false source incidents≤1.5×baseline; HOIC recall≥baseline−0.05. No minority/Portscan/Infiltration preservation clause. |

The model choice is finalized. The improvement is a **label/split/refit package comparison**; clean ablation does not attribute it to SMOTENC or isolate relabeling alone.

## 2. Cohort results at α=0.1%

Labels are CNS2022-adapted on audited February 22/28 and March 2, original elsewhere. Attempted/indeterminate rows are excluded. “Dedup” removes exact duplicates and regroups incidents by the same rule. Exposure is the declared FLOW_START observation window; completed flows can extend beyond it, so counts are primary and rates approximate.

| Cohort | Model | Benign n, dedup | FP raw→dedup | FPR raw→dedup | Attack support/recall, dedup | False source incidents, total items | Exposure |
|---|---|---:|---|---|---|---|---|
| H5–H9 pooled, used for selection | pilot | 906,279 | 591→584 | 0.065%→**0.064%** | HOIC 534,025: 0.813; Infiltration 23,450: 0.012 | **143 (156)** | 4.5 h |
| Same | A0 v2 | 906,279 | 779→701 | 0.085%→**0.077%** | HOIC 0.036; Infiltration 0.195 | **217 (254)** | 4.5 h |
| H5 HOIC | pilot / A0 v2 | 92,745 | 91 / 118, dedup | 0.098% / 0.127% | HOIC 0.813 / 0.036 | 14 / 36 | 0.5 h |
| H6, March 1 | pilot / A0 v2 | 248,156 | 153 / 140 | 0.062% / 0.056% | Infiltration 0.012 / 0.195; flagged labels, date not audited | 16 / 18 | 1 h |
| H7/H8 benign | pilot / A0 v2 | 175,955; 180,583 | 46,58 / 76,152 | 0.026%,0.032% / 0.043%,0.084% | — | 14,43 / 11,78 | 1+1 h |
| H9, February 28 evening | pilot / A0 v2 | 208,840 | 236 / 215 | 0.113% / 0.103% | 2,067 original Infiltration flows excluded as indeterminate | 56 / 74 | 1 h |
| S1, DEV | pilot / A0 v2 | 144,760 | 138 / 155 | 0.095% / 0.107% | Portscan 15,746: 0.006 / 0.063 | 16 / 42 | 0.67 h |
| R1, DEV | pilot / A0 v2 | 854,221 | 99 / 433 | 0.012% / 0.051% | Bot 62,793: **0 / 0** | 57 / 28 | 4 h |
| K1–K4 tails, within-episode | pilot / A0 v2 | 342,285 | 93 / 126 | 0.027% / 0.037% | FTP/SSH/GoldenEye 1.000; Slowloris 0.965 / 0.939 | 50 / 30 | 1.92 h |
| K5 pilot eval rows only | pilot / A0 v2 | 658 | 0 / 263 | 0% / 40.0% | XSS 15: 1 / 0; SQLi 2: 1 / 1 | 0 / 6 | 5 h |

Pooled deduplicated Wilson IID FPR intervals: pilot **[0.059%,0.070%]**, baseline **[0.072%,0.083%]**. They do not measure campaign-to-campaign variability.

### Minority argmax results

| Cohort | Class | Unique support | Pilot P/R/F1 | Baseline P/R/F1 |
|---|---|---:|---|---|
| K5 pilot eval rows | XSS | 15 | 1/1/1; recall Wilson [0.796,1] | 0/0/0 |
| Same | SQLi | 2 | 1/1/1; recall Wilson [0.342,1] | 0.286/1/0.444 |
| Pilot eval inside T5, not replayed | Web | 27 | 26/27 correctly classified | Not used as a headline comparison |

All are **inconclusive for robustness**: fewer than 30 flows per class and the same episode as training. XSS had 30 raw eval rows before 15 duplicates were removed.

## 3. Improvements and costs

| Measure | Baseline→pilot | Interpretation |
|---|---|---|
| H5–H9 dedup FPR | 0.077%→0.064% | About 17% relative reduction; raw estimate about 24% |
| H5–H9 false source incidents | 217→143 | 34.1% reduction; unchanged by dedup |
| HOIC recall | 0.036→0.813 | Largest flow-detection gain; one scenario, ten sources, binary detection only |
| H6 Infiltration recall | 0.195→0.012 | Large loss with uncertain original labels |
| S1 Portscan recall | 0.063→0.006 | Loss on adapted labels |
| Bot recall | 0→0 | Unresolved |
| H7/H8 FPR at α=0.5% | 0.231/0.386%→0.510/0.575% | Pilot worse at a higher operating budget |
| R1 / known false incidents | 28/30→57/50 | Pilot worse in development |

This is same-testbed replay evidence, not measured analyst time or live-network effectiveness.

## 4. Split chronology and holdout use

| Date | Windows | Role |
|---|---|---|
| February 14 | T1/K1/T2/K2 | Train heads and within-episode tails |
| February 15 | T3/K3/T4/K4 | Same design |
| February 16 | H2, H7 | Historical holdout |
| February 20 | C1, H1, H8 | Calibration and same-date held-out windows |
| February 21 | H4, H5 | Historical holdout |
| February 22 | T5, K5 | Web train after calibration; pilot training also uses part of K5 |
| February 23 | H3 | Historical holdout |
| February 28 | S1, H9 | Stress DEV and evening holdout |
| March 1 / March 2 | H6 / R1 | Holdout / development replay |

H1 tested decision-layer hypotheses; H2 tested Hulk; H3/H4 tested features; H5–H9 tested ops and the pilot-selection rule. All have been consumed. Subsequent analysis is exploratory or reporting correction, not a new untouched test. Purge/END-before-cut enforcement originally applied to FE inner T1–T4, not uniformly to every historical split.

## 5. Deduplication and measurement corrections

| Experiment | Exact duplicates |
|---|---|
| A0 v1/v2 and original pilot train/eval | Retained |
| FE study and H3/H4 arms | Removed |
| Original H5–H9 ops replay | Retained by protocol |
| Clean imbalance ablation | Removed |
| This ledger | Reports both; flow headlines use dedup |

The old ops denominator counted nine occupied clock-hour bins for 4.5 hours of selected exposure. Corrected ops uses declared duration and reports counts first; GO/NO-GO decisions did not change. Historical `decision.py`/`pilot.py` rates retain older semantics and are not promoted as current workload estimates.

Other corrections: pilot holdout-only drift correlation is 0.06, not pooled 0.56; family/fine labels use joint modes (0/789 real incidents affected); UI distinguishes review-time and lifetime data; wrong-config stream joins are blocked; corrections cannot reference another alert. These are presentation/measurement fixes, not detector retuning.

## 6. Claims

Supported: the conditional FPR/HOIC/false-incident comparison above; small within-episode minority results; record compression; family abstention evidence on its stated A0 v2 cohort. Unsupported: broad minority robustness, zero-day detection, calling HOIC by its unseen class name, pilot family-layer gains inferred from A0, analyst-hours saved, automatic adaptation, or new-test evidence from consumed holdouts.
