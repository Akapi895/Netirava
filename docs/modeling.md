# Modeling, features, and ablations

## 1. Checkpoint roles and recipe

| Checkpoint | Hash | Training labels/classes | Threshold at α=0.1% |
|---|---|---|---:|
| A0 v1, historical MVP | `be8f6d84bf2d` | Original labels, five classes | 0.003938 |
| A0 v2, CIC baseline | `f32899bde8b4` | Original labels, eight classes including Web/XSS/SQLi | 0.867873 |
| `pilot_cns/s0`, **primary final** | `f964bde1ef5c` | CNS2022-adapted labels, eight classes | 0.009242 |
| ToN supplementary | `42b82c1d80ed` | Original ToN labels, ten classes, separate fit | 0.995843 |

CIC's NP-v1 anchor uses CatBoost MultiClass, 1,000 trees, depth 6, L2=3, Plain boosting, Bayesian bootstrap, border count 254, GPU, and a historical CPU learning-rate probe. Classes below 1,000 training rows are increased to 1,000 with SMOTENC (`k=5`, categorical codes copied rather than interpolated). `configs/a0_reference.yaml` provides a portable snapshot if the external historical recipe is absent. Loading a checkpoint does not require that recipe.

Both datasets use 49 NetFlow v3 inputs. Raw ports, TTL, and DNS query ID remain; no IP, absolute timestamp, or label is a model input. `attack_score=1-p(Benign)` is not a calibrated attack probability. All operating thresholds are selected on benign calibration, not test attacks. ToN uses a predeclared fixed learning rate and Balanced weights without SMOTENC or the CPU probe; it is not an ablation against the CIC checkpoint.

## 2. Historical supervised/anomaly experiments

A0 v1 achieves known-tail recall 0.9985/FPR 0.025% within the same episodes, but Bot recall is zero at α=0.1%. IsolationForest has higher Bot AUROC (0.923 versus A0's 0.718) yet adds no useful low-FPR detections at that operating point. It remains a shadow diagnostic.

Decision-layer variants share a total calibration FPR budget: V1=A0, V2=anomaly, V3=OR with half-budget per branch; V4a/V4b add causal host aggregation. V4b uses ≥50 flows/60 seconds and mean anomaly score above a calibration threshold. It is locked at `e5336a8` after development on Bot/Web.

| Result | α=0.1% | α=1% |
|---|---|---|
| DEV Bot, V1 | 0/8 episodes | 0/8 |
| DEV Bot, V4b | 0/8 | 8/8; flow recall 0.958, FPR 0.601% |
| H1 LOIC-HTTP, V1 | Recall 0 | Recall 0.757 |
| H1 LOIC-HTTP, V4b | Recall 0 | Recall 0.707; at α=0.5%, recall loses 0.685 versus V1 |

**V4b is rejected:** splitting the FPR budget weakens A0 without an anomaly benefit on H1. A post-holdout A0-score aggregation observation is exploratory and raises FPR elsewhere; it is not deployed as a proven improvement. H2 Hulk yields A0 v2 recall 0.928 at FPR 0.050%, but only one attack episode.

## 3. Why the original imbalance result is insufficient

On original-label K1–K5, seed-0 rare macro-F1 is 0.469 with SMOTENC, 0.421 without resampling, and 0.458 with SqrtBalanced weights. A0 rare macro-F1 over seeds 0/1/2 is 0.469/0.487/0.525. Removing SMOTENC reduces it by 0.048/0.061/0.143, but the seed-0 source bootstrap difference interval includes zero (−0.162,+0.003), and weighting comparisons are inconsistent.

Original-label Web/XSS/SQLi F1 is 0.769/0.528/0.109. Most nominal web labels fail credible rules; fingerprints cross labels and splits. These scores primarily measure reproduction of published labels. They do **not** establish a minority-detection benefit on credible attacks.

The pilot applies CNS2022-adapted labels and a first-60%-of-credible-window training split. Before deduplication its web training support is 43/50/15; evaluation support is 27/30/2. After deduplication evaluation XSS support is 15. Near-perfect evaluation is within-episode and inconclusive for generalization. Gains against A0 v2 combine labels, web split, and refitting; they do not isolate relabeling alone.

## 4. Clean imbalance ablation

Translated [pre-fit protocol](protocols/clean_ablation.md), original commit `d368fdc`. All arms use the same 650,248 exact-deduplicated training rows, corrected labels, 49 raw features, calibration rule, and seeds 0/1/2. Arms are `none`, Balanced class weighting (`cw`), and the historical SMOTENC rule. This does not change the final CIC model.

| Metric, seed 0/1/2 | none | cw | smotenc |
|---|---|---|---|
| Web F1, n=27 | 0.962 ×3 | 1.000 ×3 | 0.981 ×3 |
| XSS F1 n=15 / SQLi n=2 | 1.000 | 1.000 | 1.000 |
| GoldenEye F1 | 0.999/1.000/1.000 | 0.961/0.966/0.961 | 1.000/1.000/1.000 |
| Slowloris F1 | 0.968 ×3 | 0.966/0.970/0.966 | 0.961/0.964/0.968 |
| R1 false source incidents, α=0.1% | 43/68/48 | **31/30/42** | 61/52/74 |
| S1 Portscan recall, α=1% | **0.70/0.48/0.56** | 0.03/0.22/0.03 | 0.15/0.12/0.33 |
| HOIC recall, α=0.1%, **EXP** | 0.99/1.00/0.70 | 1.00/1.00/0.99 | 0.56/0.33/0.88 |

Consumed holdout results are exploratory. Class weighting helps some measures but harms GoldenEye. SMOTENC's GoldenEye advantage over `none` is only 0.0003–0.0008, not a substantive reason to retain it. Minorities are too small/easy to distinguish treatments. Same-direction differences across three seeds are a descriptive rule, not statistical significance.

**Conclusion:** the earlier original-label benefit does not translate into clear credible-minority benefit under clean conditions. This is not proof that SMOTENC can never help.

## 5. Feature/preprocessing study

Protocol: `configs/fe_study.yaml`, commit `e820605`; code frozen at `c22f8fc`. Corrected labels, exact deduplication, A0 recipe, three seeds, no HPO. T1–T4 inner split uses first 70%, five-minute purge, remaining 30%; web follows the pilot split. Metrics are M1=inner-val macro-F1, M3=unseen-feature-fingerprint macro-F1, and benign FPR on S1/R1 at C1-calibrated α=0.1%.

| Candidate | Definition |
|---|---|
| G0 | 49 raw features |
| G_prep | Input/label aggregation with weights; categorical protocol/flags; top-50 destination ports and source-port buckets; structural NaNs; log/robust-scale SMOTENC |
| G_shortcut_drop | Remove source port, DNS query ID, MIN/MAX TTL, and both TCP windows |
| G_ratio | Add 14 directional/packet/retransmission/time ratios |
| G_flag | Add 25 TCP flag bits/no-reply indicators |
| G_ctx | Add 60-second causal source/destination summaries; IP used only for grouping |
| Controls | Permuted features and equal-dimensional noise for added groups |

From G_ratio onward, added groups are based on G_shortcut_drop. G_ctx therefore has 53, not 59, features.

| Arm, mean over three seeds | M1 | M3 | S1 FPR | R1 FPR | S1 scan recall |
|---|---:|---:|---:|---:|---:|
| G0 | 0.9726 | 0.9687 | 0.099% | 0.011% | 0.006 |
| G_prep | 0.9984 | 0.9981 | 0.107% | 0.020% | 0.002 |
| G_shortcut_drop | 0.9726 | 0.9687 | 0.057% | 0.022% | 0.010 |
| G_ratio | 1.0000 | 1.0000 | 0.050% | 0.027% | 0.007 |
| Permuted ratio control | 0.9809 | 0.9782 | 0.033% | 0.018% | 0.007 |
| G_flag | 0.9726 | 0.9687 | 0.077% | 0.016% | 0.009 |
| G_ctx | 0.9957 | 0.9950 | 0.019% | 0.070% | 0.713 |
| Permuted context control | 0.9726 | 0.9686 | 0.062% | 0.015% | 0.005 |

Acceptance requires M1 loss≤0.01, improvement over permuted controls where applicable, and no segment FPR worse than the reference Wilson bound. G_prep/ratios/flags/context fail the acceptance rule. G_shortcut_drop is selected on DEV but must still pass holdout.

### H3/H4 falsification

H3 has 234,262 deduplicated benign flows on an unused date. H4 has 188,094 benign and 1,725 LOIC-UDP attack flows, ten attackers. Final-training population is common across candidate/reference.

| Model, seeds 0/1/2, α=0.1% | H3 FPR | H4 FPR | H4 LOIC-UDP recall |
|---|---|---|---|
| Shortcut-drop, 43 inputs | 0.025/0.030/0.024% | 0.022/0.027/0.021% | 0/0/0 |
| Reference G0 | 0.007/0.007/0.026% | 0.018/0.018/0.033% | 0.0006/0/0.0006 |
| Frozen A0 v2 | 0.027% | 0.077% | 0 |
| Frozen pilot | 0.052% | 0.018% | 0.093, 9/10 episodes |

At α=1%, candidate recall is 0.80/0.01/0.02 versus reference 0.99/0.98/0.65. The declared rule fails: **NO-GO**. The final pipeline retains all 49 features. Historical study incident/hour values used an older occupied-hour denominator; the submission uses corrected counts/exposure rather than promoting those rates.

## 6. Final selection, cost, and stopped directions

The predeclared ops rule selects the pilot on H5–H9 only if pooled FPR is no higher, false source incidents are ≤1.5× baseline, and HOIC recall is ≥baseline−0.05. It passes, so `pilot_cns/s0` remains final. This rule has no minority/Portscan/Infiltration preservation clause. Full raw/deduplicated results and trade-offs are in [CIC evidence](cic_evidence.md).

Historical vectorized A0 compute is 0.4–0.8 µs/flow versus 3.7–10.8 for IsolationForest; these are batch timings, not per-flow service latency. ToN timing and resource scope are documented separately.

HCE-Boost/hierarchical labeling informed probability-preserving abstention, not an algorithmic novelty claim. HICID was not fully accessible; dynamic-graph methods do not resolve measured label/support limits and introduce host-shortcut concerns. PCAP expansion did not pass its separate feasibility study. These directions are not part of the final runtime and are not claims of superiority to those methods.
