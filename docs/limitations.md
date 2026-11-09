# Limitations and claim boundaries

This document qualifies the [final report](final_report.md). CIC and ToN checkpoints are fitted separately; their results are not accumulated into a single model's performance.

## 1. Limits to state in the presentation

1. **Minority generalization is unconfirmed.** CIC credible eval support is Web/XSS/SQLi 27/15/2 unique flows from the training episodes. ToN minorities have more flows but remain within-campaign; ransomware has six episodes.
2. **The detection gate determines operational output.** ToN pooled binary recall is 33.29%. XSS argmax F1 is 94.86%, but correct-class after-gate recall is 2.81%.
3. **FPR is not stable across segments/environments.** ToN pooled FPR is 0.0918%, but four of nine segments exceed 2α. Frozen CIC pilot FPR is 24–27% on UNSW at a 0.1% target.
4. **Flow counts are not independent situations.** ToN Backdoor flow recall is 90.3%, but only one of 61 label+src+dst episodes has an alert.
5. **Operational impact is still proxy evidence.** Queue/evidence/feedback work, but there is no human analyst study. ToN never saturates B=10/hour and cannot establish a ranking advantage.

## 2. Data, labels, and independence

| Issue | Scope and consequence |
|---|---|
| CIC label quality | Only 6.9% of published web rows match adapted credible rules; this does not prove the rest benign. Corrections include approximations and cover only three dates. |
| XSS conflicts | 480 rows contain 460 exact fingerprints; 440 also carry another label. The old “20” is the exclusive/keep-first count, not the total number of distinct XSS-labeled flows. |
| Experiment-specific dedup | Historical pilot/A0/ops retain duplicates; FE and clean ablation remove them; the ledger reports both. ToN derived data deduplicates without editing raw. |
| Retrospective split | Some CIC/ToN train windows occur after earlier test/calibration windows. Causal replay does not make the study globally future-only. |
| Pilot K5 overlap | K5 replay contains pilot-training rows; the headline ledger filters evaluation rows. |
| ToN source novelty | Global-unseen-source shares are injection 41.73%, password 73.77%, xss 55.47%. The 100% claim applies only relative to same-class training. |
| Connection dependence | Shared test/train 5-tuples are common for ddos/mitm. A repeated tuple need not be the same connection. Novel-tuple sensitivity does not create new campaigns. |
| Original ToN truth | No exact-fingerprint label conflicts were found; labels were not independently validated in full. |
| Selection history | H1–H9 are consumed. H5–H9 selected the pilot by a prior rule and are no longer a post-selection untouched test. |

## 3. Modeling and uncertainty

- **SMOTENC effect is not established:** original-label gains do not become a clear minority benefit after label auditing/deduplication. Three seeds with the same sign are not statistical significance.
- **ToN has one fit/seed and no treatment control:** class weighting is neither proven superior nor isolated as the cause of the benign-score tail.
- **CIC is a package comparison:** label policy, web split, and refitting change together; it does not identify a pure relabeling effect.
- **After-gate fine metrics are not family-layer gains:** ransomware P/R 98.73%/86.38% is threshold+argmax before abstention. The 344→52 family-label error reduction belongs to A0 v2, not final-pilot detection.
- **Uncertainty reflects its sampling unit:** flow Wilson assumes IID. Episode bootstrap remains within the observed campaigns and can be unstable with few, unevenly sized episodes.
- **Precision is prevalence-sensitive:** ToN binary precision 99.73% is measured at 50.8% attack prevalence, not a real-network base rate.
- **Decision scores are not calibrated attack probabilities.** Low-FPR threshold calibration is not probability calibration.

## 4. Triage and operational limits

| Issue | Status |
|---|---|
| Source grouping | Consecutive candidates can keep one source incident open for hours, merging multiple episodes. Source identity is not campaign identity. |
| Review lifecycle | Review occurs at the end of opening hour; full backlog/re-review behavior is absent. Rank is causal, but some displayed totals/labels are lifetime summaries with scope labels. |
| ToN budget | All 61 incidents fit the budget; no policy wins under demonstrated overload on this source. |
| Formative trial | One LLM reviewer, 20 decisions/condition, multiple simultaneous condition differences; no isolated module effect or human efficiency estimate. |
| Campaign correlation | CIC NO-GO due to contamination; experimental view only. |
| Monitor | Pilot CIC holdout correlation is 0.06; UNSW 99/99 flags are exploratory; ToN monitor reliability not evaluated. No automatic threshold/model updates. |
| Feedback | Append-only audit, not adaptive learning. A ToN smoke-test row is not an analyst verdict. |
| UI validation | AppTest checks logic, not browser layout/accessibility or analyst usability. |
| Performance | Batch-compute µs/flow is not single-flow latency or SLA; load/sort/persist remain RAM/I/O dependent. |

## 5. Provenance and reproduction

The original ToN plan has local timestamps/hashes before fitting, not an external timestamp authority. English protocols are later translations, not the frozen originals. Original document/code/config copies and hashes are preserved in `artifacts/documentation_originals/`; include the required originals with a provenance bundle. Historical manifests are unchanged even when a document path is renamed.

Large data/checkpoint/run artifacts are outside Git; a clone alone cannot reproduce the real UI or evaluation. Synthetic fixture fits in tests are not additional ToN research fits. `FIT_STARTED.json` and `n_fits=1` provide local guarding/logging, not an independent audit of all machine activity.

## 6. Rejected directions and allowed conclusion

V4b fails H1; shortcut-drop fails H3/H4; clean SMOTENC benefit remains unconfirmed; campaign merging fails contamination rules; monitor failure prediction remains inconclusive. PCAP/GNN and other stopped directions do not establish SOTA or solve the minority information gap.

**Supported conclusion:** a working replay prototype with reproducible conditional results and explicit trade-offs. **Unsupported:** robust performance on every minority/new network, zero-day protection, SOTA, adaptation, analyst-hours saved, or deployment readiness.
