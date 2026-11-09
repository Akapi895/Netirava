# Supplementary ToN-IoT experiment protocol

**English translation of the original locally frozen plan, dated 2026-11-09 in its heading.** Original bytes are archived and mapped in [provenance](README.md). `FROZEN_PLAN.json` records 2026-11-08T17:24:16Z, before the single fit; local date/UTC differ. It was not committed at execution time. This later translation is not the frozen original and does not replace its checksum.

Final CIC `pilot_cns/s0` and its demo remain unchanged.

## 1. Questions and intended scope

Primary: what detection/classification quality, particularly for minorities, does a locked recipe achieve on declared ToN test cohorts at a benign-calibrated operating point? Secondary: which attack episodes reach the source-incident queue and how many false incidents are reviewed?

Scope narrowed before fit: Backdoor/mitm/ransomware have temporal holdout within the same campaigns and attacker hosts; injection/password/xss were described as unseen-attacker tests; scanning uses a second temporal block with mostly shared hosts. No new-attacker minority robustness, comparative class-weighting effect, or cross-network transfer claim.

**Translation note, not a retroactive protocol change:** later audit shows “unseen” for injection/password/xss means relative to same-class training, not all training. The corrected global shares are in [ToN results](../ton_iot_evaluation.md).

## 2. Source and transformations

- `datasets/NF-ToN-IoT-v3/NF-ToN-IoT-v3.csv`, SHA-1 `24854ca3072ab7c2ade9ebfb202345a666a94cfe`, BagIt match; 27,520,260 flows, April23–29,2019, matching UQ counts.
- Source terms refer to UQ DOI 10.48610/44d7c5e; do not redistribute source data as part of this experiment.
- Flow identity: one row. Exact fingerprint: timestamps+source/destination+49 features, excluding label. Feature fingerprint: 49 inputs. Episode: label+src+dst, >30-minute gap.
- No documented session boundaries; use per-class temporal blocks and attacker groups for the stated limited independence.
- Audit: zero null/inf/negative/constant features or binary-label disagreement; 1,816,137 exact duplicate rows; zero exact-fingerprint label conflicts.
- Derived processing: exact dedup keeping first; deterministic training Bernoulli sampling with `p=min(1,cap/n)` and splitmix64(row_id,2026), expected caps Benign2,000,000 / other300,000; test/calibration retain natural selected-cohort prevalence; features cast float64. No imputation or relabeling.

The original wording called these caps maxima; the formula is preserved and yields expected rather than absolute caps, clarified in the results.

## 3. Split

Train heads and test tails of each class block with purge gaps. Cuts align to subattack boundaries for injection/password/xss; scanning block2 is test. Calibration April23 17:00–April24 02:00, 798,732 benign flows. No early stopping/validation set.

Pre-fit dependence measurements: 33 train flows end after their windows; test/train 5-tuple overlap ddos58%, dos42%, mitm27%, ransomware13%, Backdoor3%, injection/password/xss0%. This is not a globally chronological validation design.

## 4. Taxonomy and severity

Fine labels: Benign, scanning, dos, ddos, injection, xss, password, Backdoor, ransomware, mitm. Family mapping:
- Scan={scanning}; DoS={dos,ddos}; Web={injection,xss};
- Credential={password}; Malware={Backdoor,ransomware}; MITM={mitm}.

DoS/Web/Malware permit abstention at τ=0.8. Other families are single-class; confidence1 is not certainty. Fine severities: ransomware5, Backdoor5, injection4, xss4, password4, mitm4, ddos3, dos3, scanning2, Benign-argmax4. Family severities: DoS3, Web4, Malware5.

Minority=<1% of deduplicated attack train **before sampling**: Backdoor0.68%, mitm0.06%, ransomware0.05%. Test supports: Backdoor63,655/61 episodes, mitm1,978/115, ransomware903/6, with limited diversity.

## 5. Single-fit recipe

CatBoost MultiClass, 49-feature `nfv3-49-allowlist-v1`, GPU, seed0, 1,000 trees, depth6, L2=3, border254, Bayesian bootstrap, Plain boosting, Balanced class weights. No SMOTENC, HPO, or early stopping. Fixed learning rate0.111327 is a declared deviation from A0's CPU learning-rate probe, which would consume another fit. `FIT_STARTED.json` blocks a second fit; on failure log and stop without retry.

## 6. Calibration

`attack_score=1-p(Benign)` is a decision score, not calibrated probability. Threshold is the smallest value with benign calibration share `score≥threshold`≤α. Primary α=0.1%, secondary0.05%/0.5%/1%. All have at least ten expected calibration FP for nominal counting resolution.

## 7. Locked replay, triage, and evaluation

- Completed-flow replay per test window, one run/segment; primary threshold α=0.1%; source+15-minute cooldown; FIFO notification30/hour.
- Primary review severity, B=10/hour; comparators FIFO/volume/severity, B10/30, α0.1%/0.5%/1%, common alerts/budget.
- Flow metrics per segment/pooled: argmax P/R/F1, macro/weighted-F1, balanced accuracy/confusion; FPR and class recall at α; per-class AUROC/AUPRC versus benign; threshold-and-correct-class end-to-end recall.
- Predeclared sensitivity: same metrics on test 5-tuples absent in training.
- Incidents: alert/incident counts, compression, false incident counts, precision@B, strict/case episode coverage, types surfaced, time to first review; exposure=sum declared window durations.
- Uncertainty: flow Wilson with IID assumption; episode bootstrap for minority recall from stored outputs.

## 8. Descriptive conclusion rules

FPR maintained only if benign FPR≤2α in every segment. A class is “detected” if binary recall≥0.8 at α=0.1%, “classified” if whole-test argmax F1≥0.8. Support<100 is strongly limited; <30 INCONCLUSIVE. Minority statements include within-campaign/same-attacker scope. Do not retrain to fix unfavorable results. One fit/seed provides no seed-variability estimate.

Post-fit precision/F1 reporting after the gate is additional interpretation, not an alteration of these original success rules or a new model-selection test.
