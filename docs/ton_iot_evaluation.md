# Supplementary NF-ToN-IoT-v3 evaluation

## 1. Purpose and outcome

A **separate ToN model** runs the full pipeline: audit→prepare/split→one fit→calibration→completed-flow replay→source-incident triage→evaluation→UI. It does not replace `pilot_cns/s0` and is not evidence that a CIC checkpoint transfers successfully.

| Question | Finding |
|---|---|
| Does the pipeline run end-to-end? | Yes: nine test runs and AppTest on real replay data |
| Is the 0.1% FPR target maintained? | Pooled **0.0918%**, but **4/9 segments exceed 2α**; the per-segment rule fails |
| Are minority results encouraging? | After-gate Backdoor P/R/F1 **1.000/0.903/0.949**, ransomware **0.987/0.864/0.921**, mitm **0.756/0.663/0.707**; within-campaign only |
| Is detection complete? | Pooled binary recall **33.29%**; most XSS and scanning traffic is missed |
| Is new-campaign minority robustness established? | No |
| Does severity beat other queue policies? | Not distinguishable: B=10/hour is never binding |

Original outputs: `runs/ton_iot/{LEDGER_TON,EVALUATION_TON,SENSITIVITY_TON,UI_SMOKE}.json`. The versioned [evidence JSON](ton_iot_evidence.json) is an additive post-fit report from those saved scores, not a new selection experiment.

## 2. Frozen plan, data integrity, and transformations

The original Vietnamese protocol was frozen locally at **2026-11-08T17:24:16Z**; the fit marker is **17:24:35Z**. Config/protocol/data hashes are in `artifacts/ton_iot_v1/FROZEN_PLAN.json`. This is local timestamp/checksum evidence, not an independently witnessed registration. The [English protocol](protocols/ton_iot.md) is a later translation; original bytes and their [manifest](protocols/originals_manifest.json) are retained outside Git. Current documentation-reference changes are not presented as frozen original hashes.

GO at the pre-fit gates permits running the experiment; it is not a finding that the model meets every performance target. Minority claim scope was narrowed to within-campaign before fit.

Raw CSV: **27,520,260 rows**, 5,302,886,266 bytes, SHA-1 `24854ca3072ab7c2ade9ebfb202345a666a94cfe`, BagIt match. All seven source files retain before/after checksums, sizes, and mtimes; no dataset-directory files were added. Source terms: [UQ catalog](https://staff.itee.uq.edu.au/marius/NIDS_datasets/), [dataset record](https://researchdata.edu.au/nf-ton-iot-v3/3485175).

Streaming audit finds zero null/inf/negative/constant features, binary/fine-label disagreements, or END<START; **1,816,137 exact duplicate rows** and **zero exact-fingerprint label conflicts**. This does not independently validate all labels.

| Class | Raw rows | Unique exact fingerprints | Unique model-input fingerprints |
|---|---:|---:|---:|
| Benign | 16,792,214 | 15,078,514 | 7,934,215 |
| ddos | 4,141,256 | 4,141,256 | 1,088,019 |
| xss | 2,834,435 | 2,834,435 | 2,825,122 |
| password | 1,594,777 | 1,594,777 | 1,486,543 |
| scanning | 1,358,977 | 1,358,977 | 837,492 |
| injection | 381,777 | 381,777 | 380,936 |
| dos | 203,456 | 203,456 | 200,884 |
| Backdoor | 203,384 | 101,692 | 97,897 |
| mitm | 6,013 | 5,268 | 5,055 |
| ransomware | 3,971 | 3,971 | 3,530 |

Derived data removes exact duplicates, casts features to float64, and samples **training only** with `p=min(1,cap/n)`, seed 2026. Expected caps are 2 million benign and 300,000 per attack class; Bernoulli sampling is not an absolute row limit. Labels are unchanged; test/calibration are not balanced. Train **3,609,062**, calibration **802,501** including 798,732 benign, test **10,202,874**, with **50.8% attack prevalence**.

## 3. Split and host-novelty correction

FLOW_START windows are half-open. Training uses attack-block heads, then gaps and test tails. There are no documented capture-session boundaries. This is **retrospective per-class temporal holdout**, not global future-only validation: some training blocks occur after earlier test/calibration blocks. Runtime replay remains causal by FLOW_END.

| Class | Test flows | Test episodes, label+src+dst, gap 30m | Global-unseen-source flow share | Test 5-tuples seen in train |
|---|---:|---:|---:|---:|
| injection | 62,391 | 28 | **41.73%** | 0% |
| password | 116,842 | 21 | **73.77%** | 0% |
| xss | 2,271,774 | 57 | **55.47%** | 0% |
| scanning | 1,096,536 | 581 | about 0.0052% | 0.6% |
| ddos | 1,486,698 | 63 | below 0.001% | 58% |
| dos | 82,455 | 42 | 0% | 42% |
| Backdoor | 63,655 | 61 | 0% | 3% |
| mitm | 1,978 | 115 | 0% | 27% |
| ransomware | 903 | 6 | 0% | 13% |

**Post-fit correction:** original split auditing compares test sources with training sources **of the same class**. Injection/password/xss are 100% novel only under that definition. The table compares with **all fitted training rows**, including benign and other classes; results also match when both training endpoints are checked. Do not describe all three cohorts as globally host-disjoint. The translation preserves the original assertion and explicitly points to this correction.

Minorities are classes below 1% of attack training flows **after deduplication, before sampling**: Backdoor 0.68%, mitm 0.06%, ransomware 0.05%. Thirty-three training flows end after their training-window boundaries, but none reaches the corresponding test-window start. A shared 5-tuple is a dependence risk, not proof of the same continuous connection.

## 4. Model and calibration

Checkpoint `42b82c1d80ed`: CatBoost 1.2.10 MultiClass GPU, 1,000 trees, depth 6, L2=3, border count 254, Bayesian bootstrap, Plain boosting, seed 0, Balanced weights. No SMOTENC, HPO, early stopping, or CPU probe. Fixed learning rate **0.111327** was declared before fitting using the resolved CIC value.

One approximately **83.7-second fit**; `FIT_STARTED.json` refuses another. No validation set was used because there is no early stopping. Benign calibration is separate:

| Target α | Threshold | Realized calibration FPR |
|---|---:|---:|
| 0.05% | 0.996092 | 0.0458% |
| **0.1%** | **0.995843** | **0.0988%** |
| 0.5% | 0.995588 | 0.3407% |
| 1% | 0.995026 | 0.9990% |

Score ties can leave some budget unused. Calibration benign-score median is 0.1885; its high tail yields a near-one threshold. One arm cannot isolate class weighting as the cause. Score is not a calibrated attack probability.

## 5. Flow-level results

- Binary recall **33.285%** = 1,725,249/5,183,232 attack flows.
- Binary precision **99.734%**, conditional on 50.8% attack prevalence.
- FPR **0.0918%** = 4,609/5,019,642 benign; Wilson IID interval [0.0892%,0.0945%].
- Whole-test argmax macro-F1 0.667, weighted-F1 0.865, balanced accuracy 0.900; these are not end-to-end gate performance.

| Class | Argmax F1 | Binary recall | After-gate precision | Correct-class end-to-end recall | After-gate F1 |
|---|---:|---:|---:|---:|---:|
| scanning | 0.444 | **0.0000246** | undefined | 0 | 0 |
| dos | 0.487 | 0.513 | 0.340 | 0.509 | 0.408 |
| ddos | 0.981 | 0.910 | 0.997 | 0.909 | 0.951 |
| injection | 0.690 | 0.863 | 0.856 | 0.846 | 0.851 |
| xss | 0.949 | 0.067 | 0.995 | **0.028** | 0.055 |
| password | 0.975 | 0.553 | 0.994 | 0.553 | 0.710 |
| Backdoor | 0.994 | 0.903 | 1.000 | 0.903 | **0.949** |
| ransomware | 0.146 | 0.865 | 0.987 | 0.864 | **0.921** |
| mitm | 0.114 | 0.663 | 0.756 | 0.663 | **0.707** |

Recall columns are ratios, not percentages. Scanning has about 27 binary detections (0.00246%) but **zero emitted scanning predictions**. After-gate fine metrics are threshold+argmax **before family abstention**. Ransomware has 9,306 benign argmax confusions before the gate, but only 790 emitted ransomware predictions, of which 780 are correct, among 903 true ransomware flows. Both levels must be reported.

### FPR by segment

| X01 scan | X02 dos | X03 injection | X04 ddos | X05 password | X06 xss | X07 ransomware | X08 Backdoor | X09 mitm |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.024% | **0.268%** | **0.915%** | 0.194% | **0.604%** | 0.030% | 0.128% | 0% | **1.084%** |

The `FPR≤2α` rule fails in four segments. Increasing α to 1% only raises XSS binary recall from 0.067 to 0.128. No threshold is reselected on test data.

### Uncertainty and family output

Episode-bootstrap binary-recall intervals: Backdoor [0.00,0.90], ransomware [0.28,0.90], mitm [0.47,0.73], password [0.01,0.78]. Backdoor alerts only **1/61 episodes**, demonstrating dependence on a large episode. Ransomware has six episodes. Neither row-IID Wilson nor within-campaign bootstrap establishes new-campaign robustness.

Of 1,729,858 alerts, 1,613 fine labels are withheld for uncertainty, all in Web. DoS/Web/Malware allow abstention; Scan/Credential/MITM have single fine classes. A within-family confidence of one is not validated certainty.

## 6. Incident-level results

| Segment | Exposure | Flow alerts | Source incidents | False | Strict episode coverage@10 |
|---|---:|---:|---:|---:|---:|
| X01 scanning | 4.25 h | 740 | 14 | 8 | 0.138 |
| X02 dos | 3.50 h | 42,447 | 5 | 2 | 0.750 |
| X03 injection | 0.75 h | 53,957 | 3 | 1 | 1.000 |
| X04 ddos | 5.00 h | 1,356,209 | 13 | 3 | 0.833 |
| X05 password | 0.95 h | 64,631 | 3 | 1 | 1.000 |
| X06 xss | 6.17 h | 152,141 | 4 | 2 | 0.667 |
| X07 ransomware | 1.92 h | 797 | 8 | 5 | 0.750 |
| X08 Backdoor | 13.50 h | 57,465 | 1 | 0 | 0.023 |
| X09 mitm | 1.42 h | 1,471 | 10 | 6 | 1.000 |
| **Total** | **37.45 h** | **1,729,858** | **61** | **28** | — |

Triage episodes use label+source with a 30-minute gap, unlike label+src+dst split/bootstrap episodes. Pooled reviewed-item precision is **33/61=54.1%**. All items fit within the budget, so policies choose the same set. Approximately 28,000 alerts/incident is record compression, not measured time saved. Exposure uses FLOW_START windows and may omit completed-flow tails.

## 7. Technical checks, cost, and UI

Stream contains no labels; role is dropped before the runtime contract. Saved detections cover exactly 10,202,874 test flows once; candidates equal threshold comparisons and checkpoint/stream hashes agree.

Local costs: audit 158 s, prepare 138 s, load train 9.3 s, fit 83.7 s, calibration 4.5 s, replay+monitor about 59.6 s, original evaluator 332 s. Compute µs/flow is vectorized timing, not a latency SLA. Fit RSS peak is about 3.6 GB; device-total GPU memory 6.8 GB includes other processes; replay RSS 7.3 GB is cumulative process memory.

Real-run AppTest on `ton_X09_mitm` checks model/threshold captions, source/campaign views, N/M review evidence, label consistency, and wrong-config handling. A historical feedback row has `confirmed_by=ui-smoke-test`, not human-analyst provenance. The newer `ui-check` does not submit feedback. The frozen config's rare-class placeholder omits Backdoor; UI explicitly says **Configured rare-class incidents**. Reporting minority definitions remain pre-sampling, not this display list.

Browser layout/analyst usability is unverified. ToN monitor tables are computed but reliability has not been evaluated.

## 8. Documentation changes and reproduction

Original `ton.py` frozen prefix length is **26,210 bytes**; 26,209 in an older note was a counting error. The pre-translation code/config/protocol copies are preserved in the original-document archive. Current English path/comment edits are documentation-only and are not claimed to have frozen original hashes. No checkpoint, data split, score, threshold, or method was changed.

```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava ton-report
& $py -m netirava ton-report --output docs/ton_iot_evidence.json
& $py -m netirava ui-check --config configs/ton_iot.yaml --run ton_X09_mitm
& $py -m netirava ui --config configs/ton_iot.yaml --run ton_X09_mitm
```

[Reproduction](reproduction.md) lists artifacts and separates report recomputation, checkpoint replay, and new fitting. Do not remove the fit marker to bypass the single-fit guard.
