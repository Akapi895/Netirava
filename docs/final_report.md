# Netirava: final submission report

## Executive summary

Netirava addresses **Network Intrusion Detection with Imbalanced Threat Data** through data auditing, completed-flow CatBoost detection, benign-only threshold calibration, family-aware label abstention, and budgeted incident triage. Its contribution is an evaluated application design, not a new learning algorithm or a live-network deployment.

Three evaluations serve different purposes: **CIC-2018** is the primary system; **UNSW** tests frozen CIC checkpoints in another environment; **ToN-IoT** uses one separately fitted checkpoint to test pipeline reuse. Their results are not combined into the performance of a single model.

The CIC pilot reduces false source incidents from **217 to 143** and increases HOIC recall from **3.6% to 81.3%**, while degrading Infiltration and Portscan recall. On ToN, ransomware after-gate precision/recall is **98.73%/86.38%** within one campaign, but overall binary recall is **33.29%** and **4/9 segments** violate the declared FPR bound. Minority robustness across new campaigns is not established.

## 1. Problem, outputs, and research questions

[DN-CY-01](https://datanovathon.com/problems/gamswulvrvtidne) asks for a detection model with robust minority-class performance and an alert-triage interface. Suggested technologies are not evidence that an algorithm is mandatory or effective. Submission deadlines and scoring weights must follow the organizer's applicable round announcement; this report does not assume unverified numeric rubric weights.

| Output | Unit and measurement |
|---|---|
| Detection/classification | Flow-level FPR, recall per class, argmax and after-gate precision/recall/F1, support, uncertainty |
| Triage | Source incidents and reference episodes: false-item count, precision@B, episode coverage@B, time to review |

A calibration FPR target is not a guarantee on another day. Flow-to-incident compression is not analyst-hours saved.

The research asks: what does the baseline miss; does label quality or imbalance treatment explain the failures; can feature or anomaly aggregation improve low-FPR detection; what does family abstention trade away; and what reaches the analyst under a fixed review budget? Detailed negative results are retained in [modeling](modeling.md), [triage](triage.md), and [monitoring/transfer](monitoring_and_transfer.md).

## 2. Method

1. **Audit data:** checksums, time/host coverage, exact/feature fingerprints, label conflicts, and auditable derived-label rules. Raw files remain read-only.
2. **Fit a detector:** 49 NetFlow v3 inputs without IPs, absolute timestamps, or labels. `attack_score = 1 − p(Benign)` is a decision score, not a calibrated attack probability. Select thresholds on benign calibration; primary α=0.1%.
3. **Abstain on fine labels:** retain probabilities and the binary decision. Emit a fine class only if its within-family probability share meets τ=0.8.
4. **Review incidents:** group by source IP with a 15-minute candidate gap; review at the end of the opening hour with primary B=10 items/hour. Ranking uses evidence available at review. Runtime FIFO notification budget 30/hour is separate.
5. **Keep provenance:** checkpoint/config/stream hashes, per-flow detections, incident state, and append-only feedback. Truth is available only to training, auditing, and evaluation. Monitoring never updates thresholds or models.

See [architecture](architecture.md) and [reproduction](reproduction.md) for implementation contracts and commands.

## 3. Evaluation design and independence

| Evaluation | Checkpoint and labels | Split and claim boundary |
|---|---|---|
| Primary CIC | `pilot_cns/s0`, `f964bde1ef5c`; CNS2022-adapted labels on audited days | Retrospective windows. H5–H9 were used by the declared model-selection rule. K5 replay includes some pilot-training rows; the evidence ledger uses eval rows only. Minority support is small and within-episode. |
| External UNSW | Frozen CIC pilot and A0 v2 | Two captures; no target-domain calibration or threshold tuning. Tests checkpoint transfer, not a new UNSW fit. |
| Supplementary ToN | `42b82c1d80ed`, Balanced class weights, original labels | One fit/seed. Per-class head/tail windows, not globally chronological. Minority tests remain within-campaign. Only part of the test traffic uses globally unseen sources. |

CIC protocols have recorded Git commits. The ToN plan has local timestamps/checksums before fitting, not an independently witnessed preregistration timestamp. English [protocols](protocols/README.md) are translations; original bytes and hashes are preserved separately. Post-fit reporting corrections do not reselect models, splits, or thresholds.

## 4. CIC: improvements with explicit costs

At α=0.1%, H5–H9, flow metrics after exact deduplication:

| Measure | A0 v2 → final pilot |
|---|---|
| FPR on 906,279 benign flows | **0.077% → 0.064%** |
| False source incidents | **217 → 143**, a 34.1% reduction |
| HOIC recall | **3.6% → 81.3%** |
| Infiltration recall | **19.5% → 1.2%**; labels on this date are not fully audited |
| Portscan S1 / Bot R1, DEV | Portscan **6.3% → 0.6%**; Bot **0 → 0** |

This is a comparison of **label/split/refit packages**, not an isolated causal effect of relabeling. Pilot training retained duplicates; raw/deduplicated evaluation is distinguished in the [CIC ledger](cic_evidence.md).

Credible minority evaluation contains only Web 27, XSS 15, and SQLi 2 unique flows from the training episodes. A scan of all 20.1 million rows finds no eligible unused, credible, independent minority cohort under the declared rules. Thus CIC does not establish minority robustness.

Clean ablation across three seeds on common labels/splits/features does not establish a minority benefit from SMOTENC; the tiny evaluation is nearly saturated for all arms. Earlier gains on original labels do not survive as convincing credible-minority evidence. Same-direction differences across three seeds are descriptive, not a statistical significance test.

## 5. UNSW: frozen transfer fails

The frozen CIC pilot produces FPR **24–27%** at the CIC-calibrated 0.1% target and attack-vs-benign AUROC **0.06–0.27**. A0 v2 also loses threshold reliability, with FPR about 2%. Differences in TTL, TCP windows, and service mix are consistent with shortcut/domain-shift risks, but are not isolated causal explanations.

The label-free monitor flags 99/99 windows. This question was introduced after inspecting detection results, so the finding is exploratory, not prospective evidence that the monitor predicted failure. Small-shift sensitivity remains unknown. See [monitoring and transfer](monitoring_and_transfer.md).

## 6. ToN-IoT: a second source after a separate fit

The source has 27,520,260 flows with unchanged published labels. Derived data removes exact duplicates and applies declared Bernoulli training caps; test windows retain their selected-cohort prevalence. Train: **3,609,062** flows; benign calibration: **798,732**; test: **10,202,874**. CatBoost Balanced uses seed 0 and 1,000 trees, one approximately 84-second GPU fit, without HPO or early stopping.

### Classification before and after the detection gate

After-gate metrics below mean `score ≥ threshold` plus **argmax**, before family abstention. Rejected attack flows remain false negatives.

| Class | Test support | Whole-test argmax F1 | After-gate precision | Correct-class end-to-end recall | After-gate F1 |
|---|---:|---:|---:|---:|---:|
| Backdoor | 63,655 | 0.994 | 1.000 | 0.903 | **0.949** |
| ransomware | 903 | 0.146 | 0.987 | 0.864 | **0.921** |
| mitm | 1,978 | 0.114 | 0.756 | 0.663 | **0.707** |
| xss | 2,271,774 | 0.949 | 0.995 | **0.028** | 0.055 |
| password | 116,842 | 0.975 | 0.994 | 0.553 | 0.710 |
| injection | 62,391 | 0.690 | 0.856 | 0.846 | 0.851 |
| ddos | 1,486,698 | 0.981 | 0.997 | 0.909 | 0.951 |
| scanning | 1,096,536 | 0.444 | undefined: no emitted scanning predictions | **0** | 0 |

Pooled binary recall is **33.29%** on 5,183,232 attack flows. Binary precision is **99.73%** in a test population with 50.8% attack prevalence. Pooled FPR is **0.0918%** on 5,019,642 benign flows, yet **4/9 segments exceed 2α**: dos 0.268%, injection 0.915%, password 0.604%, mitm 1.084%. The declared per-segment FPR rule fails.

Argmax F1 and AUROC cannot replace operating-point recall. Conversely, low whole-test ransomware argmax precision does not imply low emitted-alert precision: the gate removes most of those false predictions. The calibration benign-score tail is high and the threshold is 0.995843; one arm cannot isolate class weighting as the cause.

### Independence and effective sample size

- Backdoor/ransomware/mitm tests are within-campaign with mostly shared attacker hosts. Backdoor alerts cover only **1/61** label+source+destination episodes despite high flow recall. Ransomware has six test episodes.
- Injection/password/xss sources are new relative to **same-class** training, not all training. Global-unseen-source flow shares are **41.73% / 73.77% / 55.47%**.
- A repeated 5-tuple need not be the same connection. Novel-5-tuple sensitivity does not create independent campaigns.

The machine-readable [ToN evidence](ton_iot_evidence.json) is generated from stored scores by `ton-report`, a post-fit reporting correction without inference or method selection. See the [full ToN evaluation](ton_iot_evaluation.md).

## 7. Triage and application value

On ToN, **1,729,858 flow alerts become 61 source incidents**, including 28 false incidents; pooled reviewed-item precision is **54.1%**. Every attack type appears at least once. B=10/hour is never binding, so FIFO/volume/severity select the same set: no ranking advantage is established on ToN.

The CIC formative trial uses one blinded LLM reviewer and 20 decisions per condition: the incident workflow surfaces five source-defined attack episodes versus one for the flow-score queue; four HOIC sources belong to one scenario. Verdict accuracy is 18/20 versus 20/20. Conditions differ in several ways, so neither grouping, ranking, nor family labels receive isolated credit. LLM timings do not measure human analyst time. See [triage](triage.md).

The UI supplies review-time evidence, N/M truncation, append-only feedback, and provenance guards. AppTest covers real replay data, but no browser-based analyst usability study or analyst-hours saving has been established.

## 8. Rejected and unresolved hypotheses

| Direction | Outcome |
|---|---|
| Anomaly aggregation V4b | Rejected on H1; not an established detector improvement |
| Shortcut-removal feature candidate | Development gains fail to hold on H3/H4 |
| SMOTENC for credible minorities | No clear benefit on the clean ablation |
| Family-aware labels | A0 v2 fine-label errors 344→52 at reduced coverage; not a pilot detection gain |
| Campaign correlation | NO-GO due to contamination; experimental view only |
| Drift monitor | Not validated as a threshold-failure predictor, FPR estimator, or adaptation mechanism |

Negative results support research discipline; they do not substitute for successful effectiveness evidence. See [limitations](limitations.md).

## 9. Conclusion and handoff

Netirava is a working detection–classification–triage replay prototype with protocols, provenance, invariance tests, and conditional quantitative evidence. Some ToN minority after-gate results are encouraging; performance varies substantially across classes, segments, and episodes. Generalization to new minority campaigns remains unconfirmed.

The CIC checkpoint remains the primary demo. ToN is supplementary. There is no claim of a new algorithm, SOTA, zero-day protection, automatic adaptation, deployed SOC readiness, or analyst-hours saved. Code, configurations, reports, and small evidence files are versioned; large checkpoints and replay outputs require the separate [artifact handoff](reproduction.md). No additional fitting is needed to use the results in this report.
