# Family-aware classification and incident triage

## 1. Probability-preserving label abstention

`family.py` is shared by replay, UI, export, and evaluation. The probability vector, `p(Benign)`, family mass, binary alert, and source incident assignments are unchanged. Only an argmax class inside a configured ambiguous family can lose its fine label:

```text
keep fine label if p(argmax class) / sum p(classes in family) >= tau
otherwise emit "<family> attack — fine class uncertain"
```

τ=0.8 was fixed before measuring risk–coverage. Incident labels use the joint modal `(family,fine_label)` pair, avoiding inconsistent independent modes. Uncertain flows receive family severity, not the withheld class's severity. `fine_confidence` is a within-family share; a value of 1 in single-class families is not validated certainty.

### A0 v2 results, not final-pilot detection gains

On K5 original labels, 1,796 flows, family precision/recall/F1 is 0.966/0.865/0.913. Among Web-family predictions:

| τ | Fine-label coverage | Accuracy when emitted | Wrong fine labels, argmax baseline 344 | Uncertain |
|---|---:|---:|---:|---:|
| 0.5 | 0.605 | 0.887 | 77 | 446 |
| 0.7 | 0.567 | 0.916 | 54 | 489 |
| **0.8** | **0.562** | **0.918** | **52** | 495 |
| 0.9 | 0.553 | 0.920 | 50 | 505 |
| 0.95 | 0.546 | 0.932 | 42 | 513 |

The 344→52 reduction trades away 43.8% of fine predictions; it does not improve detector recall. On adapted-label K5, the same A0 v2 family precision/recall is only 0.033/0.196. Across the full stream most wrong predictions are benign flows called Web, which abstention cannot fix. The pilot's small within-episode web evaluation has no incremental fine-label error reduction to establish.

Tests verify probabilities/alerts remain unchanged at different τ values. Real A0 v2 replay retains 166,636 alerts and 238 incidents with identical decision hashes. See [invariance provenance](experiment_registry.md).

## 2. Source incidents, notification, and review

- **Incident:** same source IP, ≤15-minute gap between consecutive alert candidates. A long stream can keep one incident open for hours. State resets per segment.
- **Notification:** runtime FIFO budget of 30 new incidents per clock-hour in the final configs. Excess notifications are logged separately.
- **Review queue:** one common function in `campaign.review_queue`; an item competes in its opening hour and is reviewed at that hour's end. B is typically 10 or 30 items/hour.
- **FIFO:** earliest opening; **volume:** most alerted flows up to review; **severity:** highest family-aware severity up to review, then volume.
- **Evidence:** queue ranks use prefixes only. The UI distinguishes `n_at_review`/`severity_at_review` from lifetime totals and offers review-time-only details with N/M truncation.
- **Feedback:** append-only, latest verdict displayed, correction must reference the same alert. It is an audit log, not a learning loop.

UI/export read no ground-truth labels. A stream/config provenance mismatch is blocked before joining destination metadata. A missing run under a wrong config is reported rather than crashing. Source incident is the default; campaign remains experimental.

### Historical source-queue evidence

| Scenario/model/α | Flow alerts | Incidents | Episode coverage@10/hour, FIFO→volume | Scope |
|---|---:|---:|---|---|
| H1 DDoS, A0 v1, 0.5% | 71,774 | 175 | 0/10→10/10 | EXP; volume rule introduced after FIFO failure |
| H1 DDoS, A0 v1, 1% | 77,062 | 317 | 0/10→10/10 | EXP |
| DEV Bot, V4b, 1% | 121,353 | 266 | 0/8→8/8 | Development; V4b later rejected on H1 |
| Known, A0 v2, 0.1% | 164,781 | 161 | 0.148→0.137, @30=0.306 | DEV |

Severity does not outperform volume overall on DEV (episode coverage@30 around 0.311 vs 0.313). Compression reduces records, not proven analyst work. Historical lifetime-ranking results are not automatically evidence for the later causal queue.

## 3. Campaign correlation and NO-GO result

The [ops protocol](protocols/ops_study.md) links source incidents by destination host plus predicted family, treating argmax Benign as Unknown. At opening, an incident joins an active campaign if its key has activity within 15 minutes; later flows register additional free keys. Existing campaigns are never merged. A destination-only ablation is reported.

The original open-once review design hid a later SQLi episode inside an old campaign on DEV. A documented pre-holdout amendment (`9ab983c`) introduced **campaign updates per source-incident opening hour**; both versions remain evaluated.

At α=0.1%, severity, B=10, original labels:

| Model | Scenario | Source→campaign review items | False items | Strict episode coverage | Contamination |
|---|---|---|---|---|---|
| A0 v2 | H5 HOIC | 46→5 | 36→4 | 0.80→1.00 | 0 |
| A0 v2 | H6 | 44→8 | 18→5 | 0.033→0.116 | 0.61 |
| A0 v2 | H9 | 75→12 | 74→11 | 0→0.05 | 0.05 |
| Pilot | H5 | 24→7 | 14→6 | 1.00→1.00 | 0.57 |
| Pilot | H6 | 19→16 | 16→14 | 0.011→0.017 | 0.13 |

Pooled H5–H9: A0 v2 254→41 items, pilot 156→81. Reducing false review items does not reduce false-positive flows; some benign sources are absorbed into attack campaigns. The ≤5% contamination rule fails for both models (original-label pooled rates about 6.9–7.0%; corrected A0 about 5.07%). Pilot also has no H5 coverage gain. **NO-GO:** source queue remains primary.

Strict coverage requires an attack flow before review; case-attached coverage also counts later case updates. Exposure is the declared window duration, not the number of occupied clock-hour bins. Counts remain the primary workload evidence.

## 4. Formative task with one LLM reviewer

Original preregistration commit `d368fdc`, translated [clean-ablation/task protocol](protocols/clean_ablation.md). Source: final CIC pilot, H5–H9 run `20261108T211057_a0_fast`, α=0.1%, already used in model selection, therefore exploratory.

- C0: four highest-score alerted flows per segment, one flow per card.
- C1: first four source incidents by review time/severity rank per segment; review-time context and five example flows.
- Twenty decisions per condition. IP tokens replace real IPs, dates/truth hidden, answers opened after verdicts were saved. C1 precedes C0; order is not fully counterbalanced in this single-reviewer run.
- Reference: at least one attack-labeled flow in the card/review-time evidence; adapted labels on audited days, otherwise original labels. Infiltration remains questionable.

| Measure | Flow-score queue | Incident workflow |
|---|---:|---:|
| Attack-containing items | 4/20 | 5/20 |
| Source-defined attack episodes surfaced | 1 | 5, four from the same HOIC scenario |
| Attack types surfaced | 1 | 2 |
| Benign items opened | 16 | 15 |
| Correct verdicts | 20/20 | 18/20 |
| False attack verdicts / missed attack items | 0 / 0 | 2 / 0 |
| Correct family on attack items | 0/4 | 4/5 |
| LLM time | 17 s | 20 s |

The two false verdicts involve scanning-like sources labeled Benign; the task cannot adjudicate reviewer error versus background scans. Conditions change grouping, ranking, and available context together. Results do not isolate any one module or establish human efficiency.

### Human-task kit

```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava task-make --config configs/ops_holdout.yaml --run 20261108T211057_a0_fast --out runs/triage_trial_human
& $py -m netirava task-run --task runs/triage_trial_human --cond C1 --reviewer participant1
& $py -m netirava task-run --task runs/triage_trial_human --cond C0 --reviewer participant1
& $py -m netirava task-score --task runs/triage_trial_human --verdicts verdicts_C1_participant1.csv verdicts_C0_participant1.csv
```

With multiple participants, counterbalance order, record experience, and retain the formative label. No human trial has been completed here.

## 5. ToN and product scope

ToN compresses 1,729,858 alerts into 61 incidents, 28 false; pooled review precision is 54.1%. B=10/hour never binds, so ranking policies select the same items. It validates pipeline execution, not prioritization superiority. Full flow/episode/incident results are in [ToN evaluation](ton_iot_evaluation.md).

AppTest validates rendering logic on real replay data. It does not establish browser layout, accessibility, analyst usability, time savings, or deployed impact. Feedback from `ui-smoke-test` is explicitly test provenance, not analyst confirmation.
