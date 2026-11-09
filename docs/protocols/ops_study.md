# Ops-study protocol: correlation and drift monitoring

**English translation of the original pre-registration, dated 2026-11-08, commit `e1b473a`.** This translation is not the committed original. Byte-preserved originals and hashes are described in the [protocol index](README.md). Results, deviations, and measurement corrections are reported separately; prospective statements below describe the original plan.

The original document was committed before implementing/evaluating the two additions. H5–H9 were chosen only from hourly/five-minute label support, not detector scores. Conceptual references include NoDoze (contextual triage), CADE, Thirumuruganathan et al., and Rabanser et al.'s black-box shift detection. No algorithm is copied: Netirava has neither a provenance graph nor a newly trained representation.

## 0. Scope

| | Correlation | Monitoring |
|---|---|---|
| Position | After detector, before review queue | Parallel diagnostic branch |
| Change binary alerts/model/threshold? | No | No; warning only |
| Intended benefit | More attacks reviewed at equal budget | Warn that a fixed threshold may be unreliable without labels |
| Unsupported claim | Lower FPR or additional attack-flow detection | Lower FPR or zero-day detection |

## 1. Research questions

- **RQ-C1:** with the same alerts, policy, and B items/hour, do causal destination+predicted-family campaigns improve episode/flow/risk-weighted coverage over source-IP+15-minute-cooldown incidents?
- **RQ-C2:** do campaigns hide low-volume attack types or delay first review?
- **RQ-C3:** how many benign-only incidents are absorbed into attack campaigns, how much over-merging occurs, and how many false items remain?
- **RQ-D1:** which label-free feature/score PSI, alert-rate, and sub-threshold-tail signals track realized FPR over time?
- **RQ-D2:** how many exceedance windows are detected, and what is the monitor's false-alarm rate, separating benign-only/attack-containing windows?
- **RQ-D3:** does α×TR approximate realized FPR in log10 error?
- **RQ-D4:** does the monitor flag unknown-family HOIC/Infiltration? Report as distribution drift, not evidence of FPR estimation.
- **RQ-M:** how do frozen A0 v2 and `pilot_cns/s0` compare on H5–H9 FPR, false source incidents/hour, and HOIC/Infiltration recall? This is the pilot's first evaluation on those unused windows.

## 2. Data roles

| Data | Role |
|---|---|
| K1–K5, S1, R1 | Repeatedly used development data, DEV |
| Consumed H2 | EXP only, not parameter selection |
| H5, Feb 21 18:05–18:35 | HOIC, ten sources/one destination, begins about 18:11 |
| H6, Mar 1 14:00–15:00 | Unused date, hour with greatest Infiltration support |
| H7, Feb 16 19:00–20:00 | Benign-only unused hour |
| H8, Feb 20 19:00–20:00 | Benign-only unused hour |
| H9, Feb 28 19:00–20:00 | Same date as S1, three hours later |

H5–H9 use a separate derived namespace and are evaluated once for both models after `ops-v1-frozen`. Selection criteria: no overlap with demo/FE windows; multi-source unknown-family H5; unused-day H6; unused benign hours H7/H8; persistence of S1-like FP behavior in H9. Adapted labels exist only on February 22/28 and March 2; other dates retain originals. Exact duplicates are retained to preserve original demo semantics.

## 3. Locked correlation design

Input is alerted flows in decision order, with source-incident id, destination, and predicted family; argmax Benign maps to Unknown.

1. On a source incident's first flow, join the active campaign holding `(destination,family)` if that key has activity within 15 minutes; otherwise open a campaign.
2. Later flows register free keys for that campaign. Never merge two existing campaigns.
3. Reset per segment; no labels/future information.

Report destination-only key ablation without selecting it. The original review unit is source incident or campaign, opening hour determined by its first alert, review at that hour's end. Select B among items opened in the hour: FIFO by opening time, volume by flows available at review, severity by maximum family-aware severity then volume. Uncertain fine labels use family severity; Benign argmax uses severity 4. Existing class severities remain.

Evaluate B∈{10,30}, FIFO/volume/severity, α∈{0.1%,0.5%,1%}:
- workload: items, items/hour, false items/hour, flows/item, reviewed-item precision;
- strict source-episode coverage: label+source with >30-minute gaps and an attack flow decided before review;
- case-attached coverage: includes later flows in reviewed cases;
- strict attack-type coverage, where type=segment+label;
- attack-flow and risk-weighted episode coverage; weights Web4, BruteForce3, DoS3, DDoS4, Bot5, Infiltration5;
- time from each attack type's first flow to first covering review;
- multi-source campaigns, benign-only incident contamination, campaigns with ≥2 attack labels, fragmentation.

### Campaign GO rule

Primary A0 v2, α=0.1%, severity, B=10; also report other levels:
1. H5 strict-episode **or** attack-flow coverage improves by ≥0.05 absolute at an α with A0 HOIC alerts.
2. No attack type covered by source is lost by campaign on H5–H9 across B/policies at α=0.1%.
3. At most 5% of pooled benign-only source incidents are absorbed into attack campaigns.
4. Median first-review time is no more than 15 minutes later.

All four are required for campaign to become the default; otherwise source remains default and campaign is experimental context. No FPR-reduction claim in either case. The later campaign-update amendment is documented in [triage results](../triage.md), not inserted retrospectively into this original design.

## 4. Locked monitoring design

Reference: same-checkpoint C1, February 20 12:00–14:05. Store score quantiles, α thresholds, and feature bins in `drift_reference.json`.

Windows: 15 minutes by `decision_at`, aligned to segment start, at least 2,000 flows; one-window diagnostic delay. Signals:

| Signal | Original planned definition | Alarm |
|---|---|---|
| AR | fraction score≥tα divided by α | ≥2 and one-sided binomial p<0.001 |
| TR, primary | fraction `q_ref(1−10α)≤score<tα` divided by the nominal reference band 9α | ≥2 and p<0.001 |
| Score PSI | Reference deciles plus 0.95/0.99/0.999 bins | ≥0.25 |
| Feature PSI | Median across 49 features; numeric deciles, categorical top-20+other | ≥0.25 |

The sub-threshold band is hypothesized to be more statistically stable and less dominated by near-one attack scores. This is a hypothesis, not a result. The implemented/reference-band handling and conclusions are described in [monitoring](../monitoring_and_transfer.md).

Evaluator truth: realized benign FPR, windows with ≥5,000 benign flows, E=`FPR>2α`. Evaluate original/adapted labels, adapted primary where available; report K5 web scope mismatch separately.

Metrics: Spearman(signal,FPR) with window bootstrap CI, AUROC for E, exceedance recall, non-E alarm rate split by benign-only/attack-containing, median absolute log10 error for α×TR. Primary α=0.1%, plus 0.05%/0.5%/1%.

Monitor utility requires Spearman(TR,FPR)≥0.5 with lower 95% CI>0 **and** exceedance recall≥80% with non-E alarms≤20%, on pooled DEV+HO with HO reported separately. If fewer than five E windows exist, recall is INCONCLUSIVE. The UI may always show distribution indicators, but may not claim validated FPR estimation when these rules fail.

## 5. RQ-M selection rule

Recommend `pilot_cns/s0` only if pooled H5–H9 FPR≤A0 v2, false source incident rate≤1.5×A0 v2, and H5 HOIC flow recall≥A0 v2−0.05 at α=0.1%, adapted labels where available. Otherwise keep A0 v2. Report both models across all α values.

## 6. Required invariants and sequence

Correlation/monitor must not change candidates, source incidents, or decision hashes; campaign assignment is prefix-causal; monitor/UI read no truth; source/campaign use the same review function; uncertain incidents never inherit withheld XSS/SQLi severity.

Sequence: commit plan/config → implement/test/commit → DEV/EXP diagnostics with logged design deviations → `ops-v1-frozen` → prepare and replay both models on H5–H9 once → evaluate/report. Original report path was `docs/OPS_STUDY_RESULTS.md`; current consolidated destinations are [triage](../triage.md), [monitoring](../monitoring_and_transfer.md), and [CIC evidence](../cic_evidence.md).
