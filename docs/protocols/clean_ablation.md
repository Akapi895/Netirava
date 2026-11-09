# Clean ablation, cohort inventory, and formative-task protocol

**English translation of the original pre-registration dated 2026-11-09, commit `d368fdc`.** This translation is not the original committed bytes; see [provenance](README.md). The original was committed before all three activities and before their model fits. None of these results changes the final CIC checkpoint.

## A. Common-condition imbalance ablation

Question: with common data, labels, features, split, calibration, deduplication, and seeds, does SMOTENC outperform no treatment or class weighting?

- Training: `configs/fe_study.yaml`, `fe.study_frame`, `fe.final_train_mask`; exact deduplication, CNS2022-adapted labels excluding attempted/indeterminate; T1–T4 plus pilot web training rows, 650,248 rows.
- Inputs: 49 raw NetFlow v3 features.
- Model: A0 recipe, 1,000 trees, depth 6, L2=3, CPU learning-rate probe then GPU fit.
- Arms: `none`; `cw` with Balanced auto weights; `smotenc` raising classes below 1,000 rows to 1,000, k=5, categorical codes copied from neighbors.
- Seeds: 0/1/2 in every arm, nine models, no HPO.
- Thresholds: α=0.1% and 1%, selected on deduplicated C1 benign.

DEV: pilot inner-val web rows in T5/K5, per-class P/R/F1/support/Wilson; known K1–K4 tails; S1/R1 benign FPR and false source incidents; adapted-label S1 Portscan recall.

EXP: consumed H3/H4 and H5–H9, deduplicated; benign FPR and LOIC-UDP/HOIC/Infiltration recall. These are descriptive, not new holdouts.

Original conclusion rule: support<30 is INCONCLUSIVE; the plan expected Web27/XSS30/SQLi2, later deduplication reduces XSS to15. An arm is called better on a metric only if it is better in all three seeds; otherwise not distinguished. This is a descriptive consistency rule, not statistical significance. Do not change the final model.

## B. Whole-CIC minority-cohort inventory

Question: does the dataset contain any independent, credible, unused minority cohort? Report Web/XSS/SQLi plus Bot/Infiltration/other classes.

- Scan all original CSV rows using labels, IPs, ports, time, and full-row hashes, without model scores.
- Episode: same label+source+destination, split after >30-minute gap.
- Used: overlaps any demo/FE/ops window.
- Credible web: adapted CNS2022 attacker–victim pair, label-specific time window, TCP/80. Other classes/dates without rules are unverified.
- Eligible: unused **and** credible **and** ≥30 unique flows **and** different from all training episodes.

If none qualifies, minority robustness cannot be confirmed in this dataset. Random splitting or oversampling is not a substitute for an independent cohort. Results are consolidated in [data quality](../data_quality.md).

## C. Small blinded formative triage task

Question: given the same alerts and decision count, does the incident workflow surface more attack types, fewer benign items, and more correct decisions than a score-ranked flow queue?

Source: final `pilot_cns/s0`, H5–H9 run `20261108T211057_a0_fast`, α=0.1%. Since these windows selected the model, the task is EXP.

Twenty decisions per condition, four per segment:
- C0: top four alerted flows by score, ties by earliest decision; one-flow card with relative time, tokenized endpoints, ports/protocol/L7, bytes/packets/duration, score and prediction.
- C1: first four incidents ordered by review time and severity rank; card has review-time volume, targets, ports, family-aware label, severity, max score, byte statistics, first five flows.
- Blind IPs with tokens; omit dates/truth. Keep answers separate and open them only after saving verdicts.
- Reference attack if the card/review-time evidence contains at least one attack-labeled flow; adapted labels on audited dates, otherwise original; report flagged Infiltration separately.
- Repository reviewer: one blinded LLM (Claude), not a human analyst; timings are LLM processing, not human time.
- C1 precedes C0 so any learned carryover can favor the baseline; this is not full counterbalancing.
- Human kit uses interactive per-decision timing.

Report verdict accuracy, types surfaced/confirmed, benign items opened, and time without significance testing. Call the result **formative**, not SOC effectiveness. Consolidated results and commands: [triage](../triage.md).
