# Experiment registry and invariance audit

This is the curated experiment history. `python -m netirava registry --config <config>` generates `registry.json` and `registry.md` in the **configured runs directory**. Generated local inventories are not the curated submission report and do not overwrite documentation.

Evidence labels: **DEV** for development/selection; **EXP** for exploratory reuse; **HO** for the originally declared one-time evaluation. Consumed holdouts do not become untouched again. The supplementary ToN model is separate from the final CIC model.

## 1. Data provenance

| Artifact | Recorded provenance |
|---|---|
| CIC original CSV | SHA-1 `ddcad6d826b7…`, BagIt match |
| CIC demo | `artifacts/cic18_causal_demo_v1/manifest.json`, 3,139,471 rows; stream `b7e43a671687…`, original truth `4bb8de42532d…` |
| CNS2022-adapted truth | `truth_cns2022.parquet`, `ff679256a42c…`; separate artifact, raw unchanged |
| FE study | `artifacts/fe_study_v1/`, 3,181,717 rows with H3/H4 |
| Ops holdout | `artifacts/ops_holdout_v1/`, 1,489,831 rows, H5–H9 |
| ToN original CSV | SHA-1 `24854ca3072ab7c2ade9ebfb202345a666a94cfe` |
| ToN derived/checkpoint | `artifacts/ton_iot_v1/`; checkpoint `42b82c1d80ed`; full hashes in frozen plan/model metadata |

## 2. Experiment timeline

| # | Experiment / outcome | Evidence | Artifact | Provenance |
|---|---|---|---|---|
| 1 | MVP A0 v1 and IsolationForest shadow | DEV | `runs/20261108T110255_a0_fast`, `…110215_a0-shadow_fast`, `…110325_a0-shadow_paced` | `aec4862` |
| 2 | V1–V4b selection | DEV | `…114809…/DECISIONS_dev.json` | Locked `e5336a8` |
| 3 | H1 LOIC-HTTP rejects V4b | HO | `…115320…/DECISIONS_holdout.json` | `c9f8c83` |
| 4 | Incident-priority analysis on H1 | EXP | Same run, `DECISIONS_holdout_triage.json` | `12c3b95` |
| 5 | Eight-class A0 v2 and original-label imbalance ablation | DEV | `runs/ablate_imbalance.json`, `minority_report.json` | `12c3b95`, `9302092` |
| 6 | FIFO/volume/severity on DEV | DEV | `runs/20261108T122848_a0-shadow_fast/` | `5e98876` |
| 7 | FP profile and label forensics | EXP | `runs/fp_profile.json`, `forensics_*` | `9302092`, `1687801` |
| 8 | H2 Hulk | HO | `runs/20261108T132246_a0-shadow_fast/` | Declared `5e98876`, evaluated `9302092` |
| 9 | Adapted labels and pilot, three seeds | DEV, within-episode | `artifacts/models/pilot_cns/`, `runs/pilot_cns_results.json` | `2bb5529` |
| 10 | Family-aware integration | DEV | `runs/20261108T143728_a0-shadow_fast/` | `0a817b2` |
| 11 | Feature/preprocessing study and H3/H4 rejection | DEV+HO | `artifacts/fe_study_v1/`, `runs/fe_study/` | Protocol `e820605`; tag `fe-v2-frozen` |
| 12 | Campaign/monitor/pilot selection on H5–H9 | DEV+HO, later selected | `runs/ops_study/`; DEV `…190136…`/`…190143…`, HO `…211051…`/`…211057…` | Protocol `e1b473a`; tag `ops-v1-frozen` |
| 13 | Ops training/inference invariance | Audit | `runs/ops_study/AUDIT_INVARIANCE.json` | Scope through `26fab5d` |
| 14 | Exposure/provenance/UI corrections | Measurement correction | `GO.json`, `GO_before_exposure_fix.json` | `e5168f8` |
| 15 | Clean none/cw/SMOTENC ablation, three seeds | DEV+EXP | `runs/fe_study/ablation_clean.json` | Preregistered `d368fdc` |
| 16 | Whole-CIC minority inventory | Audit | `runs/minority_inventory/` | Preregistered `d368fdc` |
| 17 | Blinded LLM triage task | EXP, formative | `runs/triage_trial/` | Preregistered `d368fdc` |
| 18 | Unified CIC ledger | Saved-score reporting | `runs/final_evidence/` | `ledger` command |
| 19 | Frozen external UNSW test; no new fit | External; monitor EXP | `runs/external_unsw/` | Preregistered `6ad5206` |
| 20 | ToN one-fit end-to-end experiment | Local frozen plan, within-campaign minorities | `artifacts/ton_iot_v1/`, `runs/ton_iot/` | Frozen UTC 2026-11-08T17:24:16; not committed at execution |
| 21 | ToN after-gate/global-novelty correction | Post-fit reporting, no inference/fit | `docs/ton_iot_evidence.json` | `ton-report` |

The shortened run ids above retain the timestamp suffix from `runs/`; exact primary ids are in [CIC evidence](cic_evidence.md), supplementary ids in [ToN evaluation](ton_iot_evaluation.md).

## 3. Ops invariance audit

Historical scope: branch at `26fab5d` versus `master`/merge-base `b900099`. The original audit is read-only; its output is `runs/ops_study/AUDIT_INVARIANCE.json`. It is not a claim that present-day source files are byte-identical to those historical commits.

| Check | Finding |
|---|---|
| Training invariance | No fit, SMOTE, fine-tuning, or threshold reselection during that ops integration; checkpoint/train-data hashes matched |
| A0 v2 before/after integration | 1,669,430 flows; max score difference0; probabilities, argmax, candidates, actions, 238 incident ids, family fields identical |
| Pilot comparable K5+R1 subset | 977,200 flows; probabilities/actions identical; 68 incident partitions matched despite id numbering differences |
| Ops on/off, A0 v2 | 1,669,430 flows, same 166,636 alerts/238 incidents, decision hash `1c7b4b31…` |
| Ops on/off, pilot | Same 164,876 alerts/141 incidents, decision hash `8eaccddf…` |

Only campaign ids differed when ops was toggled. Monitor tables are separate from detections/SQLite. Drift-reference creation does not change checkpoint loading; reference thresholds are checked against frozen thresholds.

Presentation changed: family-aware max severity affected 0/238 A0 incidents and 6/141 pilot incidents; causal top-10 differed from lifetime-volume UI ordering for 18/107 A0 and 9/90 pilot items. Notification values stayed unchanged (A0 217 notified,21 budget-blocked). Thus presentation changes are real even when detection invariance holds.

Default checkpoint selection changed from A0 v2 to pilot under the ops rule and was subsequently finalized by the user. This default change, not correlation/monitoring, changes detection output when `--model` is omitted. Checkpoint-specific results remain separate. H1/H2 were not reopened with the final pilot.

## 4. Historical research outside the primary pipeline

GraphIDS, Run1, and NP-v1 experiments live outside this repository under sibling experiment directories; they are not required dependencies for checkpoint inference. A portable A0 recipe snapshot is included. The separate [PCAP feasibility archive](../research/pcap_feasibility/README.md) retains code, original result JSON, and a consolidated English account of its NO-GO decision. Its IoT-23 results do not establish NetFlow v3 effectiveness.

## 5. Documentation provenance

Numbered Vietnamese chapters were consolidated by topic. English [protocol translations](protocols/README.md) explicitly distinguish themselves from original committed/local-frozen documents. Original documents/config/code snapshots are retained in `artifacts/documentation_originals/`; no historical manifest/checkpoint was rewritten to make current paths or hashes appear original. The [documentation index](README.md) records each keep/merge/remove decision.
