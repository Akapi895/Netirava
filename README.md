# Netirava

**Completed-flow intrusion detection and incident triage** for [DN-CY-01: Network Intrusion Detection with Imbalanced Threat Data](https://datanovathon.com/problems/gamswulvrvtidne), DataNova 2026.

Netirava connects a CatBoost detector, a threshold selected on benign calibration traffic, family-aware label abstention, and a budgeted incident-review interface. Evaluation uses completed-flow replay. The prototype does not block live traffic, update itself, or establish effectiveness in a deployed SOC.

## Read the submission

- **[Final report](docs/final_report.md):** problem, method, results, trade-offs, and conclusions.
- **[CIC evidence ledger](docs/cic_evidence.md):** primary checkpoint, runs, cohorts, labels, and raw/deduplicated results.
- **[ToN-IoT evaluation](docs/ton_iot_evaluation.md):** separately fitted model and before/after-gate metrics.
- **[Limitations](docs/limitations.md)** · **[Architecture](docs/architecture.md)** · **[Reproduction](docs/reproduction.md)** · **[Documentation index](docs/README.md)**.

### Three evaluations with different purposes

| Evaluation | Purpose | Main findings and limits |
|---|---|---|
| **CIC-2018, primary system** `pilot_cns/s0` | Compare the label-audited pilot with A0 v2 on common cohorts | H5–H9, deduplicated: FPR **0.077% → 0.064%**, false source incidents **217 → 143**, HOIC recall **3.6% → 81.3%**; Infiltration recall **19.5% → 1.2%**. Minority evaluation is small and within-episode. |
| **UNSW, frozen CIC models** | Check cross-environment transfer | Pilot FPR **24–27%** at the CIC-calibrated 0.1% target; per-attack AUROC <0.5. Direct checkpoint transfer failed. |
| **ToN-IoT, separate checkpoint** `42b82c1d80ed` | Apply the pipeline after one new fit | 10,202,874 test flows. Pooled FPR **0.092%**, but **4/9 segments exceed 2α**; binary recall **33.29%**. Ransomware after the gate: precision **98.73%**, recall **86.38%**, F1 **92.14%**, within-campaign only. |

After-gate fine-class metrics mean threshold plus argmax, **before family abstention**. ToN XSS has argmax F1 94.86% but correctly classified end-to-end recall only **2.81%**. ToN results do not belong to the CIC checkpoint and do not isolate the effect of class weighting.

## Pipeline

```text
Raw CSV (read-only) → label-free derived stream → CatBoost → locked detection gate
                                                        → family-aware labels
                    → source incidents → hourly review queue → UI / feedback
Truth (offline) ─────────────────────────→ flow / episode / incident evaluation
```

- **Detection:** 49 NetFlow v3 features; IPs, absolute timestamps, and labels are excluded from model inputs. CIC uses the label-audited SMOTENC pilot; ToN uses class weighting. Clean ablation does not establish a minority benefit from SMOTENC.
- **Classification:** withhold a fine label when its probability share within the family is too low; probabilities and detection decisions stay unchanged.
- **Triage:** source IP plus a 15-minute cooldown, FIFO/volume/severity queues, review-time evidence, and append-only feedback. Notification and review budgets are distinct.
- **Monitoring:** label-free distribution indicators; neither a validated FPR estimate nor an adaptation mechanism.

## Install and test

Python 3.12 and [uv](https://docs.astral.sh/uv/) are required. Dependencies are pinned by `uv.lock`.

```powershell
uv sync --locked
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m netirava --help
```

Tests use small synthetic models. When local ToN artifacts exist, an additional contract/checksum check runs. These fixture fits do not retrain either research checkpoint.

## Demo with existing artifacts

Large datasets, checkpoints, and replay outputs are outside Git. A clone alone does **not** include the demo artifacts; see the [artifact requirements](docs/reproduction.md).

```powershell
$py = ".venv\Scripts\python.exe"
# Primary CIC demo
& $py -m netirava ui --config configs/demo.yaml --run 20261108T190143_a0_fast
# Supplementary pipeline demo with a separately fitted ToN model
& $py -m netirava ui --config configs/ton_iot.yaml --run ton_X09_mitm
# Headless UI check without adding feedback
& $py -m netirava ui-check --config configs/ton_iot.yaml --run ton_X09_mitm
# Recompute reporting metrics from saved scores, without inference or fitting
& $py -m netirava ton-report
```

The ToN fit marker blocks further training. CIC holdouts have already been consumed; reprocessing them does not create new independent test evidence.

## Repository layout

```text
configs/        CIC, feature-study, ops-holdout, and ToN configurations
src/netirava/   contracts, detectors, replay, policy, triage, evaluation, and CLI
tests/          integration, causal-invariance, provenance, and reporting tests
docs/           submission report, evidence, English protocols, reproduction
research/       discontinued PCAP study; not a runtime dependency
```

Outside Git: `datasets/` (read-only), `artifacts/` (derived data/models/original-document archive), and `runs/` (scores, SQLite, logs). Dataset redistribution remains subject to the source terms.

## Claim boundary

The repository supports a replay prototype and the conditional findings above. **Robustness across all minority classes, new campaigns, or new networks remains unconfirmed.** Compression is not measured analyst time saved. The formative triage trial has one LLM reviewer; ToN does not saturate the review budget. No SOTA, zero-day, adaptation, or deployment-readiness claim is made.

## Sources

[UQ NetFlow datasets](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) · [NetFlow v3, Luay et al.](https://arxiv.org/abs/2503.04404) · [CNS2022 CSE-CIC-IDS2018 label analysis](https://intrusion-detection.distrinet-research.be/CNS2022/).
