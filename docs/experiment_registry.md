# Experiment registry

Bảng chi tiết từng run và model được sinh tự động ở [`experiment_registry_generated.md`](experiment_registry_generated.md) (`python -m netirava registry`): run id, model, threshold, segment, holdout, sha1 của config và manifest, git commit, `active_decisions_sha1`.

Loại bằng chứng: **DEV** (phát triển, chọn), **EXP** (hậu nghiệm), **HO** (holdout khai báo trước, chạy một lần sau khi khóa).

## Dữ liệu và nhãn
| Thành phần | Provenance |
|---|---|
| CSV NF-CSE-CIC-IDS2018-v3 | sha1 `ddcad6d826b7…`, khớp bagit (`runs/inspect/INSPECT.json`) |
| `CIC18-Causal-Demo-v1` | `artifacts/cic18_causal_demo_v1/manifest.json`: 3,139,471 row; `stream.parquet` `b7e43a671687…`; `truth.parquet` `4bb8de42532d…` |
| Nhãn sửa CNS2022 | `truth_cns2022.parquet` `ff679256a42c…`; code `relabel.py` |
| `CIC18-FE-Study-v1` | `artifacts/fe_study_v1/`: 3,181,717 row (H3, H4) |
| `CIC18-Ops-Holdout-v1` | `artifacts/ops_holdout_v1/`: 1,489,831 row (H5–H9) |

## Thí nghiệm
| # | Thí nghiệm | Loại | Artifact | Lệnh | Tài liệu | Commit |
|---|---|---|---|---|---|---|
| 1 | MVP: A0 v1 + IsolationForest shadow | DEV | `runs/20261108T110255_a0_fast`, `…110215_a0-shadow_fast`, `…110325_a0-shadow_paced` | `replay`, `evaluate` | `04` §2.1 | `aec4862` |
| 2 | Decision layer V1–V4b | DEV | `runs/20261108T114809_a0-shadow_fast/DECISIONS_dev.json` | `decide --select`, `decide` | `04` §2.2 | `e5336a8` (khóa) |
| 3 | H1 DDoS LOIC-HTTP: V4b bị bác bỏ | HO | `runs/20261108T115320_a0-shadow_fast/DECISIONS_holdout.json` | `replay --unlock-holdout`, `decide --unlock-holdout` | `04` §2.2 | `c9f8c83` |
| 4 | Triage theo incident trên H1 | EXP | `…115320/DECISIONS_holdout_triage.json` | `decision.evaluate_run` | `06` §2 | `12c3b95` |
| 5 | Lớp hiếm thành known class; ablation SMOTE / không SMOTE / SqrtBalanced, 3 seed | DEV | `runs/ablate_imbalance.json`, `runs/minority_report.json` | `ablate-imbalance`, `minority-report` | `04` §3 | `12c3b95`, `9302092` |
| 6 | Dev v2: triage FIFO / volume / severity | DEV | `runs/20261108T122848_a0-shadow_fast/DECISIONS_dev.json` | `decide` | `06` §2 | `12c3b95`, `5e98876` |
| 7 | FP profile | EXP | `runs/fp_profile.json` | `evaluation.fp_profile` | `02` §4 | `9302092` |
| 8 | H2 DoS-Hulk | HO | `runs/20261108T132246_a0-shadow_fast/DECISIONS_holdout.json` | `replay --unlock-holdout` | `04` §4 | `9302092` (khai báo ở `5e98876`) |
| 9 | Forensics FP và nhãn so với CNS2022 | EXP | `runs/forensics_*` | — | `02` §4–5 | `1687801` |
| 10 | Nhãn sửa và pilot (3 seed) | DEV (within-episode) | `truth_cns2022.parquet`, `artifacts/models/pilot_cns/`, `runs/pilot_cns_results.json` | `relabel`, `pilot-train`, `pilot-eval` | `02` §6, `04` §5 | `2bb5529` |
| 11 | Family-aware | DEV | `runs/20261108T143728_a0-shadow_fast/{FAMILY_REPORT*.json, export/}` | `family-report`, `export` | `05` | `0a817b2` |
| 12 | Feature study: EDA, preprocessing, nhóm feature; H3/H4 | DEV + HO | `artifacts/fe_study_v1/{eda,study}/`, `runs/fe_study/` | `eda`, `fe-study`, `fe-final` (`configs/fe_study.yaml`) | `02` §3, `03` | `e820605` → `b900099` (tag `fe-v2-frozen`) |
| 13 | Ops study: correlation, drift monitor, chọn model; H5–H9 | DEV + EXP (H2) + HO | DEV `runs/20261108T190136_a0_fast`, `…190143…`; HO `runs/20261108T211051_a0_fast`, `…211057…`; `runs/ops_study/` | `drift-reference`, `ops-study`, `ops-go`, `ops-pool`, `ops-summary` (`configs/ops_holdout.yaml`) | `06`, `07`, `04` §6; protocol ở `protocols/ops_study_prereg.md` | `e1b473a` → `26fab5d` (tag `ops-v1-frozen`) |
| 14 | Audit thay đổi của ops study | — | `runs/ops_study/AUDIT_INVARIANCE.json`, `runs/audit_ops_*` | `runs/ops_study/audit_inv.py` | `ops_change_audit.md` | — |
| 15 | Sửa đo lường, provenance, UI | — | `runs/ops_study/holdout/GO.json` (bản trước: `GO_before_exposure_fix.json`) | `ops-study`, `ops-go` | `10` §6 | `e5168f8` |
| 16 | Ablation imbalance sạch (none / cw / smotenc, 3 seed) | DEV + EXP | `runs/fe_study/ablation_clean.json`, `artifacts/fe_study_v1/ablation_clean/` | `ablate-clean --config configs/fe_study.yaml` | `11` §1 | prereg `d368fdc` |
| 17 | Kiểm kê cohort thiểu số | — | `runs/minority_inventory/` | `inventory` | `11` §2 | prereg `d368fdc` |
| 18 | Thử nghiệm triage nhỏ (reviewer LLM) | EXP, formative | `runs/triage_trial/` | `task-make`, `task-score` | `12` | prereg `d368fdc` |
| 19 | Ledger bằng chứng của hệ thống cuối | — | `runs/final_evidence/` | `ledger` | `10` | — |

## Bằng chứng ngoài repo
| Giai đoạn | Vị trí |
|---|---|
| GraphIDS (NO-GO) | `../GraphIDS/outputs/` |
| Run 1: LCCDE và XI2S-IDS trên UNSW-NB15-v3 | `../experiments/` (`RUN1_*.md`) |
| NP-v1: CatBoost A0/A1/A2/B1/B2 theo đợt; công thức A0 | `../experiments/nextphase/`, `../experiments/NEXT_PHASE_*.md` |
| RQ-PCAP | `research/pcap_feasibility/` |

## Tái lập
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava prepare --config configs/demo.yaml
& $py -m netirava relabel --config configs/demo.yaml
& $py -m netirava train-a0 --config configs/demo.yaml --variant a0        # + --seed 1/2, --variant a1/a2
& $py -m netirava train-anomaly --config configs/demo.yaml
& $py -m netirava score-calibration --config configs/demo.yaml
& $py -m netirava replay --config configs/demo.yaml --mode a0-shadow --model a0
& $py -m netirava decide --run <run_id>
& $py -m netirava family-report --run <run_id> --segments K5_0222_web_tail
& $py -m netirava pilot-train --config configs/demo.yaml ; & $py -m netirava pilot-eval --config configs/demo.yaml
& $py -m netirava eda --config configs/fe_study.yaml ; & $py -m netirava fe-study --config configs/fe_study.yaml
& $py -m netirava registry --config configs/demo.yaml
```
Ops study: xem `README.md`. `replay` không có `--model` dùng `final_system.model_dir` (hiện là pilot), nên tái lập số của A0 v2 phải ghi `--model a0`. Chạy lại holdout (`--unlock-holdout`) chỉ để tái lập số đã báo cáo, không làm bằng chứng mới.
