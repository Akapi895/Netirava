# Experiment registry

Bảng chi tiết của mọi run và model được **sinh tự động**: [`EXPERIMENT_REGISTRY.generated.md`](EXPERIMENT_REGISTRY.generated.md) (`python -m netirava registry`). Bảng có run id, mode, thư mục model, hash model, số class, threshold, segment, có holdout hay không, hash feature schema, sha1 của config và manifest, git commit (ghi lại hoặc *inferred*), `active_decisions_sha1`, và các file evaluation.

Mỗi số liệu trong báo cáo đều truy ngược được về artifact dưới đây. **Loại bằng chứng:**
- **DEV:** development, dùng để chọn tham số hoặc phương pháp;
- **EXP:** exploratory, phân tích hậu nghiệm;
- **HO:** holdout độc lập, chạy một lần sau khi đã khóa phương pháp.

## Dữ liệu và nhãn
| Thành phần | Provenance |
|---|---|
| Raw CSV NF-CSE-CIC-IDS2018-v3 | sha1 `ddcad6d826b7…`, khớp bagit (`runs/inspect/INSPECT.json`) |
| Subset CIC18-Causal-Demo-v1 (bản hiện tại) | `artifacts/cic18_causal_demo_v1/manifest.json`: 3,139,471 row; `stream.parquet` sha1 `b7e43a671687…`; `truth.parquet` sha1 `4bb8de42532d…`. Các run cũ ghi sha1 của manifest lúc chạy (trong registry) |
| Nhãn gốc | `truth.parquet` (NF-v3, không bao giờ bị sửa) |
| Nhãn đã sửa theo CNS2022 | `truth_cns2022.parquet` sha1 `ff679256a42c…`, `truth_cns2022.summary.json`; code `relabel.py` |
| Chuỗi thay đổi subset | MVP (2.97M row) → v1 holdout H1 (+192,863) → v2 cửa sổ web theo scope (bỏ R2) → v3 holdout H2 (+192,674). Mỗi bước có commit và ghi chú trong `DATASET_CARD.md` |

## Thí nghiệm (theo thứ tự)
| # | Thí nghiệm | Loại | Artifact | Script / lệnh | Báo cáo | Commit |
|---|---|---|---|---|---|---|
| 1 | MVP: A0 v1 + IsolationForest shadow | DEV | `runs/20261108T110255_a0_fast`, `…110215_a0-shadow_fast`, `…110325_a0-shadow_paced` | `replay`, `evaluate` | [`RESULTS_MVP.md`](RESULTS_MVP.md) | `aec4862` |
| 2 | Decision layer V1–V4b, dev (Bot, Web) | DEV | `runs/20261108T114809_a0-shadow_fast/DECISIONS_dev.json` | `decide --select`, `decide` | [`RESULTS_DECISION.md`](RESULTS_DECISION.md) | `e5336a8` (khóa) |
| 3 | **Holdout H1 DDoS LOIC-HTTP: V4b bị bác bỏ** | **HO** | `runs/20261108T115320_a0-shadow_fast/DECISIONS_holdout.json` | `replay --unlock-holdout`, `decide --unlock-holdout` | [`RESULTS_DECISION.md`](RESULTS_DECISION.md) | `c9f8c83` |
| 4 | Triage theo incident trên H1 (metric thêm sau khi H1 đã dùng) | EXP | `…115320/DECISIONS_holdout_triage.json` (dùng calibration v1 trong `artifacts/models_v1`) | `decision.evaluate_run` | [`RESULTS_FINAL.md`](RESULTS_FINAL.md) §3 | `12c3b95` |
| 5 | Lớp hiếm được đưa vào known class; ablation SMOTE / no-SMOTE / SqrtBalanced | DEV | `runs/ablate_imbalance.json`, `runs/minority_report.json` (3 seed) | `ablate-imbalance`, `minority-report` | [`RESULTS_FINAL.md`](RESULTS_FINAL.md) §2, §7 | `12c3b95`, `9302092` |
| 6 | Dev v2: decision layer và triage (FIFO / volume / severity) | DEV | `runs/20261108T122848_a0-shadow_fast/DECISIONS_dev.json` | `decide` | [`RESULTS_FINAL.md`](RESULTS_FINAL.md) §3, §7 | `12c3b95`, `5e98876` |
| 7 | FP profile | EXP | `runs/fp_profile.json` | `evaluation.fp_profile` | [`RESULTS_FINAL.md`](RESULTS_FINAL.md) §7 | `9302092` |
| 8 | **Holdout H2 DoS-Hulk: A0 recall 0.928 ở FPR 0.050% (chỉ 1 episode)** | **HO** (khai báo trước ở `5e98876`) | `runs/20261108T132246_a0-shadow_fast/DECISIONS_holdout.json` | `replay --unlock-holdout` | [`RESULTS_FINAL.md`](RESULTS_FINAL.md) §7 | `9302092` |
| 9 | Forensics FP và nhãn so với CNS2022 | EXP | `runs/forensics_*` | (script inline, tóm tắt trong báo cáo) | [`FP_LABEL_FORENSICS.md`](FP_LABEL_FORENSICS.md), [`MINORITY_INFORMATION_AUDIT.md`](MINORITY_INFORMATION_AUDIT.md) | `1687801` |
| 10 | Nhãn đã sửa và pilot A0 (3 seed) | DEV (within-episode) | `truth_cns2022.parquet`, `artifacts/models/pilot_cns/`, `runs/pilot_cns_results.json` | `relabel`, `pilot-train`, `pilot-eval` | [`CORRECTED_LABEL_AUDIT.md`](CORRECTED_LABEL_AUDIT.md), [`CORRECTED_LABEL_PILOT_RESULTS.md`](CORRECTED_LABEL_PILOT_RESULTS.md) | `2bb5529` |
| 11 | Family-aware (tích hợp chính thức) | DEV | `runs/20261108T143728_a0-shadow_fast/{FAMILY_REPORT*.json, export/}`, `runs/family_aware_triage_impact.json` | `family-report`, `export` | [`FAMILY_AWARE_FINAL_REPORT.md`](FAMILY_AWARE_FINAL_REPORT.md) | bản hoàn thiện |
| 12 | Pilot model chạy replay độc lập (smoke test) | — | `runs/20261108T143803_a0_fast` | `replay --model pilot_cns/s0` | — | bản hoàn thiện |
| 13 | **Feature-engineering study** (EDA, preprocessing, nhóm feature, control, shortcut): v2 bỏ shortcut bị **holdout H3/H4 bác bỏ (NO-GO)**; FPR ≤ 0.1% đạt trên ngày mới H3 | DEV (Phase 4) + **HO** (H3/H4, khai báo ở `e820605`) | `artifacts/fe_study_v1/{eda,study}/`, `runs/fe_study/` | `eda`, `fe-study`, `fe-final` (`configs/fe_study.yaml`) | [`EDA_REPORT.md`](EDA_REPORT.md), [`FEATURE_EVALUATION.md`](FEATURE_EVALUATION.md), [`FE_HOLDOUT_RESULTS.md`](FE_HOLDOUT_RESULTS.md) | `e820605` → `4019679` (tag `fe-v2-frozen`) |

**Kết quả âm được giữ:** GraphIDS NO-GO; V4a không có lợi trên dev; V4b bị bác bỏ trên H1; triage theo severity không tốt hơn theo volume; A1+B2 (NP-v1) không chuyển giao qua đợt; A0 v2 có XSS F1 = 0 trên nhãn đã sửa; bỏ cột shortcut làm kết quả holdout H3/H4 kém hơn.

## Bằng chứng ngoài repo này (không di chuyển)
| Giai đoạn | Vị trí | Commit hoặc file |
|---|---|---|
| GraphIDS: chẩn đoán và validation (NO-GO) | `../GraphIDS/outputs/class_diagnostics/`, `../GraphIDS/outputs/graphids_validation/FINAL_GRAPHIDS_VALIDATION.md`, checkpoint `GraphIDS_NF-CSE-CIC-IDS2018-v3_sameHost_seed24.ckpt` | Thư mục GraphIDS (không phải git repo của Netirava) |
| Run 1: LCCDE (Direct) và XI2S-IDS (Two-stage) trên UNSW-NB15-v3 | `../experiments/` (`RUN1_*.md`, `runs/{lccde,xi2s}/run1/`) | `4cbd157` → `03ac965` (repo `experiments`) |
| NP-v1: CatBoost A0/A1/A2/B1/B2, chia theo đợt | `../experiments/nextphase/`, `../experiments/NEXT_PHASE_*.md`, `runs/np_v1/` | `3c3bc78` → `064591a` (repo `experiments`) |
| Công thức A0 được kế thừa | `../experiments/nextphase/configs.yaml` (sha1 ghi trong `a0_meta.json → recipe`) | |

## Tái lập (tóm tắt)
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava prepare --config configs/demo.yaml
& $py -m netirava relabel --config configs/demo.yaml
& $py -m netirava train-a0 --config configs/demo.yaml --variant a0        # + --seed 1/2, --variant a1/a2
& $py -m netirava train-anomaly --config configs/demo.yaml
& $py -m netirava score-calibration --config configs/demo.yaml
& $py -m netirava replay --config configs/demo.yaml --mode a0-shadow
& $py -m netirava decide --run <run_id>
& $py -m netirava family-report --run <run_id> --segments K5_0222_web_tail
& $py -m netirava export --run <run_id>
& $py -m netirava pilot-train --config configs/demo.yaml ; & $py -m netirava pilot-eval --config configs/demo.yaml
& $py -m netirava registry --config configs/demo.yaml
```
Chạy lại các holdout (`--unlock-holdout`) chỉ để tái lập con số đã báo cáo. Không được dùng lại chúng như bằng chứng độc lập cho phương pháp mới.
