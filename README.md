# Netirava

IDS chạy trên **flow đã hoàn tất** (NF-CSE-CIC-IDS2018-v3), dùng **dataset replay**:
- **CatBoost A0** quyết định attack hay benign tại một threshold đã khóa;
- **nhãn family-aware** (không phát lớp mịn khi Web/XSS/SQLi mơ hồ);
- **gom incident**, **correlation theo campaign** (nhiều nguồn → cùng đích, cùng họ) và **giao diện triage Streamlit**;
- **drift monitor** không cần nhãn, báo khi threshold đã khóa có thể không còn giữ được FPR mục tiêu;
- **IsolationForest** chạy ở chế độ shadow.

Phản ứng chỉ là mô phỏng. Dự án nộp cho DataNovathon 2026, đề DN-CY-01.

| Tài liệu | Nội dung |
|---|---|
| [`docs/FINAL_SOLUTION_ARCHITECTURE.md`](docs/FINAL_SOLUTION_ARCHITECTURE.md) · [`CURRENT_LIMITATIONS.md`](docs/CURRENT_LIMITATIONS.md) · [`FINAL_COMPLETION_PLAN.md`](docs/FINAL_COMPLETION_PLAN.md) | **Giải pháp đã chốt** (3 thành phần), toàn bộ hạn chế, checklist hoàn thiện |
| [`docs/OPS_STUDY_PREREG.md`](docs/OPS_STUDY_PREREG.md) · [`OPS_STUDY_RESULTS.md`](docs/OPS_STUDY_RESULTS.md) | **Incident correlation + drift monitoring**: RQ, protocol khóa trước, holdout mới H5–H9, kết quả và quyết định GO/NO-GO |
| [`docs/EDA_REPORT.md`](docs/EDA_REPORT.md) · [`PREPROCESSING_SPEC.md`](docs/PREPROCESSING_SPEC.md) · [`FEATURE_EVALUATION.md`](docs/FEATURE_EVALUATION.md) · [`FE_HOLDOUT_RESULTS.md`](docs/FE_HOLDOUT_RESULTS.md) | EDA, preprocessing, đánh giá feature, holdout mới H3/H4 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Pipeline, ranh giới module, contract dữ liệu, bất biến |
| [`docs/EXPERIMENT_REGISTRY.md`](docs/EXPERIMENT_REGISTRY.md) (+ [bản sinh tự động](docs/EXPERIMENT_REGISTRY.generated.md)) | Mọi thí nghiệm: loại bằng chứng (DEV / EXP / HO), artifact, lệnh, commit |
| [`docs/RESULTS_FINAL.md`](docs/RESULTS_FINAL.md) + [`docs/RESULTS_FINAL_ADDENDUM.md`](docs/RESULTS_FINAL_ADDENDUM.md) | Kết quả trên nhãn gốc; addendum về lỗi nhãn NF-v3 |
| [`docs/FAMILY_AWARE_FINAL_REPORT.md`](docs/FAMILY_AWARE_FINAL_REPORT.md) | Family-aware: implementation, test, metric, giới hạn |
| [`docs/CORRECTED_LABEL_AUDIT.md`](docs/CORRECTED_LABEL_AUDIT.md) · [`CORRECTED_LABEL_PILOT_RESULTS.md`](docs/CORRECTED_LABEL_PILOT_RESULTS.md) · [`DATA_SUFFICIENCY_DECISION.md`](docs/DATA_SUFFICIENCY_DECISION.md) | Nhãn sửa theo CNS2022, pilot, quyết định về dữ liệu |
| [`docs/FP_LABEL_FORENSICS.md`](docs/FP_LABEL_FORENSICS.md) · [`MINORITY_INFORMATION_AUDIT.md`](docs/MINORITY_INFORMATION_AUDIT.md) · [`SOTA_METHOD_REVIEW.md`](docs/SOTA_METHOD_REVIEW.md) | Forensics FP và nhãn, giới hạn thông tin, review paper |
| [`docs/RESEARCH_FRAMING.md`](docs/RESEARCH_FRAMING.md) · [`DATASET_CARD.md`](docs/DATASET_CARD.md) · [`MODEL_CARD_A0_v2.md`](docs/MODEL_CARD_A0_v2.md) | Đề bài và RQ; subset; model card |
| [`docs/RESULTS_MVP.md`](docs/RESULTS_MVP.md) · [`RESULTS_DECISION.md`](docs/RESULTS_DECISION.md) · [`docs/history/`](docs/history/) | Kết quả lịch sử (MVP; decision layer và holdout DDoS) và các tài liệu đã bị thay thế |
| [`docs/CLEANUP_MANIFEST.md`](docs/CLEANUP_MANIFEST.md) | Thay đổi cấu trúc repo |

## Cài đặt
```powershell
cd D:\Downloads\DataNova\Netirava
uv sync                                   # Python 3.12; versions pinned in uv.lock
.venv\Scripts\python.exe -m pytest -q     # 36 tests
```
- **Ngoài git:** `datasets/` (CSV gốc, chỉ đọc), `artifacts/` (subset dẫn xuất, model), `runs/` (các run).
- **A0** kế thừa công thức NP-v1 từ `../experiments/nextphase/configs.yaml`.

## Demo
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava replay --config configs/demo.yaml --mode a0                       # final model: pilot_cns/s0 (final_system.model_dir)
& $py -m netirava ui --run <run_id>                                                 # http://localhost:8501
& $py -m netirava export --run <run_id>                                             # runs/<run_id>/export/
& $py -m netirava replay --config configs/demo.yaml --mode a0-shadow --model a0     # baseline A0 v2 (+ shadow), as in earlier reports
& $py -m netirava drift-reference --model pilot_cns/s0                               # once per model (C1 reference)
& $py -m netirava drift-monitor --run <run_id>                                       # tab "Threshold reliability" in the UI
```

Ops study (tái lập toàn bộ incident correlation + drift monitoring):
```powershell
& $py -m netirava ops-study --runs <a0_dev_run> <pilot_dev_run> --tag dev
& $py -m netirava prepare --config configs/ops_holdout.yaml; & $py -m netirava relabel --config configs/ops_holdout.yaml
& $py -m netirava replay --config configs/ops_holdout.yaml --mode a0 --model a0 --unlock-holdout   # and --model pilot_cns/s0
& $py -m netirava ops-study --config configs/ops_holdout.yaml --runs <a0_ho_run> <pilot_ho_run> --tag holdout
& $py -m netirava ops-go --config configs/ops_holdout.yaml --tag holdout
& $py -m netirava ops-pool --tags dev holdout --out pooled; & $py -m netirava ops-summary --tag holdout
```

## Toàn bộ lệnh CLI
`inspect` · `prepare` · `audit` · `relabel` · `train-a0 [--variant a0|a1|a2] [--seed N]` · `train-anomaly` · `score-calibration` · `replay [--mode a0|a0-shadow] [--pace fast|paced] [--model DIR] [--segments …] [--max-events N] [--unlock-holdout]` · `evaluate --run` · `decide --run [--select] [--unlock-holdout]` · `family-report --run [--segments …]` · `export --run` · `eda` · `fe-study` · `fe-final` · `ablate-imbalance` · `minority-report` · `pilot-train` · `pilot-eval` · `registry` · `incidents --run` · `feedback --run --alert-id --status [--provenance]` · `ui --run` · `drift-reference [--model]` · `drift-monitor --run` · `ops-study --runs … --tag` · `ops-go --tag` · `ops-pool --tags … --out` · `ops-summary --tag [--labels]`

Mỗi lần `replay` tạo một run mới `runs/<run_id>/` gồm `run.json`, `detections.parquet` và `alerts.db`. Cách tái lập từng thí nghiệm có trong [`docs/EXPERIMENT_REGISTRY.md`](docs/EXPERIMENT_REGISTRY.md).

## Phạm vi claim
- Chỉ là replay flow đã hoàn tất trong một testbed: **development evidence**.
- Kết quả trên **holdout** (H1 DDoS, H2 DoS-Hulk; H3/H4 của FE study; H5–H9 của ops study) được đánh dấu riêng.
- Correlation và drift monitor **không** giảm FPR và không phát hiện thêm attack flow; chúng chỉ đổi đơn vị xem xét và cảnh báo độ tin cậy của threshold.
- Nhãn NF-v3 có lỗi đã được xác định (xem forensics); mọi báo cáo đều ghi rõ dùng nhãn gốc hay nhãn đã sửa.
- Không phải SOTA, không phải zero-day detection, không phải IPS.
