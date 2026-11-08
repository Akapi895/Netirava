# Netirava

IDS chạy trên **flow đã hoàn tất** (NF-CSE-CIC-IDS2018-v3), dùng **dataset replay**:
- **CatBoost A0** quyết định attack hay benign tại một threshold đã khóa;
- **nhãn family-aware** (không phát lớp mịn khi Web/XSS/SQLi mơ hồ);
- **gom incident** và **giao diện triage Streamlit**;
- **IsolationForest** chạy ở chế độ shadow.

Phản ứng chỉ là mô phỏng. Dự án nộp cho DataNovathon 2026, đề DN-CY-01.

| Tài liệu | Nội dung |
|---|---|
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
.venv\Scripts\python.exe -m pytest -q     # 18 tests
```
- **Ngoài git:** `datasets/` (CSV gốc, chỉ đọc), `artifacts/` (subset dẫn xuất, model), `runs/` (các run).
- **A0** kế thừa công thức NP-v1 từ `../experiments/nextphase/configs.yaml`.

## Demo
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava replay --config configs/demo.yaml --mode a0-shadow                # A0 v2 (default model)
& $py -m netirava ui --run <run_id>                                                 # http://localhost:8501
& $py -m netirava export --run <run_id>                                             # runs/<run_id>/export/
& $py -m netirava replay --config configs/demo.yaml --mode a0 --model pilot_cns/s0  # corrected-label pilot, separately
```

## Toàn bộ lệnh CLI
`inspect` · `prepare` · `audit` · `relabel` · `train-a0 [--variant a0|a1|a2] [--seed N]` · `train-anomaly` · `score-calibration` · `replay [--mode a0|a0-shadow] [--pace fast|paced] [--model DIR] [--segments …] [--max-events N] [--unlock-holdout]` · `evaluate --run` · `decide --run [--select] [--unlock-holdout]` · `family-report --run [--segments …]` · `export --run` · `ablate-imbalance` · `minority-report` · `pilot-train` · `pilot-eval` · `registry` · `incidents --run` · `feedback --run --alert-id --status [--provenance]` · `ui --run`

Mỗi lần `replay` tạo một run mới `runs/<run_id>/` gồm `run.json`, `detections.parquet` và `alerts.db`. Cách tái lập từng thí nghiệm có trong [`docs/EXPERIMENT_REGISTRY.md`](docs/EXPERIMENT_REGISTRY.md).

## Phạm vi claim
- Chỉ là replay flow đã hoàn tất trong một testbed: **development evidence**.
- Kết quả trên **holdout** (H1 DDoS, H2 DoS-Hulk) được đánh dấu riêng.
- Nhãn NF-v3 có lỗi đã được xác định (xem forensics); mọi báo cáo đều ghi rõ dùng nhãn gốc hay nhãn đã sửa.
- Không phải SOTA, không phải zero-day detection, không phải IPS.
