# Netirava

Netirava là IDS chạy trên flow NetFlow v3 đã hoàn tất (NF-CSE-CIC-IDS2018-v3), đánh giá bằng dataset replay, cho đề DN-CY-01 của DataNovathon 2026: *Network Intrusion Detection with Imbalanced Threat Data*.

Giải pháp có ba thành phần:
1. **Minority-aware detection:** CatBoost 8 known class (gồm Web, XSS, SQLi), SMOTE theo quy tắc, nhãn sửa CNS2022 trong file riêng, threshold khóa trên cửa sổ calibration.
2. **Family-aware classification:** luôn trả họ tấn công; chỉ trả lớp mịn khi đủ tin cậy.
3. **Incident triage UI (Streamlit):** gom alert thành incident có budget, hàng xem xét theo severity, view campaign (thử nghiệm), chỉ báo drift không cần nhãn, feedback append-only.

Phản ứng chỉ là mô phỏng. Netirava không claim SOTA, zero-day detection hay IPS.

## Kết quả chính
Chi tiết và nguồn của từng số: [`docs/08_final_report.md`](docs/08_final_report.md).

| Kết quả | Số | Loại bằng chứng |
|---|---|---|
| Nhãn web của NF-v3 phần lớn sai | 6.9% flow web là tấn công thật | Forensics |
| FPR ở mục tiêu 0.1% trên ngày chưa từng chạm | 0.007–0.052% (H3); 0.026–0.127% (H5–H9) | Holdout |
| SMOTE so với không xử lý mất cân bằng | Lợi ích trên nhãn gốc không tái hiện trên nhãn sửa và dữ liệu đã loại trùng; không quy cải thiện cho SMOTENC | DEV |
| Model cuối (nhãn sửa) so với baseline (nhãn gốc) | FPR 0.064% so với 0.077% (đã loại trùng); false incident 143 so với 217; HOIC 0.81 so với 0.04; Infiltration 0.012 so với 0.194 | Holdout (sau khi chọn) |
| Lớp thiểu số | Đúng hết trên eval nhỏ cùng episode (XSS 15, SQLi 2); không còn cohort độc lập trong dataset | Chưa xác nhận được |
| Thử nghiệm triage (reviewer LLM, 20 lượt xem) | Workflow incident đưa ra 5 source-defined attack episode, hàng flow theo score đưa ra 1 | Formative |
| Family-aware | Nhãn mịn sai 344 → 52, không đổi alert | DEV |
| Gom incident | Nén 243–1,024 lần | DEV/EXP |
| Correlation theo campaign | 46 → 5 mục trên HOIC, nhưng gộp nhầm 7% incident benign: NO-GO | Holdout |
| Drift monitor | Chưa đủ bằng chứng trên CIC (ρ = 0.06 trên holdout); báo 99/99 cửa sổ khi chạy trên môi trường UNSW | Holdout; exploratory |
| Chuyển giao sang NF-UNSW-NB15-v3 (model frozen) | Không chuyển giao: FPR 24–27% ở mục tiêu 0.1%, AUROC < 0.5 | Đánh giá ngoài |

## Cài đặt
```powershell
uv sync                                    # Python 3.12, phiên bản khóa trong uv.lock
.venv\Scripts\python.exe -m pytest -q      # 36 test
```
Ngoài git: `datasets/` (CSV gốc, chỉ đọc), `artifacts/` (subset, model), `runs/` (các run). Công thức A0 kế thừa từ `../experiments/nextphase/configs.yaml`.

## Demo
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava replay --config configs/demo.yaml --mode a0                 # model cuối: final_system.model_dir = pilot_cns/s0
& $py -m netirava replay --config configs/demo.yaml --mode a0 --model a0      # baseline A0 v2
& $py -m netirava drift-reference --model pilot_cns/s0                        # một lần cho mỗi model
& $py -m netirava drift-monitor --run <run_id>                                # tab "Threshold reliability"
& $py -m netirava ui --run <run_id>                                           # http://localhost:8501
& $py -m netirava export --run <run_id>                                       # runs/<run_id>/export/
```

## Ops study (correlation và drift monitor)
```powershell
& $py -m netirava ops-study --runs <a0_dev_run> <pilot_dev_run> --tag dev
& $py -m netirava prepare --config configs/ops_holdout.yaml; & $py -m netirava relabel --config configs/ops_holdout.yaml
& $py -m netirava replay --config configs/ops_holdout.yaml --mode a0 --model a0 --unlock-holdout   # và --model pilot_cns/s0
& $py -m netirava ops-study --config configs/ops_holdout.yaml --runs <a0_ho_run> <pilot_ho_run> --tag holdout
& $py -m netirava ops-go --config configs/ops_holdout.yaml --tag holdout
& $py -m netirava ops-pool --tags dev holdout --out pooled; & $py -m netirava ops-summary --tag holdout
```

## Lệnh CLI
`inspect` · `prepare` · `audit` · `relabel` · `eda` · `fe-study` · `fe-final` · `train-a0 [--variant a0|a1|a2] [--seed N]` · `train-anomaly` · `score-calibration` · `ablate-imbalance` · `minority-report` · `pilot-train` · `pilot-eval` · `replay [--mode a0|a0-shadow] [--pace fast|paced] [--model DIR] [--segments …] [--max-events N] [--unlock-holdout]` · `evaluate --run` · `decide --run [--select] [--unlock-holdout]` · `family-report --run` · `export --run` · `incidents --run` · `feedback --run --alert-id --status` · `ui --run` · `drift-reference` · `drift-monitor --run` · `ops-study` · `ops-go` · `ops-pool` · `ops-summary` · `registry`

Mỗi `replay` tạo `runs/<run_id>/` gồm `run.json`, `detections.parquet` và `alerts.db`.

## Cấu trúc
```
configs/   demo.yaml (subset chính), fe_study.yaml, ops_holdout.yaml
src/netirava/   pipeline, detector, family-aware, triage, campaign, drift, evaluator, CLI, UI
tests/     test_pipeline.py, test_fe.py, test_ops.py
docs/      tài liệu (mục lục ở docs/README.md)
research/pcap_feasibility/   nghiên cứu PCAP (đã dừng)
```

## Phạm vi claim
- Replay flow đã hoàn tất trong một testbed; mỗi lớp tấn công chỉ có một episode.
- Kết quả holdout (H1–H9) được đánh dấu riêng; mọi holdout đã dùng.
- Mọi bảng ghi rõ nhãn gốc NF-v3 hay nhãn sửa CNS2022.
- Correlation và drift monitor không giảm FPR và không phát hiện thêm flow tấn công.
