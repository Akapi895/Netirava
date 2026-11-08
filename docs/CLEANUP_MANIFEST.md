# Cleanup manifest (2026-11-08)

**Snapshot khôi phục:** git tag **`pre-consolidation-20261108`** (trỏ tới `2bb5529`). Khôi phục một file bằng `git checkout pre-consolidation-20261108 -- <path>`.

Chỉ xóa cache tạo lại được; không xóa artifact, run, model hay báo cáo nào.

**Phạm vi:** repo Netirava. Bằng chứng của GraphIDS, LCCDE, XI2S và NP-v1 nằm trong `../GraphIDS` và `../experiments`, không bị động tới; chúng được liệt kê trong [`EXPERIMENT_REGISTRY.md`](EXPERIMENT_REGISTRY.md).

## Audit
- **File đang được git theo dõi:** 38 file trước, 43 file sau. Repo vốn đã gọn (package phẳng, một file test); không có script thử nghiệm lỗi thời hay checkpoint trong git.
- **Ngoài git:** `artifacts/` (226 MB subset, khoảng 68 MB model), `runs/` (224 MB, 9 run cùng các file phân tích).
  - **Mọi run đều được báo cáo trích dẫn** (registry), nên tất cả được giữ.
  - `artifacts/models_v1` (A0 v1 và calibration v1) cần để tái lập các run MVP và triage của H1, nên được giữ.

## Thay đổi
| File / thư mục | Hành động | Lý do |
|---|---|---|
| `src/netirava/family.py` | **Viết lại** thành module chính thức (`annotate`, `annotate_frame`, `incident_labels`, `settings`); giữ hàm `render` cho `pilot.py` | Một implementation duy nhất cho replay, triage, UI, export và evaluation |
| `src/netirava/triage.py` | **Mới**: `flow_table`, `incident_table`, `export` (dời logic bảng incident từ `app.py` sang) | UI và export dùng cùng một code |
| `src/netirava/registry.py` | **Mới**: sinh registry | Truy vết run và model |
| `src/netirava/replay.py` | Thêm `--model`, ghi các trường family, `git_commit` và `family` vào `run.json` | Pilot dùng độc lập; provenance |
| `src/netirava/app.py` | Dùng `triage.incident_table`; hiển thị family, nhãn mịn, status và lý do | Bỏ logic family-aware viết riêng trong UI |
| `src/netirava/evaluation.py` | Thêm `family_report` (risk–coverage, nhãn gốc và nhãn đã sửa, kiểm tra bất biến) | Đánh giá family-aware |
| `src/netirava/cli.py` | Thêm `export`, `family-report`, `registry`, `replay --model` | |
| `configs/demo.yaml` | Thêm mục `family` (họ mơ hồ, τ = 0.8) | Bỏ hardcode τ trong UI |
| `tests/test_pipeline.py` | Thêm 3 test (trường và phạm vi của family; replay bất biến theo τ; tương thích run cũ và export) | 18 test |
| `pyproject.toml`, `uv.lock` | Thêm `tabulate` | Bảng markdown của registry |
| `docs/ARCHITECTURE.md`, `EXPERIMENT_REGISTRY.md`, `EXPERIMENT_REGISTRY.generated.md`, `FAMILY_AWARE_FINAL_REPORT.md`, `CLEANUP_MANIFEST.md`, `MODEL_CARD_A0_v2.md` | **Mới** | Deliverable; model card v2 copy từ `artifacts/models/a0/MODEL_CARD.md` |
| `docs/MODEL_CARD_A0.md` | **Chuyển** sang `docs/history/MODEL_CARD_A0_v1.md` | Đó là card của A0 v1 (`be8f6d84bf2d`), không phải model hiện tại |
| `docs/NEXT_RESEARCH_DECISION.md` | **Chuyển** sang `docs/history/` | Bị thay bởi `DATA_SUFFICIENCY_DECISION.md`; link trong addendum đã cập nhật |
| `docs/FAMILY_AWARE_EVALUATION.md` | **Chuyển** sang `docs/history/` | Bị thay bởi `FAMILY_AWARE_FINAL_REPORT.md` |
| `README.md` | **Viết lại** (cài đặt, demo, CLI, mục lục tài liệu) | |
| `docs/RESULTS_FINAL_ADDENDUM.md` | Chỉ cập nhật link | Không đổi nội dung |
| `.pytest_cache/`, `catboost_info/` | **Xóa** (ngoài git, tạo lại được) | Cache |
| `RESULTS_MVP.md`, `RESULTS_DECISION.md`, `RESULTS_FINAL.md`, các file forensics, pilot, nhãn | **Giữ nguyên** | Bằng chứng lịch sử và kết quả âm |
| `runs/*`, `artifacts/*` | **Giữ nguyên** | Bằng chứng và model đang dùng |

## Không thay đổi
- Nhãn gốc, nhãn đã sửa, dataset nguồn.
- Model A0 v2 (vẫn là mặc định) và các checkpoint.
- Các con số trong báo cáo lịch sử.
- Các holdout không được đánh giá lại.
