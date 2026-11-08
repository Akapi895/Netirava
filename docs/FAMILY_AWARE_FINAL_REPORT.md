# Family-aware labelling — final report (2026-11-08)

## 1. Implementation
- **Module duy nhất:** `src/netirava/family.py`. Mọi nơi dùng family-aware đều đi qua module này:
  - `replay.py` ghi các trường family vào `detections.parquet`;
  - `triage.py` dựng bảng flow, bảng incident và export;
  - `app.py` (UI);
  - `evaluation.family_report`.
- **Cấu hình:** `configs/demo.yaml → family: {ambiguous: {Web: [Brute_Force_-Web, Brute_Force_-XSS, SQL_Injection]}, tau: 0.8}`. Họ của các lớp khác lấy từ `labels.taxonomy`. Không có nhãn hay kết quả evaluation nào được hardcode vào logic.
- **Luật:** xác suất không bị sửa. Chỉ flow có argmax thuộc một họ mơ hồ mới có thể mất nhãn mịn. Nhãn mịn được giữ nếu `p(argmax) / khối của họ ≥ τ`; ngược lại `fine_label = "Web attack — fine class uncertain"`, `fine_label_status = uncertain`, và `uncertainty_reason` ghi tỷ trọng cùng τ.
- **Trường dữ liệu theo flow:** `predicted_family`, `fine_label`, `fine_label_status` (fine / uncertain / benign), `fine_confidence`, `family_mass`, `uncertainty_reason`.
- **Theo incident:** cặp (họ, nhãn mịn) xuất hiện nhiều nhất trong các flow của incident; status uncertain nếu nhãn đó là uncertain; kèm `share_uncertain`.
- **Chọn model:** `replay --model a0` (A0 v2, mặc định) hoặc `--model pilot_cns/s0` (pilot), hai model độc lập với nhau. Default không đổi.
- **Tương thích ngược:** run tạo trước khi tích hợp không có các trường family; `triage.flow_table` tính chúng lúc load bằng cùng code.

## 2. Test và regression
- **Unit test** (`tests/test_pipeline.py`, 18/18 pass):
  - `test_family_aware_keeps_probabilities_and_binary_alerts`
  - `test_family_annotate_fields_and_scope`
  - `test_replay_family_columns_do_not_change_active_decisions`: τ = 0.05 và τ = 0.99 cho cùng `active_decisions_sha1` và cùng số incident
  - `test_flow_table_backward_compatible_with_old_runs`
- **Regression trên dữ liệu thật:** replay lại A0 v2 bằng code mới (`20261108T143728_a0-shadow_fast`) và so với run v2 trước khi tích hợp (`20261108T122848`):
  - `active_decisions_sha1` là **`1c7b4b31a0…` ở cả hai**;
  - candidate 166,636; incident 238; notify 217; bị chặn bởi budget 21: **giống hệt**.
- **Kiểm tra bất biến** (`FAMILY_REPORT*.json`, mọi τ):
  - số alert bằng số candidate đã lưu;
  - **0** row ngoài họ Web bị đổi nhãn;
  - **0** row có argmax Benign bị đổi.

## 3. Metric (A0 v2, run `20261108T143728`, `netirava family-report`)
**Segment web K5 (nhãn gốc; 1,796 flow):**
- Họ Web: precision 0.966, recall 0.865, F1 0.913.
- Risk–coverage của nhãn mịn trong các dự đoán họ Web:

| τ | Coverage (có nhãn mịn) | Độ chính xác nhãn mịn khi phát | Nhãn mịn sai (argmax: 344) | Uncertain |
|---|---|---|---|---|
| 0.5 | 0.605 | 0.887 | 77 | 446 |
| 0.7 | 0.567 | 0.916 | 54 | 489 |
| **0.8 (đang dùng)** | **0.562** | **0.918** | **52** | 495 |
| 0.9 | 0.553 | 0.920 | 50 | 505 |
| 0.95 | 0.546 | 0.932 | 42 | 513 |

**Cùng segment, nhãn đã sửa** (1,142 flow sau khi loại attempted/indeterminate):
- Họ Web: precision **0.033**, recall 0.196, F1 0.057.
- Ở τ = 0.8: coverage 0.13, độ chính xác nhãn mịn 0.05.

**Toàn bộ stream (1.67M flow):**
- A0 v2 dự đoán họ Web cho 6,765 flow; precision họ Web 0.161 (nhãn gốc) và 0.003 (nhãn đã sửa).
- Ở τ = 0.8, số nhãn mịn sai chỉ giảm từ 5,979 xuống 5,129, vì phần lớn là **Benign bị đoán thành Web**, không phải nhầm lẫn bên trong họ.

**Triage:**
- 238 incident, **không đổi**: 229 có nhãn fine, **9 uncertain**.
- 1,049/166,636 flow bị alert có status uncertain (`runs/20261108T143728_a0-shadow_fast/export/`).

**Pilot** (nhãn đã sửa, within-episode, `runs/pilot_cns_results.json`):
- Họ Web: precision 1.00, recall 0.983; không có nhãn mịn nào bị từ chối.
- n rất nhỏ (Web 27, XSS 30, SQLi 2) → INCONCLUSIVE.

## 4. Kết luận và giới hạn
- **GO như một lớp hiển thị trung thực.** Không ảnh hưởng FP theo cấu trúc (có kiểm chứng). Trong họ Web, số nhãn mịn sai giảm khoảng 85% (344 → 52 ở K5), đổi lại 44% dự đoán trong họ bị trả về dạng uncertain.
- **Không phải cải thiện detection.** Việc giảm số nhãn sai đến từ abstention (không phát nhãn khi không chắc), không phải từ việc nhận diện đúng hơn. Precision/recall của họ và alert giữ nguyên.
- **Family-aware không sửa được:**
  - (i) Benign bị đoán thành Web: lỗi chủ yếu trên toàn stream, do A0 v2 học từ nhãn web sai;
  - (ii) nhãn train sai: trên nhãn đã sửa, precision họ Web của A0 v2 chỉ 0.033;
  - (iii) giới hạn thông tin giữa XSS và SQLi.
- **τ = 0.8** được chọn trước (ở `FAMILY_AWARE_EVALUATION`) và không đổi; bảng risk–coverage chỉ dùng để tham khảo.
