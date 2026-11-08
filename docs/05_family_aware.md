# 05. Family-aware classification

## 1. Luật
Một implementation duy nhất, `src/netirava/family.py`, dùng chung cho replay, triage, UI, export và evaluation. Cấu hình: `family: {ambiguous: {Web: [Brute_Force_-Web, Brute_Force_-XSS, SQL_Injection]}, tau: 0.8}`.

- Vector xác suất không bị sửa, nên p(Benign), khối xác suất của mỗi họ và alert binary giữ nguyên.
- Chỉ flow có argmax thuộc một họ mơ hồ mới có thể mất nhãn mịn. Nhãn mịn được giữ nếu `p(argmax) / khối của họ ≥ τ`; ngược lại `fine_label = "Web attack — fine class uncertain"` và `uncertainty_reason` ghi tỷ trọng cùng τ.
- Trường theo flow: `predicted_family`, `fine_label`, `fine_label_status` (fine / uncertain / benign), `fine_confidence`, `family_mass`, `uncertainty_reason`.
- Nhãn của incident là cặp (họ, nhãn mịn) xuất hiện nhiều nhất trong các flow của incident.
- Severity dùng trong triage theo nhãn family-aware: flow uncertain lấy severity của họ (`family.severity: {Web: 4}`), không lấy của lớp mịn bị giữ lại (`family.flow_severity`).

τ = 0.8 được chọn trước khi đo risk–coverage và không đổi.

## 2. Bất biến đã kiểm chứng
- Test: `test_family_aware_keeps_probabilities_and_binary_alerts`, `test_family_annotate_fields_and_scope`, `test_replay_family_columns_do_not_change_active_decisions` (τ = 0.05 và 0.99 cho cùng hash quyết định), `test_uncertain_flow_never_gets_withheld_class_severity`.
- Dữ liệu thật: replay A0 v2 trước và sau khi tích hợp cho cùng `active_decisions_sha1` (`1c7b4b31…`), cùng 166,636 alert, 238 incident.
- Ở mọi τ: 0 row ngoài họ Web bị đổi nhãn, 0 row argmax Benign bị đổi.

## 3. Kết quả (A0 v2, run `20261108T143728`)
**K5, nhãn gốc** (1,796 flow): họ Web có precision 0.966, recall 0.865, F1 0.913.

| τ | Coverage (có nhãn mịn) | Độ chính xác nhãn mịn khi phát | Nhãn mịn sai (argmax: 344) | Uncertain |
|---|---|---|---|---|
| 0.5 | 0.605 | 0.887 | 77 | 446 |
| 0.7 | 0.567 | 0.916 | 54 | 489 |
| **0.8** | **0.562** | **0.918** | **52** | 495 |
| 0.9 | 0.553 | 0.920 | 50 | 505 |
| 0.95 | 0.546 | 0.932 | 42 | 513 |

**K5, nhãn sửa** (1,142 flow sau khi loại attempted/indeterminate): họ Web có precision 0.033, recall 0.196; ở τ = 0.8, coverage 0.13 và độ chính xác nhãn mịn 0.05.

**Toàn stream** (1.67M flow): A0 v2 dự đoán họ Web cho 6,765 flow, precision họ Web 0.161 (nhãn gốc) và 0.003 (nhãn sửa). Nhãn mịn sai chỉ giảm 5,979 → 5,129, vì phần lớn lỗi là Benign bị đoán thành Web.

**Triage:** 238 incident không đổi; 9 incident uncertain; 1,049/166,636 flow bị alert có status uncertain.

**Pilot** (nhãn sửa, within-episode): họ Web precision 1.00, recall 0.983, không nhãn mịn nào bị giữ lại (n nhỏ, INCONCLUSIVE).

## 4. Kết luận
- **GO** như một lớp output trung thực: nhãn mịn sai trong họ Web giảm khoảng 85% (344 → 52), đổi lại 44% dự đoán trong họ được trả về dạng uncertain.
- Family-aware không cải thiện detection. Precision, recall của họ và alert giữ nguyên; việc giảm nhãn sai đến từ abstention.
- Family-aware không sửa được Benign bị đoán thành Web, nhãn train sai hay giới hạn thông tin giữa XSS và SQLi.
