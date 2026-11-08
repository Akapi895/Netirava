# 07. Drift monitoring

## 1. Vấn đề
Cùng một threshold khóa trên C1, FPR thực của A0 v2 dao động từ 0.037% (known) tới 0.598% (28/02, nhãn gốc). Câu hỏi: một tín hiệu không cần nhãn có báo được khi threshold không còn giữ FPR mục tiêu không, trước khi có nhãn?

Monitor là nhánh song song. Nó không đổi prediction, threshold hay incident, và không đọc nhãn (`test_monitor_is_label_free`). Cơ sở tham khảo: black-box shift detection trên output model (Rabanser et al., NeurIPS 2019), CADE (USENIX Security 2021), Thirumuruganathan et al. (USENIX Security 2024).

## 2. Thiết kế (`src/netirava/drift.py`, khai báo trước)
- **Reference:** cửa sổ C1 chấm bằng cùng model, lưu ở `artifacts/models/<model>/drift_reference.json`.
- **Cửa sổ:** 15 phút event time trong mỗi segment, bỏ cửa sổ < 2,000 flow. Độ trễ của monitor là một cửa sổ.

| Tín hiệu | Định nghĩa | Báo động |
|---|---|---|
| AR | tỷ lệ flow có score ≥ t_α, chia α | AR ≥ 2 và p nhị thức một phía < 0.001 |
| TR (chính) | tỷ lệ flow trong dải [q_ref(1 − 10α), t_α), chia tỷ lệ của dải đó trên reference | TR ≥ 2 và p < 0.001 |
| S_PSI | PSI của score trên bin quantile reference | ≥ 0.25 |
| F_PSI | trung vị PSI qua 49 feature | ≥ 0.25 |

TR nhìn vào khối flow ngay dưới threshold: dải này rộng gấp 9 lần đuôi alert, nên ổn định hơn về thống kê và ít bị chi phối bởi tấn công có score gần 1.

**Ground truth** (evaluator): FPR benign thực của mỗi cửa sổ có ≥ 5,000 flow benign. Sự kiện E là FPR > 2α.

**Luật "hữu ích"** (α = 0.1%): ρ(TR, FPR) ≥ 0.5 với cận dưới CI > 0, và TR bắt ≥ 80% cửa sổ E với tỷ lệ báo giả ≤ 20%. Nếu có < 5 cửa sổ E, phần recall là INCONCLUSIVE.

## 3. Kết quả (α = 0.1%, nhãn sửa)
Số chính là của **holdout riêng**. Pool DEV + holdout chỉ là phụ, vì DEV đã được xem nhiều lần.

| Pool | Model | Cửa sổ | Cửa sổ E | ρ(TR, FPR) [CI 95%] | ρ(AR, FPR) [CI 95%] | TR báo trên cửa sổ không-E: chỉ benign / có tấn công | AR: chỉ benign / có tấn công |
|---|---|---|---|---|---|---|---|
| Holdout H5–H9 | A0 v2 | 18 | 0 | 0.33 [−0.25, 0.73] | 0.61 [0.09, 0.93] | 0.17 / 1.00 | 0.00 / 1.00 |
| Holdout H5–H9 | Pilot | 18 | 1 | 0.06 [−0.45, 0.57] | 0.54 [0.01, 0.93] | 0.00 / 0.80 | 0.00 / 0.60 |
| DEV + holdout | A0 v2 | 46 | 2 | 0.32 [0.01, 0.58] | 0.24 [−0.13, 0.63] | 0.13 / 0.32 | 0.00 / 0.54 |
| DEV + holdout | Pilot | 46 | 1 | **0.56 [0.32, 0.73]** | 0.50 [0.18, 0.78] | 0.00 / 0.21 | 0.00 / 0.38 |

- **Score PSI và feature PSI** không theo được FPR (ρ từ −0.19 đến 0.04 trên DEV + holdout) và không báo trên cửa sổ chỉ benign nào.
- **AR** bắt cả 3 cửa sổ E của DEV (nhãn gốc) nhưng cũng báo trên phần lớn cửa sổ có tấn công: nó đo khối lượng alert, không tách được tấn công với FP.
- **TR:** trên holdout riêng, ρ = 0.33 (A0 v2) và **0.06 (pilot)**, CI đều chứa 0. Chỉ khi gộp với DEV, TR của pilot mới đạt tiêu chí tương quan (0.56), nên không dùng số gộp làm bằng chứng cảnh báo. Nó cũng báo trên cửa sổ có tấn công, vì dải dưới threshold chứa cả tấn công có score trung bình.
- **α·TR không dùng được làm ước lượng FPR:** sai số trung vị 0.30 (A0 v2) và 0.58 (pilot) bậc log10; chỉ 48% và 20% cửa sổ nằm trong khoảng 2 lần FPR thực.

## 4. Kết luận
- **INCONCLUSIVE.** Trên 5 cửa sổ mới, cả hai model giữ FPR gần mục tiêu (A0 v2 0.043–0.127%, pilot 0.026–0.113%), nên gần như không có sự kiện suy giảm để kiểm chứng. Toàn bộ DEV + holdout chỉ có 1–3 cửa sổ E, dưới ngưỡng 5.
- Monitor có trên UI (tab "Threshold reliability") như chỉ báo thay đổi phân phối: trạng thái theo cửa sổ, AR, TR, PSI và các feature thay đổi nhiều nhất. UI ghi rõ đây không phải ước lượng FPR.
- Không có hành động tự động (calibrate lại, đổi threshold) nào gắn với monitor; muốn có cần một nghiên cứu riêng với nhãn kiểm chứng.
