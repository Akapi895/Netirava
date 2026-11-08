# Corrected-label pilot — A0 recipe trained on CNS2022-corrected labels (2026-11-08)

| Thành phần | Chi tiết |
|---|---|
| Code | `src/netirava/pilot.py` (`python -m netirava pilot-train`, `pilot-eval`) |
| Model pilot | `artifacts/models/pilot_cns/s{0,1,2}` |
| So sánh với | A0 v2 trên nhãn gốc (`artifacts/models/{a0,a0_s1,a0_s2}`) |
| Kết quả | `runs/pilot_cns_results.json` |

**Thiết lập:**
- Công thức A0 giữ nguyên (CatBoost, 1000 iteration, GPU, learning rate theo CPU, SMOTE theo quy tắc); 3 seed; không HPO.
- Threshold khóa trên benign của C1 ở FPR 0.1%.
- Không đọc các holdout LOIC-HTTP hay DoS-Hulk.

**Split của pilot** (khai báo trong code trước khi fit):
- Bên trong mỗi cửa sổ web của CNS2022: 60% đầu dùng để train, phần còn lại để eval.
- Ngoài các cửa sổ: T5 dùng để train, K5 để eval.
- Row có status `attempted` hoặc `indeterminate` bị loại.
- **Train (nhãn đã sửa):** Web 43, XSS 50, SQLi 15 flow.
- **Eval phạm vi web (nhãn đã sửa):** Web 27, XSS 30, **SQLi 2**, Benign 1,026.

## 1. Lớp hiếm (eval trong phạm vi web; mỗi ô là seed 0 / 1 / 2)
| Model · nhãn đánh giá | Web F1 | XSS F1 | SQLi F1 | Benign FPR trong phạm vi |
|---|---|---|---|---|
| A0 v2 (train nhãn gốc) · nhãn gốc | 0.86 / 0.84 / 0.86 | 0.55 / 0.55 / 0.26 | 0.25 / 0.29 / 0.60 | 0 |
| A0 v2 · **nhãn đã sửa** | 0.52 / 0.53 / 0.62 | **0.00 / 0.00 / 0.00** | 0.12 / 0.08 / 0.01 | **47.7%** (cả 3 seed) |
| **Pilot (train nhãn đã sửa)** · **nhãn đã sửa** | **0.98 / 0.98 / 0.98** | **1.00 / 1.00 / 1.00** | 1.00 (n = 2) | **0** |
| Pilot · nhãn gốc | 0.03 | 0.11–0.12 | 0.12 | 0 |

**Đọc kết quả:**
- **A0 v2 học nhãn sai.** Đánh giá trên nhãn đã sửa, nó **không bắt được XSS thật nào**, và báo nhầm 47.7% flow benign trong phạm vi (traffic nền UDP/500).
- **Pilot gần như hoàn hảo trên nhãn đã sửa**, nhưng đây là **within-episode**: cùng attacker, cùng cửa sổ, chia theo thời gian, nên các flow gần như lặp lại nhau. **Rất lạc quan.**
- SQLi chỉ có 2 flow eval. → **INCONCLUSIVE** cho XSS/SQLi; kết quả không tổng quát hóa được.

## 2. FP trên các ngày khác (threshold khóa; mỗi ô là seed 0 / 1 / 2)
| Scenario · nhãn | A0 v2: benign FPR | **Pilot: benign FPR** | A0 v2: incident báo nhầm/giờ | Pilot: incident báo nhầm/giờ |
|---|---|---|---|---|
| S1 28/02 · nhãn gốc | 0.598 / 0.350 / 0.158% | **0.109 / 0.052 / 0.107%** | 44 / 38 / 36 | **18 / 17 / 18** |
| S1 28/02 · nhãn đã sửa (Portscan = attack, indeterminate bị loại) | 0.105 / 0.068 / 0.074% | **0.093 / 0.016 / 0.096%** | 42 / 36 / 34 | **16 / 15 / 16** |
| R1 02/03 · cả hai bộ nhãn (giống nhau) | 0.081 / 0.065 / 0.073% | **0.012 / 0.008 / 0.009%** | 5.6 / 3.8 / 3.2 | 11.4 / 6.8 / 8.8 ⚠ |
| Known K1–K4 · cả hai bộ nhãn | 0.037 / 0.016 / 0.036% | 0.027 / 0.025 / 0.023% | 5.0 / 5.0 / 4.8 | 8.3 / 7.2 / 6.3 ⚠ |

- **Ngân sách FPR ≤ 0.1%:**
  - Pilot đạt ở mọi scenario với nhãn đã sửa.
  - Với nhãn gốc trên S1, seed 0 và 2 hơi vượt (0.109% và 0.107%).
  - A0 v2 vượt rõ trên S1 với nhãn gốc ở cả 3 seed (0.16–0.60%).
- **Đánh đổi (⚠):** số flow báo nhầm giảm 7–9 lần trên R1, nhưng chúng rải ra nhiều host hơn, nên **số incident báo nhầm mỗi giờ tăng** trên R1 và known (khoảng 2 lần).
- **Portscan** (unknown, nhãn đã sửa): recall binary của pilot chỉ 0.5–0.7%, so với 6–11% của A0 v2. Pilot mất khả năng "bắt nhầm đúng" scan thành web attack.
- **Known macro-F1 K1–K4:** 0.991 → 0.992–0.993, không đổi.
- **Bot:** cả hai đều 0 (Bot là unknown).

## 3. Kết luận
| Mục | Kết luận |
|---|---|
| Huấn luyện bằng nhãn đã sửa **để giảm FP** | **GO (development evidence).** FP theo flow giảm nhất quán qua 3 seed trên S1 và R1, và FPR ≤ 0.1% với nhãn đã sửa. Cần ghi kèm đánh đổi: incident báo nhầm/giờ tăng trên R1 và known; portscan recall giảm |
| Cải thiện **phát hiện và phân biệt XSS/SQLi** | **INCONCLUSIVE.** Một episode mỗi lớp, chia within-episode, SQLi có n = 2 |
| Giới hạn | Luật CNS2022 được chuyển từ CICFlowMeter sang NetFlow kèm các xấp xỉ (payload proxy, ngưỡng packet). 17,082 nhãn Infilteration bị loại thành indeterminate. Một testbed. Chưa có holdout độc lập cho nhãn đã sửa |
