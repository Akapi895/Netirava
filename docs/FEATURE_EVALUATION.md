# Đánh giá hiệu quả feature (Phase 4, 2026-11-08)

- **Protocol:** `configs/fe_study.yaml` (commit `e820605`). Code khóa ở `c22f8fc`, trước khi chạy ablation.
- **Kết quả gốc:** `artifacts/fe_study_v1/study/STUDY.json`. Log: `runs/fe_study/study.log`.
- **Thiết lập:**
  - nhãn sửa CNS2022; bản trùng toàn phần đã bị loại;
  - train trên inner-train;
  - M1 và M3 đo trên inner-val; M2 đo trên benign của S1 và R1 (dev) ở threshold α = 0.1% khóa trên C1;
  - công thức A0, 3 seed, không HPO.

## 1. Kết quả theo arm (mean qua 3 seed)
| Arm | #feat | M1 macro-F1 | M3 (fingerprint chưa thấy) | FPR S1 | FPR R1 | Incident báo nhầm/giờ (TB) | Recall tấn công S1 (Portscan/Infil, nhãn sửa) |
|---|---|---|---|---|---|---|---|
| **G0** (49 cột thô, như A0) | 49 | 0.9726 | 0.9687 | 0.099% | 0.011% | 20.1 | 0.006 |
| G_prep (categorical, port top-k, NaN cấu trúc, gom trùng, SMOTE có scale) | 49 | 0.9984 | 0.9981 | 0.107% | 0.020% | 24.4 | 0.002 |
| **G_shortcut_drop** (G0 bỏ src port, DNS id, TTL, TCP win) | 43 | 0.9726 | 0.9687 | 0.057% | 0.022% | 35.1 | 0.010 |
| G_ratio (+14 tỷ lệ) | 57 | 1.0000 | 1.0000 | 0.050% | 0.027% | 41.7 | 0.007 |
| control: ratio bị hoán vị | 57 | 0.9809 | 0.9782 | 0.033% | 0.018% | 31.4 | 0.007 |
| control: 14 cột nhiễu | 57 | 0.9726 | 0.9686 | 0.082% | 0.016% | 27.1 | 0.005 |
| G_flag (+25 bit cờ) | 68 | 0.9726 | 0.9687 | 0.077% | 0.016% | 26.7 | 0.009 |
| control: flag bị hoán vị / nhiễu | 68 | 0.9726 / 0.9726 | 0.9687 / 0.9686 | 0.074% / 0.084% | 0.017% / 0.016% | 30.4 / 28.8 | — |
| **G_ctx** (+10 feature ngữ cảnh causal) | 53 | 0.9957 | 0.9950 | **0.019%** | **0.070%** | **13.5** | **0.713** |
| control: ctx bị hoán vị | 53 | 0.9726 | 0.9686 | 0.062% | 0.015% | 26.9 | 0.005 |
| control: 10 cột nhiễu | 53 | 0.9726 | 0.9686 | 0.083% | 0.017% | 30.5 | 0.006 |

**Cách đọc:** từ G_ratio trở xuống, mỗi arm là **reference hiện hành (G_shortcut_drop)** cộng thêm nhóm tương ứng.

**F1 của lớp hiếm** (support inner-val: Web 27, XSS 30, **SQLi 2**):
- G0: Web 0.981, XSS 1.000, SQLi 0.800;
- G_ratio và G_prep: SQLi 1.000;
- G_ctx: XSS 0.966, SQLi 1.000.

Mọi khác biệt về M1 đến từ **1 flow SQLi và 1 flow Web**. Tất cả các lớp known khác có F1 = 1.000 ở mọi arm.

## 2. Quyết định theo luật đã khai báo
| Nhóm | ΔM1 | Vượt control hoán vị? | M2 không xấu hơn cận Wilson của reference ở **mọi** segment? | Shortcut / drift | Quyết định |
|---|---|---|---|---|---|
| G_prep | +0.026 | — | **Không** (R1: 0.020% so với cận 0.014%) | — | **Loại** |
| G_shortcut_drop | 0.000 (≥ −0.01) | — | FPR TB giảm 0.055% → 0.040% | Adversarial AUC 0.818 → 0.795 | **Chấp nhận** |
| G_ratio | +0.027 | Có (0.981) | **Không** (R1) | — | Loại |
| G_flag | 0.000 | Không | Không | — | Loại |
| G_ctx | +0.023 | Có (0.973) | **Không** (R1: 0.070%, gấp khoảng 3 lần) | — | Loại |

**Pipeline v2 = G0 bỏ `L4_SRC_PORT, DNS_QUERY_ID, MIN_TTL, MAX_TTL, TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT`** (43 cột). Không có preprocessing hay nhóm cộng thêm nào được chấp nhận.

## 3. Diễn giải (trung thực với giới hạn)
1. **M1 đã bão hòa và gần như không phân biệt được các arm.**
   - Trùng lặp nặng (EDA E2, E3) cùng việc mỗi lớp chỉ có một episode và một attacker khiến known class đạt F1 = 1.0 ở mọi arm.
   - Chênh lệch chỉ đến từ 1–2 flow web (SQLi có n = 2 trong val). Đây là điểm yếu của protocol: **M1 không đủ nhạy**, nên mọi kết luận "feature giúp phân loại lớp hiếm" đều **INCONCLUSIVE**.
2. **Tín hiệu thật nằm ở FP khi chuyển ngày (M2):**
   - **Bỏ shortcut** giảm FPR trên S1 (0.099% → 0.057%) và làm model khó phân biệt "ngày train" với "ngày khác" hơn (adversarial AUC giảm). Nhưng FPR trên R1 nhích lên (0.011% → 0.022%) và **incident báo nhầm/giờ tăng 20 → 35**, vì các FP rải ra nhiều host hơn. Luật bỏ shortcut (đã khai báo) không xét số incident; điều kiện này sẽ được kiểm tra trên holdout H3.
   - **G_ctx là một đánh đổi rõ rệt**, không phải lợi ích thuần:
     - trên S1, FPR giảm 3 lần, incident báo nhầm/giờ giảm còn 13.5, và **bắt được 71% Portscan/Infiltration** (nhãn sửa), trong khi mọi arm khác chỉ 0.2–1%;
     - trên R1, FPR tăng khoảng 3 lần (0.070%).
     - Control hoán vị và control nhiễu đều không tái tạo được hiệu ứng, nên đây là **thông tin thật** (hành vi theo host), không phải hiệu ứng số cột.
     - Bị loại theo luật vì R1 xấu hơn. Đây là **giả thuyết mạnh nhất cho bước sau**: ngữ cảnh causal giúp phát hiện scan, cần một cơ chế chặn FP trên R1. Chưa có claim.
   - **G_prep và G_ratio:** M1 tăng nằm trong mức nhiễu của 1–2 flow web, còn FPR trên R1 tăng. Không có lợi ích có thể chứng minh.
   - **G_flag:** không có thông tin mới. CatBoost đã tách được bit cờ từ giá trị số của bitmask.
3. **Chẩn đoán shortcut và drift** (model cuối, seed 0):
   - **Probe theo segment trên benign:** chỉ một feature có thể đoán ngày/segment. **L4_SRC_PORT đứng đầu** (macro-F1 0.333, mức ngẫu nhiên 0.167), MAX/MIN_TTL khoảng 0.30. Điều này củng cố việc bỏ chúng.
   - **Adversarial validation (train so với S1 + R1):** feature trôi nhiều nhất là L4_DST_PORT, SHORTEST_FLOW_PKT và throughput (drift do thành phần dịch vụ, EDA E6).
   - **Permutation importance theo nhóm** trên inner-val (ΔM1 khi hoán vị): kích thước packet và byte **0.460**, cờ TCP thô 0.113, port 0.091, timing −0.024.
   - **Top feature importance:** DST_TO_SRC_AVG_THROUGHPUT, L4_DST_PORT, L7_PROTO, SHORTEST_FLOW_PKT, TCP_FLAGS, OUT_BYTES.

## 4. Giới hạn
- Inner-val vẫn là **within-episode** (cùng attacker). Lớp hiếm có n = 2–30, nên không đủ để chọn feature dựa trên lớp hiếm.
- M2 dùng hai ngày dev (S1, R1) **đã từng được xem** ở các giai đoạn trước.
- Luật chấp nhận dùng điều kiện "**mọi** segment không xấu hơn cận Wilson". Luật này nghiêm, và đã loại cả G_ctx dù G_ctx tốt rõ trên S1. Luật **không được nới** sau khi xem kết quả.
- Đánh giá độc lập duy nhất là holdout H3/H4 ở Phase 5, chạy một lần sau tag `fe-v2-frozen`.
