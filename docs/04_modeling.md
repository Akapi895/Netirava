# 04. Modeling

## 1. Model
| | A0 v1 (MVP) | **A0 v2** | **Pilot `pilot_cns/s0`** |
|---|---|---|---|
| Thư mục | `artifacts/models_v1/a0` | `artifacts/models/a0` | `artifacts/models/pilot_cns/s0` |
| Hash | `be8f6d84bf2d` | `f32899bde8b4` | `f964bde1ef5c` |
| Known class | 5 (Benign, FTP, SSH, GoldenEye, Slowloris) | 8 (thêm Web, XSS, SQLi) | 8 |
| Nhãn train | gốc | gốc | sửa CNS2022 (bỏ attempted/indeterminate) |
| Threshold @ α = 0.1% | 0.003938 | 0.8679 | 0.00924 |
| Seed khác | — | `a0_s1`, `a0_s2` | `s1`, `s2` |

**Công thức chung** (kế thừa NP-v1, `../experiments/nextphase/configs.yaml`): CatBoost MultiClass, 1000 iteration, depth 6, l2 3, learning rate dò trên CPU rồi train trên GPU, SMOTENC cho lớp < 1,000 row. Output gồm lớp argmax, vector xác suất và `attack_score = 1 − p(Benign)` (điểm quyết định, chưa calibrate). Threshold: giá trị nhỏ nhất sao cho tỷ lệ benign của C1 (278,255 flow) có score ≥ t không vượt α. A0 v2: FPR đạt trên C1 0.100% [Wilson 0.089, 0.112].

Model không gọi tên được lớp chưa train; tấn công lạ chỉ lộ ra qua `attack_score` cao.

## 2. MVP, anomaly shadow và decision layer
### 2.1 MVP (A0 v1 + IsolationForest shadow, α = 0.1%)
| Scenario | Attack recall | Benign FPR | Episode phát hiện |
|---|---|---|---|
| Known (within-episode) | 0.9985 | 0.025% | 4/4; known macro-F1 0.993 |
| Bot (unknown) | 0.000 | 0.018% | 0/8 |
| Web (unknown ở v1) | 0.0055 | 0.007% | 2/97 |
| Infiltration (nhãn gắn cờ) | 0.0016 | 0.029% | 3/118 |

AUROC (không dùng threshold) cho Bot: A0 0.718, IsolationForest 0.923. Nhưng ở FPR 0.1% theo flow, shadow không thêm được flow hay episode nào mà A0 bỏ sót, chỉ thêm alert benign (Jaccard với A0 = 0). Shadow giữ ở chế độ shadow.

### 2.2 Decision layer V1–V4b (`src/netirava/decision.py`)
Mọi biến thể calibrate trên C1 ở cùng FPR tổng α:
- V1: A0;
- V2: anomaly;
- V3: A0 OR anomaly, mỗi nhánh α/2;
- V4a: A0@α/2 OR [anomaly ở top 1% và số flow bất thường của host trong 60 s ≥ k];
- **V4b** (đề xuất, đã khóa ở `e5336a8`): A0@α/2 OR [host có ≥ 50 flow trong 60 s và TB anomaly score ≥ τ@α/2].

Tham số chọn theo grid khai báo trước, chỉ trên dev Bot và Web; có hai vòng thiết kế (V4a không có lợi vì Bot nằm giữa mốc 90% và 95% của benign).

| Kết quả | α = 0.1% | α = 1% |
|---|---|---|
| Dev Bot, V1 | 0/8 episode | 0/8 |
| Dev Bot, V4b | 0/8 | **8/8**, recall 0.958, FPR 0.601%; Δ +0.958 [+0.872, +0.994] |
| **Holdout H1 DDoS LOIC-HTTP** (101,051 flow, 10 attacker), V1 | recall 0.000, FPR 0.122% | 0.757 (ở 0.5%: 0.707) |
| H1, V4b | 0.000 | 0.707; Δ so với A0 −0.050 [−0.055, −0.044] (ở 0.5%: −0.685) |

V4b bị bác bỏ: chia đôi ngân sách FPR làm nhánh A0 mất recall, trong khi nhánh anomaly không bắt được DDoS. Một ablation (TB `attack_score` của A0 theo host) bắt 78% DDoS ở α = 0.1%, nhưng được nhận ra sau khi xem holdout và làm FPR ngày Infiltration lên 3.5–6%, nên chỉ là giả thuyết.

## 3. Lớp hiếm và xử lý mất cân bằng (A0 v2)
Web/XSS/SQLi được đưa vào known class (T5 train 12:00–17:00, K5 eval 17:00–22:00 ngày 22/02, cùng episode). A0 là công thức chốt trước; A1 (không SMOTE) và A2 (class weight SqrtBalanced) chỉ là ablation.

**Theo lớp trên K1–K5** (nhãn gốc, seed 0, argmax):

| Lớp | Support | Precision | Recall [CI Wilson] | F1 A0 | F1 A1 | F1 A2 |
|---|---|---|---|---|---|---|
| Benign | 346,851 | 0.997 | 0.999 | 0.998 | 0.998 | 0.999 |
| FTP / SSH | 81,780 / 57,196 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| DoS-GoldenEye | 11,166 | 0.982 | 1.000 | 0.991 | 0.999 | 0.991 |
| DoS-Slowloris | 14,688 | 0.997 | 0.939 [0.935, 0.943] | 0.967 | 0.967 | 0.971 |
| Brute_Force_-Web | 715 | 0.762 | 0.776 [0.744, 0.805] | 0.769 | 0.726 | 0.738 |
| Brute_Force_-XSS | 257 | 0.386 | 0.833 [0.782, 0.873] | 0.528 | 0.517 | 0.526 |
| SQL_Injection | 290 | 0.810 | 0.059 [0.037, 0.092] | 0.109 | 0.020 | 0.111 |
| **Rare macro-F1** | | | | **0.469** | 0.421 | 0.458 |

- **Ổn định qua 3 seed:** rare macro-F1 của A0 là 0.469 / 0.487 / 0.525 (TB 0.494). Bỏ SMOTE giảm ở cả 3 seed (−0.048, −0.061, −0.143), nhưng CI bootstrap theo source IP của seed 0 là [−0.162, +0.003]. So với SqrtBalanced: −0.010, −0.028, +0.059 (không nhất quán). Kết luận: SMOTE tốt hơn không xử lý, chưa tốt hơn class weight.
- **SQLi:** 222/290 flow bị đoán thành XSS. 82% flow XSS và 75% flow SQLi trong eval có fingerprint đã xuất hiện ở train dưới nhãn khác. Gộp theo họ Web: F1 0.851.
- **Phát hiện binary** (threshold theo từng α):

| α | 0.05% | 0.1% | 0.5% | 1% |
|---|---|---|---|---|
| Recall Web / XSS / SQLi | 0.26 / 0.76 / 0.82 | 0.40 / 0.76 / 0.82 | 0.945 / 1.0 / 1.0 | 0.987 / 1.0 / 1.0 |
| FPR known_replay | 0.015% | 0.037% | 0.108% | 0.656% |
| FPR S1 (28/02) | 0.066% | 0.598% | 1.805% | 2.464% |
| FPR R1 (02/03) | 0.068% | 0.081% | 0.140% | 0.752% |

- **Cái giá:** A0 v1 (không có lớp web) chỉ có FPR 0.029% trên S1 ở α = 0.1%. Thêm lớp web làm threshold kém chuyển giao sang 28/02.
- **Cách đọc đúng:** các số trên đo khả năng tái tạo nhãn NF-v3. Trên nhãn sửa, A0 v2 có XSS F1 = 0 và báo nhầm 47.7% flow benign trong phạm vi máy chủ web (§5).

## 4. Holdout H2 DoS-Hulk
Hệ thống v3 (A0 v2, α = 0.1%) khai báo ở `5e98876`, chạy một lần trên 16/02 17:35–18:05: recall 0.928 ở FPR 0.050%, chỉ 1 episode và 1 attacker. Tấn công mới được phát hiện khi gần họ đã biết (Hulk thuộc DoS); họ lạ (DDoS ở FPR thấp, Bot) thì không.

## 5. Pilot trên nhãn sửa (`src/netirava/pilot.py`)
- **Thiết lập:** công thức A0 giữ nguyên, 3 seed, không HPO, threshold khóa trên C1.
- **Split:** trong mỗi cửa sổ web của CNS2022, 60% đầu để train, phần còn lại để eval; ngoài các cửa sổ, T5 để train và K5 để eval.
- **Support:** train Web 43, XSS 50, SQLi 15; eval Web 27, XSS 30, SQLi 2, Benign 1,026.

| Model · nhãn đánh giá (seed 0 / 1 / 2) | Web F1 | XSS F1 | SQLi F1 | Benign FPR trong phạm vi web |
|---|---|---|---|---|
| A0 v2 · nhãn gốc | 0.86 / 0.84 / 0.86 | 0.55 / 0.55 / 0.26 | 0.25 / 0.29 / 0.60 | 0 |
| A0 v2 · nhãn sửa | 0.52 / 0.53 / 0.62 | 0.00 / 0.00 / 0.00 | 0.12 / 0.08 / 0.01 | 47.7% |
| Pilot · nhãn sửa | 0.98 / 0.98 / 0.98 | 1.00 / 1.00 / 1.00 | 1.00 (n = 2) | 0 |

Pilot gần như hoàn hảo trên nhãn sửa, nhưng đó là within-episode: cùng attacker, cùng cửa sổ, flow gần như lặp lại. XSS/SQLi: INCONCLUSIVE.

| FP trên ngày khác (seed 0 / 1 / 2) | A0 v2 FPR | Pilot FPR | A0 v2 incident báo nhầm/giờ | Pilot incident báo nhầm/giờ |
|---|---|---|---|---|
| S1, nhãn gốc | 0.598 / 0.350 / 0.158% | 0.109 / 0.052 / 0.107% | 44 / 38 / 36 | 18 / 17 / 18 |
| S1, nhãn sửa | 0.105 / 0.068 / 0.074% | 0.093 / 0.016 / 0.096% | 42 / 36 / 34 | 16 / 15 / 16 |
| R1 | 0.081 / 0.065 / 0.073% | 0.012 / 0.008 / 0.009% | 5.6 / 3.8 / 3.2 | 11.4 / 6.8 / 8.8 |
| Known K1–K4 | 0.037 / 0.016 / 0.036% | 0.027 / 0.025 / 0.023% | 5.0 / 5.0 / 4.8 | 8.3 / 7.2 / 6.3 |

- **Lợi ích:** FP theo flow giảm. Trên R1 giảm 7–9 lần.
- **Cái giá:**
  - FP rải ra nhiều host hơn, nên incident báo nhầm/giờ tăng khoảng 2 lần trên R1 và known;
  - recall portscan giảm từ 6–11% xuống 0.5–0.7%;
  - S1 với nhãn sửa không cải thiện nhất quán (seed 2: 0.096% so với 0.074%).
- Trên H3/H4 (`03` §3): pilot có FPR H3 0.052% và bắt 9/10 episode LOIC-UDP ở α = 0.1%.

## 6. So sánh A0 v2 và pilot trên holdout mới H5–H9
Luật chọn khai báo trước trong ops study ([`protocols/ops_study_prereg.md`](protocols/ops_study_prereg.md) §5): chọn pilot nếu FPR không cao hơn, source incident báo nhầm/giờ ≤ 1.5 lần, và recall HOIC ≥ A0 v2 − 0.05.

| α = 0.1% | A0 v2 | Pilot |
|---|---|---|
| FPR gộp H5–H9 (913,211 benign) | 0.085% [0.080, 0.092] | 0.065% [0.060, 0.070] |
| FPR H7 / H8 / H5 / H6 / H9 | 0.043 / 0.084 / 0.127 / 0.086 / 0.103% | 0.026 / 0.032 / 0.098 / 0.063 / 0.113% |
| Source incident báo nhầm/giờ | 24.1 | 15.9 |
| Recall HOIC (H5, 10 attacker) | 0.036 | 0.813 |
| Recall Infilteration (H6, lớp nhãn gắn cờ) | 0.194 | 0.012 |
| FPR ở α = 0.5%, H7 / H8 | 0.231 / 0.386% | 0.510 / 0.575% |

Luật đạt, nên `configs/demo.yaml → final_system.model_dir` đang đặt `pilot_cns/s0`. Đây là **khuyến nghị**: việc chọn model nằm ngoài phạm vi ops study, và quyết định cuối thuộc người dùng ([`ops_change_audit.md`](ops_change_audit.md) §5). Bảng đánh đổi đầy đủ (lớp hiếm theo từng bộ nhãn, Bot, portscan) ở audit §5.2.

## 7. Chi phí (replay trên máy dev)
| Thành phần | Chi phí |
|---|---|
| A0 inference | 0.4–0.8 µs/flow |
| IsolationForest shadow | 3.7–10.8 µs/flow |
| Replay 1.67M flow (A0 v2) | khoảng 10.7 s wall |
| Peak RSS | khoảng 3.5 GB |
| Train A0 trên GPU | khoảng 20 s |

## 8. Review phương pháp SOTA
Tiêu chí: giải đúng vấn đề đã đo (nhãn sai, XSS/SQLi, FP), có code chính thức, có kết quả theo lớp và FPR, không tạo shortcut.

| Phương pháp | Đánh giá | Quyết định |
|---|---|---|
| HCE-Boost (Sci. Rep. 2026) | Expert cục bộ cho họ lớp hiếm cộng luật chỉnh xác suất bảo toàn khối của họ. Chỉ báo macro-F1; tác giả ghi expert không kích hoạt trên Edge-IIoT. Không sửa được nhãn hay thêm thông tin | Lấy ý tưởng bảo toàn khối xác suất cho family-aware (`05`) |
| HICID (Computer Networks 2026) | Không đọc được toàn văn | Không đánh giá |
| DIDS-MFL (IEEE TPAMI 2025) | Graph động theo IP, few-shot. Không thêm payload; rủi ro shortcut theo host như GraphIDS; chi phí cao | NO-GO |
| Hierarchical IDS (HFPD-IDS, CANET, Verkerken et al.) | Coarse-to-fine giảm nhầm attack thành benign, nhưng lỗi lan truyền và không thêm thông tin | Không triển khai |
| Engelen et al., CNS 2022 (data-centric) | Có code, bằng chứng mức PCAP, giải đúng nguyên nhân chính | Dùng để sửa nhãn (`02` §6) |
