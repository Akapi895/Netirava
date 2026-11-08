# 06. Incident triage và correlation theo campaign

## 1. Thiết kế triage
- **Gom incident** (`policy.py`, chạy trong replay): flow bị alert của cùng source IP, cách nhau ≤ 15 phút event time, thuộc một incident. Mỗi incident mới tạo một notification nếu còn budget B/giờ mô phỏng; phần vượt được ghi `budget_exceeded`. State reset ở ranh giới segment.
- **Hàng xem xét** (`campaign.review_queue`, một hàm cho mọi đơn vị): mỗi giờ chọn B mục trong số mục mở trong giờ đó, xếp theo:
  - `fifo`: mở sớm nhất;
  - `volume`: nhiều flow alert nhất tính tới cuối giờ (causal);
  - `severity` (khai báo trước): severity family-aware lớn nhất, rồi volume.
- `notified` (budget FIFO lúc chạy) và `queue_rank_*` (thứ tự hàng xem xét) là hai cột riêng trên UI và trong export.
- **UI Streamlit** (`python -m netirava ui --run <run_id>`):
  - chỉ số tổng: flow alert, incident, tỷ lệ nén;
  - hàng top-B mỗi giờ;
  - chi tiết incident gồm flow, đích, port, score, nhãn family-aware và lý do uncertain;
  - feedback append-only (có người xác nhận và nguồn, không có vòng học lại);
  - tab "Threshold reliability" (`07`).
- UI và export không đọc nhãn.

## 2. Kết quả triage theo source incident
| Scenario · α · model | Flow alert | Incident | Nén | Episode phủ @ 10 incident/giờ: FIFO → priority (volume) | Precision incident @ 10/giờ |
|---|---|---|---|---|---|
| H1 DDoS · 0.5% · A0 v1 | 71,774 | 175 | 410 | 0/10 → 10/10 | 1.00 |
| H1 DDoS · 1% · A0 v1 | 77,062 | 317 | 243 | 0/10 → 10/10 | 1.00 |
| Bot · 1% · V4b (shadow) | 121,353 | 266 | 456 | 0/8 → 8/8 | 0.16 |
| Known · 0.1% · A0 v2 | 164,781 | 161 | 1,024 | 0.148 → 0.137 (@ 30/giờ: 0.306) | 0.74 |

- Gom incident giảm tải 2–3 bậc độ lớn.
- Luật ưu tiên theo volume được đặt sau khi thấy FIFO thất bại, nên số của H1 là EXP.
- **Severity so với volume** (DEV, α = 0.5%): episode phủ @ 30 là 0.311 so với 0.313; có lúc severity làm SSH rơi khỏi hàng. Trên H2, cả ba chính sách phủ 1/1 episode.
- **Nút thắt là đơn vị gom.** Trên nhãn gốc, web brute-force đến từ 562 IP, tạo 386 episode nhỏ, vượt xa budget 10–30/giờ. Đây là lý do thử correlation theo campaign.

## 3. Correlation theo campaign
Protocol khai báo trước: [`protocols/ops_study_prereg.md`](protocols/ops_study_prereg.md). Code: `src/netirava/campaign.py`.

- **Khóa:** (host đích, họ dự đoán family-aware; argmax Benign → `Unknown`). Ablation: chỉ host đích.
- **Gán causal:**
  - khi một source incident mở, nó gia nhập campaign đang giữ khóa của flow đầu tiên (khóa còn sống nếu flow cuối trên khóa cách ≤ 15 phút), hoặc tạo campaign mới;
  - các flow sau đăng ký thêm khóa nếu khóa chưa thuộc campaign khác;
  - không bao giờ gộp hai campaign đã có; reset theo segment.
- **Đơn vị xem xét: campaign update.** Mỗi giờ, các source incident mở trong giờ đó và thuộc cùng campaign tạo thành một mục. Số campaign update mỗi giờ không bao giờ vượt số source incident.
- **Sai lệch so với pre-registration** (ghi ở commit `9ab983c`, trước holdout): bản pre-register cho mỗi campaign vào hàng một lần lúc mở. Trên DEV (K5, nhãn sửa), một SQLi thật lúc 20:16 gia nhập campaign đã mở từ 17:00 trên cùng máy chủ web (80 nguồn, phần lớn benign) và không bao giờ được xem. Loại tấn công được phủ giảm từ 0.833 xuống 0.667. Campaign update khôi phục 0.833; bản "open-once" vẫn được báo cáo.
- **Không làm thay đổi alert, FPR hay source incident** (`ops_change_audit.md` §3).

### 3.1 Luật GO (khai báo trước)
| Luật | Nội dung |
|---|---|
| G1 lợi ích | Trên H5 HOIC, episode phủ (strict) hoặc attack-flow phủ của campaign ≥ source + 0.05 |
| G2 không mất tấn công | Không loại tấn công nào được phủ bởi source mà không được phủ bởi campaign |
| G3 không ngụy trang FP | Source incident chỉ-benign bị gộp vào campaign có tấn công ≤ 5% |
| G4 độ trễ | Trung vị thời gian tới lần xem đầu không chậm hơn > 15 phút |

"Strict" chỉ tính flow quyết định trước lúc xem xét; "case" tính cả flow đến sau trong một case đang mở.

## 4. Kết quả correlation
### 4.1 Holdout H5–H9 (α = 0.1%, severity, B = 10/giờ, nhãn gốc)
Số đếm trên toàn cửa sổ; exposure H5 = 0.5 giờ, H6–H9 = 1 giờ mỗi cửa sổ, tổng 4.5 giờ. Bản trước của bảng này chia cho số ô giờ có event (9 ô cho 4.5 giờ), nên các số "/giờ" cũ bị lệch; xem `10` §6.

| Model | Scenario | Mục: source → campaign | Mục báo nhầm: source → campaign | Episode phủ (strict) | Contamination |
|---|---|---|---|---|---|
| A0 v2 | H5 HOIC | 46 → 5 | 36 → 4 | 0.80 → 1.00 | 0.00 |
| A0 v2 | H6 01/03 | 44 → 8 | 18 → 5 | 0.033 → 0.116 | 0.61 |
| A0 v2 | H7 benign 16/02 | 11 → 6 | 11 → 6 | – | – |
| A0 v2 | H8 benign 20/02 | 78 → 10 | 78 → 10 | – | – |
| A0 v2 | H9 28/02 tối | 75 → 12 | 74 → 11 | 0.00 → 0.05 | 0.05 |
| Pilot | H5 HOIC | 24 → 7 | 14 → 6 | 1.00 → 1.00 | 0.57 |
| Pilot | H6 01/03 | 19 → 16 | 16 → 14 | 0.011 → 0.017 | 0.13 |

Gộp H5–H9: A0 v2 254 → 41 mục (báo nhầm 217 → 36), pilot 156 → 81 (143 → 78). "Mục báo nhầm giảm" là giảm số lần mở một mục, không phải giảm false positive: FPR và số flow benign bị alert không đổi.

| Luật | A0 v2 (nhãn gốc / sửa) | Pilot |
|---|---|---|
| G1 | đạt (0.80 → 1.00) | không đạt (đã là 1.00) |
| G2 | đạt (0 loại bị mất) | đạt |
| G3 | **không đạt** (6.9% / 5.07%) | **không đạt** (7.0%) |
| G4 | đạt (Δ trung vị 0 s) | đạt |
| **Kết luận** | **NO-GO** | **NO-GO** |

### 4.2 Cơ chế contamination
- **A0 v2, H6/H9:** nguồn Internet mang nhãn Infilteration (lớp gắn cờ) và nguồn benign cùng nhắm 172.31.69.15 / .7 với họ dự đoán Web, nên chung khóa. Một phần có thể do nhãn sai, nhưng luật không cho loại trừ sau khi xem kết quả.
- **Pilot, H5:** HOIC bị chấm argmax Benign (họ `Unknown`). 8 nguồn benign có alert `Unknown` tới .28 bị gộp vào campaign DDoS 434,279 flow. Analyst sẽ thấy 8 host vô hại như thành viên DDoS.

### 4.3 DEV và EXP (chỉ để phát hiện lỗi)
| Run | Quan sát |
|---|---|
| K1–K5, nhãn gốc, A0 v2 | Episode phủ 0.132 → 0.303, chủ yếu nhờ gộp các "episode web" mà phần lớn là nhãn sai |
| K1–K5, nhãn sửa | Source 0.833, campaign update 0.833, open-once 0.667 |
| S1, A0 v2 | Contamination 0.805 (nhãn gốc), 0.31 (nhãn sửa): cảnh báo sớm cho G3 |
| H2 DoS-Hulk (EXP) | 9 → 3 mục (báo nhầm 8 → 2) trên 0.5 giờ, cùng phủ 1/1 episode, contamination 0 |

## 5. Kết luận
- Source incident là đơn vị mặc định của hàng xem xét (`ops.ui_default_unit`).
- Campaign có trên UI như view thử nghiệm, kèm ghi chú NO-GO.
- Lợi ích có thật trên DDoS nhiều nguồn (HOIC), nhưng chỉ có một holdout nhiều nguồn và tỷ lệ gộp nhầm benign vượt ngưỡng.
