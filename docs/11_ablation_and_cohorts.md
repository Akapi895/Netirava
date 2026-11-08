# 11. Ablation imbalance sạch và kiểm kê cohort thiểu số

Protocol khai báo trước: [`protocols/evidence_round2_prereg.md`](protocols/evidence_round2_prereg.md) §A–B (commit `d368fdc`).

## 1. Ablation: không resampling, class weighting, SMOTENC
- **Thiết lập chung cho cả ba arm:**
  - tập train cuối của feature study: 650,248 row, gồm toàn bộ T1–T4 và phần train của pilot ở web, nhãn CNS2022-adapted, bản trùng toàn phần đã loại;
  - 49 feature thô, công thức A0, seed 0/1/2;
  - threshold trên benign của C1 (đã loại trùng).
- **Code:** `src/netirava/ablation.py`. Kết quả: `runs/fe_study/ablation_clean.json`. Model: `artifacts/fe_study_v1/ablation_clean/`.
- **Arm:** `none` (không xử lý), `cw` (`auto_class_weights = Balanced`), `smotenc` (luật A0: lớp < 1,000 row → 1,000).
- **Support eval sau khi loại trùng:** web Benign 737, Web 27, **XSS 15**, SQLi 2; known FTP 40,890, SSH 28,598, Slowloris 7,344, GoldenEye 5,583.

### 1.1 Kết quả (seed 0 / 1 / 2)
| Metric | none | cw | smotenc | Kết luận theo luật (hơn ở cả 3 seed) |
|---|---|---|---|---|
| F1 Web (n = 27) | 0.962 ×3 | 1.000 ×3 | 0.981 ×3 | INCONCLUSIVE (n < 30); chênh lệch 1–2 flow |
| F1 XSS (n = 15), SQLi (n = 2) | 1.000 | 1.000 | 1.000 | INCONCLUSIVE |
| F1 GoldenEye (known) | 0.999 / 1.000 / 1.000 | 0.961 / 0.966 / 0.961 | 1.000 / 1.000 / 1.000 | cw **kém hơn** cả hai arm kia |
| F1 Slowloris (known) | 0.968 ×3 | 0.966 / 0.970 / 0.966 | 0.961 / 0.964 / 0.968 | Không phân biệt được |
| FPR S1, α = 0.1% | 0.018 / 0.103 / 0.010% | 0.013 / 0.102 / 0.035% | 0.032 / 0.020 / 0.050% | Không phân biệt được |
| FPR R1, α = 0.1% | 0.011 / 0.016 / 0.010% | 0.007 / 0.006 / 0.009% | 0.012 / 0.012 / 0.015% | Không phân biệt được (mức chênh vài flow) |
| False source incident R1, α = 0.1% | 43 / 68 / 48 | **31 / 30 / 42** | 61 / 52 / 74 | cw **tốt hơn** cả hai arm kia |
| Recall Portscan S1, α = 0.1% | 0.004 / 0.005 / 0.004 | 0.003 / 0.005 / 0.005 | 0.004 / 0.004 / 0.005 | Không phân biệt được (cả ba gần 0) |
| Recall Portscan S1, α = 1% | **0.70 / 0.48 / 0.56** | 0.03 / 0.22 / 0.03 | 0.15 / 0.12 / 0.33 | none tốt hơn cả hai arm kia |

**Holdout đã dùng** (EXP, chỉ mô tả, đã loại trùng):

| Metric | none | cw | smotenc |
|---|---|---|---|
| Recall HOIC (H5), α = 0.1% | 0.99 / 1.00 / 0.70 | **1.00 / 1.00 / 0.99** | 0.56 / 0.33 / 0.88 |
| Recall LOIC-UDP (H4), α = 1% | 0.21 / 1.00 / 0.01 | 0.96 / 0.22 / 1.00 | 1.00 / 0.96 / 0.65 |
| Recall Infilteration (H6), α = 1% | 0.54 / 0.51 / 0.45 | 0.22 / 0.45 / 0.03 | 0.26 / 0.30 / 0.27 |
| FPR H6, α = 1% | 4.76 / 3.79 / 3.60% | 0.49 / 0.84 / 0.91% | 0.77 / 0.61 / 1.95% |
| FPR H3 / H7 / H8, α = 0.1% | 0.01–0.03% | 0.01–0.06% | 0.01–0.07% |

### 1.2 Kết luận
- **Trên điều kiện sạch, không có bằng chứng SMOTENC giúp lớp thiểu số hay giảm tải analyst.**
  - SMOTENC chỉ hơn ở cả 3 seed tại F1 GoldenEye (hơn `none` 0.0003–0.0008, hơn `cw` khoảng 0.04) và FPR H6 ở α = 1% so với `none` (EXP).
  - SMOTENC kém `cw` ở false incident R1 và recall HOIC, kém `none` ở recall Portscan α = 1%, ở cả 3 seed.
  - Trên lớp hiếm, nó hơn `none` một flow Web (n = 27, INCONCLUSIVE).
- **Kết quả cũ "bỏ SMOTE làm giảm rare macro-F1 ở cả 3 seed"** (`04` §3) chỉ đúng với A0 v2: nhãn gốc NF-v3, chưa loại trùng, đánh giá trên K5 mà phần lớn nhãn web là nhiễu. Không nên dùng nó làm bằng chứng rằng SMOTE giúp lớp thiểu số thật.
- **Class weighting** giảm false incident trên R1 và giữ recall HOIC cao ở cả 3 seed, nhưng làm giảm F1 GoldenEye ở cả 3 seed. HOIC là holdout đã dùng, nên đây chỉ là gợi ý.
- **Lớp thiểu số:** cả ba arm gần hoàn hảo trên một episode, n = 27 / 15 / 2. Không đủ để phân biệt các cách xử lý mất cân bằng.
- Theo protocol, kết quả không đổi model cuối. Nếu có thêm dữ liệu độc lập, class weighting là ứng viên đáng thử hơn SMOTENC.

## 2. Kiểm kê cohort thiểu số trong toàn bộ dataset
- **Code:** `src/netirava/inventory.py`. Kết quả: `runs/minority_inventory/INVENTORY.json`, `episodes.csv`.
- **Phạm vi quét:** 20,115,529 row; 2,600,903 row tấn công, trong đó 507,042 row là bản trùng toàn phần.
- **Định nghĩa:** episode là (nhãn, IP nguồn, IP đích), tách khi nghỉ > 30 phút. "Đã dùng" nghĩa là giao với bất kỳ cửa sổ nào của ba config. "Credible" (chỉ áp cho lớp web) nghĩa là khớp luật CNS2022-adapted: đúng cửa sổ của nhãn, đúng cặp attacker–victim, TCP port 80.

| Nhãn | Flow (sau khi loại trùng) | Ngày | Episode | Episode chưa dùng | Flow chưa dùng (dedup) | Credible (flow duy nhất) | Cohort đủ điều kiện |
|---|---|---|---|---|---|---|---|
| Brute_Force_-Web | 1,618 (1,618) | 22/02 | 771 (561 nguồn) | 0 | 0 | 115, đều đã dùng | 0 |
| Brute_Force_-XSS | 480 (**20**) | 22/02 | 5 | 0 | 0 | 41, đều đã dùng | 0 |
| SQL_Injection | 440 (440) | 22/02 | 6 | 0 | 0 | 20, đều đã dùng | 0 |
| Infilteration | 188,152 (115,805) | 28/02, 01/03 | 5,477 | 3,448 (72 có ≥ 30 flow) | 31,103 | Không có luật (nhãn gắn cờ) | 0 |
| Bot | 207,703 (111,460) | 02/03 | 9 | 1 | 1 | Không có luật | 0 |
| DoS-SlowHTTPTest | 105,550 | 16/02 | 1 | 1 | 105,550 | Không có luật; feature trùng FTP | 0 |
| DDoS LOIC-HTTP | 288,589 | 20/02 | 20 | 10 (đuôi 17:00) | 2,153 | Không có luật; cùng 10 attacker với H1 | 0 |
| Các lớp khác (FTP, SSH, GoldenEye, Slowloris, Hulk, HOIC, LOIC-UDP) | — | Một ngày mỗi lớp | 1–10 | 0 | 0 | — | 0 |

**Phát hiện mới về nhãn:**
- **XSS:** 440/480 row là bản sao y hệt (cả timestamp và 49 feature) của một row mang nhãn web khác. Sau khi loại trùng chỉ còn 20 flow mang nhãn XSS.
- **Web và SQLi:** tương tự ở 168 row Web và 272 row SQLi.
- Một flow được NF-v3 xuất nhiều lần, mỗi lần một nhãn web khác nhau.
- Trên toàn dataset, cặp attacker–victim web chỉ có flow vào ngày 22/02. Ngày 23/02 không có flow nào của cặp này, kể cả flow mang nhãn Benign.

### 2.1 Kết luận
**Không có cohort nào đủ điều kiện.** Mọi episode của Web, XSS và SQLi nằm trong một ngày và đã được dùng cho train hoặc eval. Các episode chưa dùng thuộc lớp không có luật kiểm chứng (Infilteration), trùng feature với lớp khác (SlowHTTPTest), hoặc dùng chung attacker với holdout đã dùng (LOIC-HTTP). Vì vậy **robustness trên lớp thiểu số không thể xác nhận trong dataset này**. Tăng seed hay oversampling không tạo ra episode độc lập. Muốn có bằng chứng cần dữ liệu khác (PCAP gốc ngày 23/02 hoặc một dataset khác), và hướng đó nằm ngoài phạm vi đã chốt.
