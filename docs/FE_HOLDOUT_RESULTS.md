# Holdout mới H3/H4: kết quả cuối của feature-engineering study (Phase 5, 2026-11-08)

- **Chạy một lần** sau tag `fe-v2-frozen` (commit `4019679`), bằng `python -m netirava fe-final --config configs/fe_study.yaml`.
- **Kết quả gốc:** `artifacts/fe_study_v1/study/FINAL_HOLDOUT.json`. Log: `runs/fe_study/final.log`.
- **Holdout** (khai báo ở `e820605`, trước `prepare`; chưa từng được đọc trước bước này):
  - **H3** 23/02 14:00–15:00: 234,262 flow benign, ngày chưa từng dùng;
  - **H4** 21/02 14:00–15:00: 188,094 benign và **1,725** flow DDoS LOIC-UDP (10 episode/attacker; 3,450 flow gốc, một nửa là bản trùng toàn phần, cùng artefact với EDA E1).
  - Loại bản trùng toàn phần trên holdout: 3,702 row.
- **Các arm:**
  - **v2** = pipeline đã khóa (G0 bỏ 6 cột shortcut);
  - **reference** = G0 (49 cột thô);
  - cả hai được train trên cùng tập train cuối: T1–T4 đầy đủ và phần train của pilot ở web, nhãn sửa, đã loại bản trùng (650,248 row), 3 seed;
  - **tham chiếu đã đóng băng:** A0 v2 (nhãn gốc) và pilot `pilot_cns/s0`, không train lại.
  - Threshold của mọi model đều lấy trên benign của C1.

## 1. Kết quả (mỗi ô ghi seed 0 / 1 / 2)
**α = 0.1%** (operating point chính)

| Model | H3 FPR | H3 incident báo nhầm/giờ | H4 FPR | H4 recall LOIC-UDP (episode) |
|---|---|---|---|---|
| **v2** (43 cột) | 0.025 / 0.030 / 0.024% | 36.8 / 42.6 / 35.8 | 0.022 / 0.027 / 0.021% | 0 / 0 / 0 (0/10) |
| **reference G0** (49 cột, nhãn sửa, đã loại trùng) | **0.007 / 0.007 / 0.026%** | **13.6 / 12.6 / 32.9** | 0.018 / 0.018 / 0.033% | 0.0006 / 0 / 0.0006 (1/10, 0/10, 1/10) |
| A0 v2 (đóng băng, nhãn gốc) | 0.027% | 10.7 | 0.077% | 0 (0/10) |
| pilot_cns/s0 (đóng băng) | 0.052% | 18.4 | 0.018% | **0.093 (9/10)** |

**α = 1%**

| Model | H3 FPR | H4 FPR | H4 recall LOIC-UDP (episode) |
|---|---|---|---|
| v2 | 0.63 / 0.60 / 0.65% | 0.77 / 0.74 / 0.78% | 0.80 / 0.01 / 0.02 (10, 8, 8 trên 10) |
| **reference G0** | 0.46 / 0.61 / 1.43% | 0.57 / 0.64 / 0.83% | **0.99 / 0.98 / 0.65** (10, 10, 9 trên 10) |
| A0 v2 | 0.76% | 0.90% | 0.008 (8/10) |
| pilot_cns/s0 | 0.72% | 0.72% | 0.81 (10/10) |

## 2. Luật GO/NO-GO đã khai báo → **NO-GO** cho pipeline v2
| Điều kiện | Kết quả |
|---|---|
| H3: FPR (α = 0.1%) của v2 ≤ reference, **và** incident báo nhầm/giờ của v2 ≤ reference | **Không đạt.** FPR TB 0.026% so với 0.013%; incident 38.4 so với 19.7/giờ |
| H4: recall của v2 ≥ reference − 0.02 ở α = 0.1% và 1% | **Không đạt** ở α = 1% (0.28 so với 0.87) |

- **Bỏ cột shortcut** (src port, DNS id, TTL, TCP window) **làm kết quả kém hơn** trên dữ liệu độc lập.
- Mức giảm FPR trên S1 ở Phase 4 không chuyển giao sang H3. Trên H4, việc bỏ cột còn làm mất khả năng phát hiện flood UDP ở α = 1%.
- **Pipeline giữ nguyên 49 feature.** Quyết định "bỏ shortcut" ở Phase 4 bị **holdout bác bỏ**. Đây là kết quả âm được giữ lại.

## 3. Những gì holdout xác nhận được
1. **Mục tiêu FPR ≤ 0.1% ở α = 0.1% đạt được trên một ngày hoàn toàn mới.**
   - Trên H3 (n = 234,262), **mọi** model đều có FPR thực tế từ 0.007% đến 0.052%.
   - Cận trên Wilson 95% của reference G0 seed 0 là 0.011%.
   - Đây là bằng chứng **HO** mạnh nhất về kiểm soát FP mà dự án có, với support đủ lớn.
2. **Tấn công lạ kiểu flood UDP (LOIC-UDP):**
   - ở α = 0.1%, hầu như không được phát hiện theo flow (≤ 0.1%, trừ pilot 9.3%);
   - ở α = 1%, reference G0 bắt được 65–99%, đủ 9–10/10 episode, đổi lại FPR 0.6–0.8%.
   - Kết luận nhất quán với H1: tấn công lạ chỉ lộ ra ở ngân sách FPR cao hơn.
3. **Dao động theo seed rất lớn ở cùng công thức.**
   - Reference G0 seed 2: FPR trên H3 cao gấp 4 lần seed 0/1; recall trên H4 0.65 so với 0.99.
   - Không nên báo cáo kết quả của một seed duy nhất.
4. **So với các model đóng băng** (chỉ tham khảo, không thuộc luật GO):
   - reference G0 (nhãn sửa, đã loại trùng) có FPR trên H3 thấp hơn pilot (TB 0.013% so với 0.052%) và recall H4 ở α = 1% cao hơn (TB 0.87 so với 0.81);
   - nhưng pilot tốt hơn ở α = 0.1% trên H4 (9/10 episode);
   - A0 v2 (nhãn gốc) có FPR trên H4 cao nhất (0.077%).
   - **Chưa đủ để claim** model nào vượt trội: so sánh này không được khai báo trước, và mỗi model đóng băng chỉ có 1 seed.

## 4. Đóng góp của phần data engineering (sau holdout)
| Thành phần | Trạng thái |
|---|---|
| **Loại bản trùng toàn phần** (EDA E1: NF-v3 xuất phần lớn flow tấn công hai lần, cả trong holdout) | **Giữ.** Đây là sửa dữ liệu, không phải lựa chọn theo metric. Mọi số đếm tấn công cũ (A0 v2, pilot) bị thổi phồng khoảng 2 lần với FTP, SSH, GoldenEye và LOIC-UDP |
| Nhãn sửa CNS2022 cho train | Giữ (đã chốt từ trước) |
| G_prep, G_ratio, G_flag | Không có lợi ích chứng minh được (Phase 4) |
| **Bỏ shortcut** | **Bị holdout bác bỏ** |
| **G_ctx** (ngữ cảnh causal theo host) | Bị loại ở Phase 4 vì FPR trên R1, nhưng trên S1 bắt được 71% scan và giảm 3 lần incident báo nhầm. **Giả thuyết mạnh nhất** cho bước tiếp theo; không còn holdout sạch để kiểm chứng trong dataset này (H3/H4 đã dùng) |
| EDA, spec, test chống leakage, cách ly artifact | Hoàn thành; dùng lại được |

## 5. Giới hạn
- **Holdout chỉ có 2 cửa sổ 1 giờ**, một họ tấn công lạ (LOIC-UDP, 10 attacker). Lớp hiếm (Web, XSS, SQLi) **không có holdout**, vì chỉ có một episode.
- **H3 và H4 giờ đã dùng hết**, không dùng lại làm bằng chứng độc lập cho phương pháp mới.
- **Số incident báo nhầm/giờ** tính theo source IP với cooldown 15 phút, trên cửa sổ 1 giờ, nên rất nhạy với vài host benign hay gửi traffic.
