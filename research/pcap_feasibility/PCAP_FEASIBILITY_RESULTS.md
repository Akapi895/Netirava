# RQ-PCAP: feasibility results (Phase 3–4)

**Dataset:** IoT-23, 3 capture (34-1 Mirai, 8-1 Hakai, 20-1 Torii), 36,757 flow. **Không phải NF-CSE-CIC-IDS2018-v3.**

- **Provenance:**
  - protocol khóa ở `2feaa35`, code khóa ở `973b4c8` (cả hai trước khi đánh giá);
  - kết quả gốc: `results/loco_main.json`, `loco_ablation_groups.json`, `capture_identifiability.json`, `within_capture_multiclass_EXPLORATORY.json`, `coverage.json`, `run_log.json`;
  - bảng: `results/SUMMARY.md` (do `scripts/summarize.py` sinh).
- **Model:** CatBoost CPU, 500 iteration, depth 6, lr 0.1, 3 seed (0, 1, 2), **không HPO**.
- **Split chính: leave-one-capture-out (LOCO)**, binary Benign / Malicious:
  - train trên 70% đầu (theo thời gian) của hai capture còn lại;
  - threshold lấy trên benign của 30% cuối các capture train, rồi khóa;
  - test trên capture bỏ ra, là một **họ malware chưa thấy khi train**.
- **Số flow chưa qua tổng hợp:** số flow chi tiết (flow-level) có trong `results/*.json`.

## 1. Support và mức FPR
| Fold (test) | Benign test | Malicious test | Benign calibration | FPR 1% | **FPR 0.1%** |
|---|---|---|---|---|---|
| 34-1 Mirai | 1,923 | 21,222 | 1,608 | OK | **INSUFFICIENT SUPPORT** (calibration < 3,000, test < 3,000) |
| 8-1 Hakai | 2,181 | 8,222 | 1,133 | OK | **INSUFFICIENT SUPPORT** |
| 20-1 Torii | 3,193 | **16** (1 đích) | 815 | OK | **INSUFFICIENT SUPPORT** (calibration 815) |

- **Mức 0.1%:** với ≤ 1,608 benign, threshold 0.1% chỉ là điểm cao nhất của calibration. **Không kết luận được gì về ràng buộc FPR ≤ 0.1%.** Quan sát 0 FP trên 1,923 benign vẫn tương ứng cận trên Wilson 95% khoảng 0.2%.
- **Quyết định dùng mức 1%** (đã khai báo trước) cộng với PR-AUC.

## 2. Kết quả chính: LOCO binary (mean ± sd qua 3 seed)
| Test | Set | #feat | PR-AUC | Recall @ thr 1% (cal) | **FPR thực tế trên test** @ thr 1% | Precision | False incidents | Oracle recall @ test-FPR 1% |
|---|---|---|---|---|---|---|---|---|
| 34-1 Mirai | **A** | 11 | 0.989 ± 0.005 | 1.000 | 0.075 ± 0.005 | 0.993 | 4.0 ± 3.6 | 0.08 ± 0.12 |
| | B | 64 | 0.992 ± 0.000 | 1.000 | 0.075 ± 0.002 | 0.993 | 4.0 ± 2.8 | 0.00 |
| | **C** | 75 | 0.988 ± 0.002 | 1.000 | 0.073 ± 0.000 | 0.993 | 2.7 ± 1.2 | 0.00 |
| | A + noise | 75 | 0.975 ± 0.001 | 1.000 | 0.079 ± 0.009 | 0.993 | 4.7 ± 3.9 | 0.00 |
| | A + B hoán vị | 75 | 0.993 ± 0.002 | 1.000 | 0.241 ± 0.162 | 0.979 | 9.7 ± 6.2 | 0.17 ± 0.08 |
| 8-1 Hakai | **A** | 11 | 1.000 | 0.667 ± 0.471 | 0.001 | 0.667 | 2.0 | 1.000 |
| | B | 64 | 1.000 | 1.000 | 0.001 | 1.000 | 2.0 | 1.000 |
| | **C** | 75 | 0.999 | 0.750 ± 0.354 | 0.001 | 1.000 | 2.0 | 1.000 |
| | A + noise | 75 | 0.998 | 1.000 | 0.001 | 1.000 | 2.0 | 1.000 |
| | A + B hoán vị | 75 | 0.999 | 1.000 | 0.001 | 1.000 | 2.0 | 1.000 |
| 20-1 Torii | **A** | 11 | 1.000 | 1.000 | 0.158 ± 0.042 | 0.033 | 23.0 | 1.000 |
| | B | 64 | 1.000 | 1.000 | 0.023 ± 0.017 | 0.251 | 19.3 ± 5.2 | 1.000 |
| | **C** | 75 | 1.000 | 1.000 | 0.160 ± 0.044 | 0.033 | 15.0 ± 5.7 | 1.000 |
| | A + noise | 75 | 1.000 | 1.000 | 0.150 ± 0.063 | 0.043 | 20.0 ± 2.2 | 1.000 |
| | A + B hoán vị | 75 | 1.000 | 1.000 | 0.148 ± 0.076 | 0.052 | 26.7 ± 7.6 | 1.000 |

*"Oracle" = threshold lấy trên benign của test, chỉ để phân tích, không triển khai được. False incident = incident (orig_h, cooldown 15 phút) không chứa flow malicious nào.*

**Hiệu C − A theo từng seed:**

| Fold | ΔPR-AUC | ΔRecall @1% | ΔFPR test |
|---|---|---|---|
| 34-1 | +0.004, +0.003, −0.008 | 0, 0, 0 | +0.003, −0.009, +0.001 |
| 8-1 | −0.000, +0.000, −0.001 | 0, 0, **+0.25** | 0 |
| 20-1 | 0, 0, 0 | 0, 0, 0 | −0.101, +0.015, +0.090 |

- **Ở seed 2 của 8-1:** A tụt về recall 0 và C về 0.25 tại threshold đã khóa, trong khi **A + noise đạt 1.0**. Đây là **bất ổn khi chuyển threshold**, không phải thông tin mới: oracle recall của mọi set đều 1.0.

### Đọc kết quả
1. **Trần (ceiling).**
   - A, với 11 feature conn.log, đã đạt PR-AUC 0.989–1.000. Ở 8-1 và 20-1, mọi set có oracle recall 1.0.
   - Lý do: **benign 98.4% là UDP (NTP, DNS), malicious 99.99% là TCP**. Feature quan trọng nhất của A là `proto` (74–88% importance) và `resp_p`.
   - Thiết lập này **gần như không còn chỗ** để B thể hiện giá trị.
2. **C không vượt A, cũng không vượt control.**
   - Ở 34-1: C − (A + B hoán vị) về PR-AUC = −0.007, −0.003, −0.003. Tức là khi phá liên hệ giữa B và nhãn, kết quả **không tệ hơn**.
   - A + noise kém A một chút (−0.008 đến −0.019 PR-AUC ở 34-1): thêm cột không giúp gì.
   - **Không tách ra được lợi ích nào do thông tin packet/protocol.**
3. **B thay thế thông tin, không bổ sung thông tin.**
   - Trong C, importance chuyển sang cờ TCP và kích thước packet đầu (`o_fin`, `o_ack`, `r_syn`, `first1_signed_size`, `r_urg`…).
   - Đó vẫn là thông tin "đây là TCP / handshake kiểu gì", trùng với `proto`/`conn_state` của A. Kết quả cuối không đổi.
4. **Threshold không chuyển giao được giữa các capture, với mọi set.**
   - Threshold khóa ở FPR 1% trên calibration cho FPR thực tế **7.5% ở 34-1** và **15–16% ở 20-1** (A, C).
   - Mục tiêu FPR **bị vi phạm ở 2/3 fold bởi mọi feature set**. Nguyên nhân:
     - 34-1 có 111 flow benign TCP, trong đó 65 flow tới `185.244.25.235:80`; trông giống C&C và có thể là nhãn sai;
     - phân bố benign khác nhau giữa các thiết bị.
   - Riêng **B** trên 20-1 có FPR thực tế thấp hơn (0.023 so với 0.158; nhất quán qua 3 seed). Nhưng **C không thừa hưởng** điều đó, và xếp hạng (PR-AUC, oracle recall) của mọi set đều bằng nhau.
   - Đây là khác biệt về **chuyển threshold khi B không có `proto`/`resp_p`**, không phải bằng chứng rằng thêm B vào flow giúp ích.
5. **False incidents:**
   - C thấp hơn A ở 34-1 (2.7 so với 4.0) và 20-1 (15.0 so với 23.0);
   - nhưng sd qua seed rất lớn (±1.2 đến ±5.7) và FPR theo flow gần như bằng nhau. **Không đủ để claim.**

## 3. Theo họ tấn công (recall @ threshold 1% đã khóa, mean qua seed)
| Fold | Họ | Số đích | A | B | C |
|---|---|---|---|---|---|
| 34-1 | C&C (Mirai) | 1 | 1.000 | 1.000 | 1.000 |
| 34-1 | DDoS | 3 | 1.000 | 1.000 | 1.000 |
| 34-1 | PartOfAHorizontalPortScan (n = 122) | 2 | 1.000 | 0.992 | 0.997 |
| 8-1 | C&C (Hakai) | 2 | 0.667 | 1.000 | 0.750 |
| 20-1 | C&C-Torii (**n = 16**) | 1 | 1.000 | 1.000 | 1.000 |

- **Không họ nào cho thấy C tốt hơn A một cách ổn định.**
- Số "tình huống" độc lập chỉ là **1–3 đích cho mỗi họ**.

## 4. Kiểm tra shortcut, artefact và ablation
- **Bản ghi Zeek có 0 packet** (14,260 bản ghi DDoS ở 34-1, xem `FEATURE_EXTRACTION_REPORT.md` §3). Khi loại chúng ra:
  - PR-AUC: A 0.974 ± 0.016, B 0.984 ± 0.001, C 0.974 ± 0.006, A + B hoán vị 0.992;
  - recall @1% bằng 1.0 với mọi set.
  - Lợi thế "B thấy được packet mà conn.log bỏ sót" **không chuyển thành lợi thế cho C**.
- **Capture identifiability** (đoán capture từ feature của flow benign, CV 5 fold; chance 0.333):

| Set | macro-F1 |
|---|---|
| A | 0.712 |
| B | 0.769 |
| C | 0.768 |

  B mang **nhiều dấu vết môi trường hơn A**, tức rủi ro shortcut theo môi trường cao hơn.
- **Ablation bỏ từng nhóm B khỏi C** (seed 0, EXP):
  - mọi |ΔPR-AUC| ≤ 0.007; ΔRecall = 0;
  - ngoại lệ: bỏ `zeek_service` ở 8-1 cho ΔRecall −0.75, cùng kiểu bất ổn threshold như ở seed 2.
  - **Không nhóm nào mang lợi ích riêng.**
- **Leakage:**
  - không dùng IP, `orig_p`, `ts`, uid, `capture_id`, nhãn, cờ join, TTL / IP-ID / window hay chuỗi thô;
  - có test `test_feature_sets_have_no_identifiers_labels_or_join_artefacts`;
  - không loại sample nào: 100% flow đều được giữ.

## 5. Multiclass trong từng capture: EXPLORATORY
- **Split:** 60% đầu / 40% cuối theo thời gian trong từng capture, gộp lại. Malware **giống** nhau giữa train và test, nên chỉ là bằng chứng thăm dò.
- **Lớp được chấm:** C&C, DDoS, Benign. PortScan và C&C-Torii có < 20 mẫu ở train hoặc test nên không chấm.

| Set | macro-F1 | F1 C&C | F1 DDoS | F1 Benign | Benign FPR (argmax) |
|---|---|---|---|---|---|
| A | 0.987 | 1.000 | 0.990 | 0.972 | 0.000 |
| B | 0.987 | 1.000 | 0.990 | 0.972 | 0.000 |
| C | 0.987 | 1.000 | 0.990 | 0.972 | 0.000 |

Ba set **giống hệt nhau** (trần). Không có thông tin phân biệt A, B, C.

## 6. Chi phí
| Hạng mục | A | B | C |
|---|---|---|---|
| Trích feature | có sẵn trong conn.log | ≈ 95k packet/s (dpkt, 1 luồng); 0.85–5.0 s / capture; peak RSS 120–300 MB | như B |
| Fit (CPU, 8 luồng) | 11.2 s | 12.8 s | 13.7 s |
| Inference | 0.92 µs/flow | 1.30 µs/flow | **1.94 µs/flow (≈ 2.1× A)** |

- **Pipeline đánh giá:** chạy hết trong 1,179 s; peak RSS ghi ở `results/run_log.json`.
- **Dữ liệu:**
  - B cần PCAP;
  - ở CIC-2018, PCAP lớn hơn flow CSV khoảng 2–3 bậc độ lớn (38–59 GB/ngày);
  - riêng một host thì nhỏ (web server 22/02: 25.7 MB).

## 7. Source A: kiểm tra join trên dataset của Netirava (không có model)
- **Kết quả:** NF-v3 ↔ PCAP của web server 22/02 join được **85.7%**; số packet khớp đúng 100% trên các flow join được.
- **Thất bại:** chỉ "XSS" là join không được (4.2%). Các flow này là IKE/500 từ IP AWS và DHCP; không có HTTP tấn công trong pcap.
- **Ý nghĩa:**
  - **Khả năng kỹ thuật:** đã chứng minh được việc làm giàu flow NF-v3 bằng packet.
  - **Chưa trả lời** RQ-PCAP trên NF-v3. Muốn trả lời cần thêm dữ liệu, cần protocol mới, và cần nhãn web đã sửa (CNS2022), vì nhãn gốc của lớp hiếm là nút thắt.

## 8. Giới hạn
- **Không chuyển giao sang Netirava:**
  - IoT-23 không phải NF-v3;
  - A ở đây (conn.log, 11 feature) nghèo hơn NetFlow v3 (49 feature, đã có cờ TCP, IAT, histogram kích thước);
  - kết quả **không** chuyển giao được sang Netirava, theo cả hai chiều.
- **Về dữ liệu:**
  - 3 capture, mỗi capture một thiết bị nhiễm, benign là traffic nền của chính thiết bị đó (gần như toàn NTP và DNS);
  - mỗi họ chỉ có 1–3 đích;
  - **không có traffic mã hóa** (TLS/SSH 0%) và gần như không có metadata ứng dụng ở malicious (100% không có metadata). Phần "protocol-level" của B gần như **không được kiểm tra**: chỉ phần packet-level thực sự có dữ liệu.
- **Về FPR:**
  - mức FPR 0.1%: **INSUFFICIENT SUPPORT** ở mọi fold;
  - mức 1%: threshold không chuyển giao qua capture, với mọi set.
- **Về phương pháp:** mỗi split chỉ chạy một model cấu hình cố định, có 3 seed. Không có HPO, nên không loại trừ được khả năng B cần cấu hình khác.
