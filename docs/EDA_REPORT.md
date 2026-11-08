# EDA và audit chất lượng dữ liệu (feature-engineering study, 2026-11-08)

- **Config:** `configs/fe_study.yaml` (khai báo trước ở commit `e820605`).
- **Code:** `src/netirava/eda.py` (`python -m netirava eda --config configs/fe_study.yaml`).
- **Artifact:** `artifacts/fe_study_v1/eda/` gồm `EDA.json`, `feature_profile.csv`, `drift_psi.csv`, `value_unseen_in_benign.csv`, `mutual_info.csv`.

## Phạm vi và chống leakage
- **Subset:** `CIC18-FE-Study-v1`, 3,181,717 row.
  - Holdout mới **H3** (23/02 benign) và **H4** (21/02 LOIC-UDP), tổng 427,783 row, **không được đọc** (`fe.study_frame` có assert).
  - H1 và H2 (đã dùng hết) không có trong config.
- **Phần không dùng nhãn** (profile, giá trị 0 cấu trúc, nhất quán nội tại, drift): chạy trên 2,753,934 row không thuộc holdout.
- **Phần có nhãn** (support, trùng lặp, host, mutual information, mức "giá trị chỉ có ở tấn công"): chỉ chạy trên **inner-train** (và calibration), với **nhãn sửa CNS2022**.
- **Inner split:**
  - T1–T4: 70% đầu theo thời gian / purge 5 phút / 30% cuối;
  - web theo split của pilot.
  - Số row theo vai trò: inner_train 560,658 · inner_val 128,537 · purged 117,512 · calib 278,255 · dev (S1 + R1) 1,156,487 · excluded (attempted/indeterminate) 1,338.

## Phát hiện chính và quyết định xử lý
| # | Phát hiện | Bằng chứng | Quyết định |
|---|---|---|---|
| E1 | **NF-v3 xuất phần lớn flow tấn công hai lần.** Hai row giống hệt nhau cả timestamp, IP, port và 49 feature, `row_id` liền nhau | GoldenEye 18,270/36,540 row, SSH 44,876/89,752, FTP 52,880/105,760 (inner train + val) là bản trùng toàn phần; Benign chỉ 6,168/440,220 (1.4%). Toàn bộ phần không holdout: **310,892 row** | Loại bản trùng toàn phần (giữ `flow_id` nhỏ nhất) cho **mọi** arm và mọi tập đánh giá. Không dùng nhãn, causal, áp dụng được lúc runtime (`fe.drop_exact_duplicates`). Đã ghi là deviation trong commit `c22f8fc` |
| E2 | **Trùng lặp theo feature rất nặng ở lớp tấn công** (khác timestamp) | Inner-train, số row / số fingerprint khác nhau: FTP 86,200 / 14,116; SSH 67,162 / 33,581; GoldenEye 26,368 / 13,184; Slowloris 14,248 / 5,043; XSS 50 / 26; Benign 366,572 / 349,907 | Gom row trùng (input + nhãn) thành một row có trọng số. Quy tắc SMOTE tính trên số row có trọng số. Thêm metric **M3 trên fingerprint chưa thấy** |
| E3 | **Val trùng với train, nên số đo bị thổi phồng** | Tỷ lệ fingerprint của inner-val đã có trong inner-train: **FTP 100%**, Slowloris 34%, Benign 5%; các lớp còn lại 0% | Báo M3 song song với M1. Kết quả FTP chỉ là "nhớ" |
| E4 | **Port nguồn gần như là thứ duy nhất làm các flow FTP khác nhau** | Khi port nguồn chỉ còn là nhóm (well-known / registered / ephemeral), FTP chỉ còn < 1000 tổ hợp input khác nhau (smoke test) | Port nguồn là **ứng viên shortcut**: thay bằng nhóm (G_prep) và thử bỏ hẳn (G_shortcut_drop) |
| E5 | **Benign trôi giữa các ngày, mạnh nhất ở port nguồn và TTL** | PSI của benign giữa inner-train và C1: L4_SRC_PORT **0.165**, L7_PROTO 0.078, MAX_TTL 0.059, MIN_TTL 0.058, CLIENT_TCP_FLAGS 0.057 | Củng cố giả thuyết shortcut cho port nguồn và TTL. Có adversarial validation trong study |
| E6 | Drift của toàn bộ traffic (không dùng nhãn) chủ yếu do thành phần dịch vụ | PSI trung bình (inner-train so với C1, S1, R1): L4_DST_PORT 1.72, L7_PROTO 1.44, TCP_WIN_MAX_IN 0.83 | Đây là drift về thành phần traffic (mỗi ngày một kịch bản), không phải lỗi. Port đích được giữ dưới dạng categorical top-k |
| E7 | **Giá trị 0 mang tính cấu trúc** | DNS_* khác 0 ở 99.99% flow DNS, 0.65% ngoài DNS. TCP_WIN và cờ TCP bằng 0 ở **100%** flow không phải TCP. FTP_COMMAND_RET_CODE **hằng 0** (cả với FTP) | P5: giá trị không áp dụng → NaN. FTP_COMMAND_RET_CODE không mang thông tin |
| E8 | **Artefact ICMP_TYPE trên flow TCP** | ICMP_TYPE khác 0 trên 202,066 flow TCP (ví dụ 15360 = 60·256): Benign TCP 15%, **Slowloris 40%**, GoldenEye 5%. Đây là giá trị rác của bộ chuyển đổi, nhưng lại tương quan với lớp | Gán NaN cho ICMP_* ngoài ICMP (P5). Tránh một shortcut do artefact |
| E9 | Histogram kích thước packet không khớp tổng số packet | 126,247 flow (4.6%), gần như toàn UDP benign, và histogram **lớn hơn** tổng (99.8%) | Giữ nguyên (đây là cách nProbe đếm). Các tỷ lệ trong G_ratio có thể > 1; ghi nhận, không sửa |
| E10 | Mâu thuẫn thời lượng | `DURATION_IN > FLOW_DURATION` ở 504 flow | Không đáng kể; giữ nguyên |
| E11 | Feature dư thừa (Spearman ≥ 0.95, inner-train) | LONGEST_FLOW_PKT ≡ MAX_IP_PKT_LEN (ρ = 1.0); ICMP_TYPE ≈ ICMP_IPV4_TYPE; RETRANSMITTED_*_BYTES ≈ *_PKTS; MIN_TTL ≈ MAX_TTL; IAT_MAX ≈ IAT_AVG; TCP_FLAGS ≈ CLIENT_TCP_FLAGS | Tree xử lý được cột dư thừa; không bỏ (không có lợi về accuracy). Ghi nhận để diễn giải importance |
| E12 | Mỗi lớp tấn công chỉ có **1 IP nguồn và 1 IP đích** trong inner-train | Đúng với cả 7 lớp tấn công. Benign có 9,652 nguồn | Probe shortcut theo host không dùng được (mỗi lớp trùng với đúng một host). Thay bằng probe nhận diện segment trên benign (deviation đã ghi) |
| E13 | **Support của lớp hiếm với nhãn sửa** | Inner-train: Web 43, **XSS 50, SQLi 15**. Inner-val: Web 27, XSS 30, **SQLi 2** | F1 của lớp hiếm sẽ gắn cờ INCONCLUSIVE khi n < 30 |

## Thông tin của từng feature (inner-train, nhãn sửa)
- **Mutual information cao nhất:** LONGEST_FLOW_PKT 1.42, MAX_IP_PKT_LEN 1.42, IN_BYTES 1.39, OUT_BYTES 1.38, TCP_FLAGS 1.33, các throughput 1.32–1.33, L4_DST_PORT 1.28, L7_PROTO 1.28.
- **Thấp nhất:** DNS_* (khoảng 0.19), RETRANSMITTED_* (khoảng 0.16), FTP_COMMAND_RET_CODE (0).
- **Feature có giá trị ở lớp tấn công mà benign không bao giờ có** (trung bình qua các lớp): IN_BYTES 0.36, FLOW_DURATION 0.36, DURATION_IN 0.34, LONGEST_FLOW_PKT 0.32, **L4_SRC_PORT 0.26**.

## Hệ quả cho thiết kế (Phase 2–4)
1. Mọi số liệu dùng dữ liệu **đã loại bản trùng toàn phần**; số của A0 v2 / pilot cũ đã tính trên dữ liệu còn trùng và không so trực tiếp được.
2. Known class có trần rất cao do trùng lặp và nhớ (E2, E3). Metric phân biệt được các arm là **M3** (fingerprint chưa thấy), **FPR ở các ngày khác (M2)** và **holdout mới**.
3. Các ứng viên được kiểm chứng qua ablation đã khóa:
   - port nguồn, TTL, DNS_QUERY_ID và TCP_WIN là ứng viên shortcut (E4, E5);
   - artefact ICMP (E8) và giá trị 0 cấu trúc (E7) được xử lý trong G_prep.
