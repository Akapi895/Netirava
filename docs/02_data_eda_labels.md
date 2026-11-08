# 02. Dữ liệu, EDA và chất lượng nhãn

## 1. Nguồn
| Mục | Giá trị |
|---|---|
| Dataset | NF-CSE-CIC-IDS2018-v3 (NetFlow v3, University of Queensland), bag `f78acbaa2afe1595_NFV3DATA-A11964_A11964` |
| File | `datasets/NF-CSE-CIC-IDS2018-v3/.../data/NF-CICIDS2018-v3.csv`, 4,222,783,755 byte, chỉ đọc |
| sha1 | `ddcad6d826b73a128a447a0189137efd6c8f70c9`, khớp `manifest-sha1.txt` của bagit |
| Kích thước | 20,115,529 flow; 55 cột (49 feature NetFlow v3, 2 IP, 2 timestamp, `Label`, `Attack`) |
| Timestamp | epoch ms, đọc là UTC: 2018-02-14 12:28:07 → 2018-03-02 20:06:24 |
| Kiểm tra (`inspect`) | 0 null, 0 feature âm, 0 flow có `END < START`, 0 mâu thuẫn giữa `Label` và `Attack` |
| Nhãn | 15 nhãn gốc, giữ nguyên văn (kể cả chính tả `Infilteration`) |

Mỗi lớp tấn công chỉ xuất hiện trong một ngày UTC, gần như một burst liên tục (`runs/inspect/class_by_utc_day.csv`). Vì vậy không lớp nào có hai episode độc lập, và dữ liệu chỉ có thể chia theo cửa sổ thời gian.

## 2. Subset
**Quy tắc** (`dataset.prepare`): giữ mọi flow có `FLOW_START` trong `[start, end)` của một cửa sổ khai báo trong config. Không lấy mẫu từng row, không cân bằng lớp. Cửa sổ, vai trò và known class được chốt sau `inspect` (chỉ dùng support theo giờ) và trước khi train. `flow_id` là chỉ số dòng trong CSV gốc nên ổn định giữa các subset.

### 2.1 `CIC18-Causal-Demo-v1` (`configs/demo.yaml`, 3,139,471 flow)
| Segment | Vai trò | UTC | Benign | Tấn công |
|---|---|---|---|---|
| T1_0214_ftp_head | train | 02-14 14:25–15:05 | 133,273 | FTP-BruteForce 125,700 |
| K1_0214_ftp_tail | known_replay | 02-14 15:50–16:20 | 91,221 | FTP-BruteForce 81,780 |
| T2_0214_ssh_head | train | 02-14 17:55–18:50 | 149,678 | SSH-Bruteforce 100,140 |
| K2_0214_ssh_tail | known_replay | 02-14 19:05–19:40 | 106,364 | SSH-Bruteforce 57,196 |
| T3_0215_gold_head | train | 02-15 13:20–13:55 | 123,806 | DoS-GoldenEye 50,134 |
| K3_0215_gold_tail | known_replay | 02-15 13:55–14:20 | 76,197 | DoS-GoldenEye 11,166 |
| T4_0215_slow_head | train | 02-15 14:55–15:25 | 100,356 | DoS-Slowloris 21,352 |
| K4_0215_slow_tail | known_replay | 02-15 15:25–15:50 | 72,535 | DoS-Slowloris 14,688 |
| H2_0216_hulk | holdout | 02-16 17:35–18:05 | 92,598 | DoS-Hulk 100,076 |
| C1_0220_benign | calibration | 02-20 12:00–14:05 | 278,255 | — |
| H1_0220_ddos | holdout | 02-20 14:05–14:35 | 91,812 | DDoS LOIC-HTTP 101,051 |
| T5_0222_web_head | train (máy chủ web) | 02-22 12:00–17:00 | 534 | Web 903, XSS 223, SQLi 150 |
| K5_0222_web_tail | known_replay (máy chủ web) | 02-22 17:00–22:00 | 534 | Web 715, XSS 257, SQLi 290 |
| S1_0228_infil | stress | 02-28 15:00–15:40 | 160,416 | Infilteration 20,667 (gắn cờ chất lượng) |
| R1_0302_bot | replay | 03-02 13:30–17:30 | 858,080 | Bot 117,324 |

- T5 và K5 chỉ giữ flow đi từ hoặc tới các máy chủ web 172.31.69.28 và 172.31.69.1 (khai báo `scope_hosts`).
- Known class của A0 v2: Benign, FTP, SSH, GoldenEye, Slowloris, Brute_Force_-Web, Brute_Force_-XSS, SQL_Injection. Bot, Infilteration, DDoS và Hulk là unknown.

### 2.2 Các subset khác
| Subset | Config | Flow | Khác với demo |
|---|---|---|---|
| `CIC18-FE-Study-v1` | `configs/fe_study.yaml` | 3,181,717 | Bỏ H1/H2; thêm H3 (23/02 14:00–15:00, 235,852 benign) và H4 (21/02 14:00–15:00, 188,481 benign và 3,450 LOIC-UDP) |
| `CIC18-Ops-Holdout-v1` | `configs/ops_holdout.yaml` | 1,489,831 | Chỉ H5–H9: H5 HOIC 534,025 + 92,941 benign; H6 39,455 Infilteration + 252,503 benign; H7 177,986 và H8 180,753 benign; H9 3,140 Infilteration + 209,028 benign |

## 3. EDA
EDA chạy trên subset của feature study (`src/netirava/eda.py`, `artifacts/fe_study_v1/eda/`). Phần có nhãn chỉ chạy trên inner-train với nhãn sửa. Holdout không được đọc (có assert).

| # | Phát hiện | Bằng chứng | Xử lý |
|---|---|---|---|
| E1 | NF-v3 xuất phần lớn flow tấn công hai lần (trùng cả timestamp, IP, port và 49 feature, `row_id` liền nhau) | GoldenEye 18,270/36,540 row, SSH 44,876/89,752, FTP 52,880/105,760; Benign 1.4%. Ngoài holdout: 310,892 row | Loại bản trùng toàn phần cho mọi tập (`fe.drop_exact_duplicates`). Số đếm tấn công trước đó bị thổi phồng khoảng 2 lần |
| E2 | Trùng theo feature (khác timestamp) rất nặng ở lớp tấn công | Row / fingerprint: FTP 86,200 / 14,116; SSH 67,162 / 33,581; XSS 50 / 26; Benign 366,572 / 349,907 | Thêm metric trên fingerprint chưa thấy (M3) |
| E3 | Tập đánh giá trùng với train | Fingerprint inner-val đã có trong train: FTP 100%, Slowloris 34%, Benign 5% | Kết quả FTP là "nhớ" |
| E4 | Src port gần như là thứ duy nhất làm các flow FTP khác nhau | Nhóm src port thành 3 loại thì FTP còn < 1,000 tổ hợp input | Ứng viên shortcut |
| E5 | Benign trôi giữa các ngày, mạnh nhất ở src port và TTL | PSI inner-train so với C1: L4_SRC_PORT 0.165, L7_PROTO 0.078, MAX_TTL 0.059 | Ứng viên shortcut |
| E6 | Drift toàn traffic chủ yếu do thành phần dịch vụ | PSI TB: L4_DST_PORT 1.72, L7_PROTO 1.44 | Drift theo kịch bản của từng ngày, không phải lỗi |
| E7 | Giá trị 0 mang tính cấu trúc | TCP_WIN và cờ TCP bằng 0 ở 100% flow không phải TCP; FTP_COMMAND_RET_CODE luôn bằng 0 | Thử gán NaN (G_prep) |
| E8 | Artefact `ICMP_TYPE` trên flow TCP | 202,066 flow TCP có ICMP_TYPE ≠ 0; Slowloris 40%, Benign TCP 15% | Thử gán NaN để tránh shortcut |
| E9 | Histogram kích thước packet lớn hơn tổng packet | 126,247 flow, gần như toàn UDP benign | Giữ (cách nProbe đếm) |
| E11 | Feature dư thừa | LONGEST_FLOW_PKT ≡ MAX_IP_PKT_LEN (ρ = 1.0); MIN_TTL ≈ MAX_TTL | Giữ (tree xử lý được) |
| E12 | Mỗi lớp tấn công có đúng 1 IP nguồn và 1 IP đích trong train | Cả 7 lớp; Benign có 9,652 nguồn | Probe shortcut theo host không dùng được |
| E13 | Support lớp hiếm với nhãn sửa rất nhỏ | Train: Web 43, XSS 50, SQLi 15. Val: Web 27, XSS 30, SQLi 2 | Cờ INCONCLUSIVE khi n < 30 |

**Host và trùng lặp** (`dataset.audit`, subset demo): FTP, SSH, GoldenEye và Slowloris mỗi lớp có đúng một attacker IP, dùng chung giữa train và eval. 7/8 host Bot cũng gửi traffic benign trong cùng cửa sổ. Các fingerprint mang nhiều nhãn (XSS|SQLi 32, FTP|SSH 30, Benign|Infilteration 21) được giữ nguyên.

## 4. Forensics của false positive
Phạm vi: flow benign mà A0 v2 báo nhầm ở α = 0.1% (threshold 0.8679), run `20261108T122848`. Nguồn đối chiếu: Engelen et al., IEEE CNS 2022 ([tài liệu](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)), dựa trên phân tích PCAP của họ. NF-v3 sinh nhãn bằng cách khớp timestamp và 5-tuple với ground truth gốc của CIC ([Luay et al.](https://arxiv.org/pdf/2503.04404)), nên kế thừa lỗi nhãn của CIC. Trên máy không có PCAP, nên mọi kết luận "khớp luật CNS2022" chưa được kiểm chứng ở mức packet.

| Ngày | FP (nhãn gốc) | Nhóm chính | Phân loại |
|---|---|---|---|
| S1 28/02 | 959 flow (0.598%), 44 incident | 804 flow (2 incident) 172.31.69.24 → .15 trong cửa sổ NMAP của CNS2022: 580 cổng đích, 1 packet mỗi chiều | Portscan bị gắn Benign. Ở mức binary không phải FP; ở mức multiclass vẫn sai lớp (đoán Web BF) |
| | | 111 flow từ host Internet tới cổng 23/22/445/6379 | Quét nền Internet, chưa xác minh |
| R1 02/03 | 699 flow (0.081%), 28 incident | 524 flow UDP/500 và 5060 tới .28 | FP thật so với kịch bản; nguyên nhân là model học nhãn train sai (đúng mẫu này mang nhãn web ngày 22/02) |
| | | 175 flow nội bộ duyệt web ra ngoài | FP thật |

Nếu 804 flow NMAP được tính là tấn công, FPR của S1 giảm từ 0.598% xuống 0.097% (phân tích độ nhạy, EXP). Nhãn Infilteration lệch cả hai chiều: chỉ 3,585/20,667 (17%) flow dính tới victim .24, trong khi 12,633 flow từ .24 tới host nội bộ mang nhãn Benign.

## 5. Nhãn của các lớp web
Theo CNS2022, mọi web attack đi từ 18.218.115.60 tới 172.31.69.28 (BF 14:13–15:23, XSS 17:51–18:29, SQLi 20:14–20:27 UTC).

| Lớp | Flow mang nhãn | Credible (đúng cặp, trong cửa sổ, TCP/80) | Credible trong train T5 | Credible trong eval K5 |
|---|---|---|---|---|
| Brute_Force_-Web | 1,618 | 115 | 115/903 | 0/715 |
| Brute_Force_-XSS | 480 | 41 | 0/223 | 41/257 |
| SQL_Injection | 440 | 20 | 0/150 | 20/290 |

- Chỉ 176/2,538 flow web (6.9%) là credible. 993 flow (39%) là UDP/500 từ 562 IP nguồn.
- Model chưa từng thấy một flow XSS hay SQLi credible nào khi train. "Web F1 0.769" trên K5 được đo trên 715 flow không credible.
- Ngày 23/02, NF-v3 không có flow nào giữa cặp attacker và victim, nên không có episode web thứ hai.

**Collision fingerprint** (T5 + K5, 3,606 flow): 77 nhóm fingerprint mang nhiều nhãn. 100% row XSS và 87% row SQLi nằm trong các nhóm này. Nhóm lớn nhất là cùng một mẫu IKE UDP/500 (6 packet, 3,168 byte) mang ba nhãn web khác nhau tùy thời điểm. Collision vì vậy chủ yếu là lỗi nhãn, không phải hai tấn công có cùng biểu diễn.

## 6. Nhãn sửa theo CNS2022
`src/netirava/relabel.py` ghi `truth_cns2022.parquet` (sha1 `ff679256a42c…`) cạnh nhãn gốc, không sửa file gốc. Mỗi flow có `label_original`, `label_corrected`, `status`, `confidence`, `rule`. Ngày được audit: 22/02, 28/02, 02/03; ngày khác là `not_audited` và giữ nhãn gốc.

| Status | Ý nghĩa | Row |
|---|---|---|
| `confirmed` | Đặt theo luật tấn công (cặp IP + cửa sổ, có thể kèm cổng) | 133,711 |
| `background` | CNS2022 ghi nhận không phải tấn công (UDP/500, DHCP) → Benign | 1,033 |
| `indeterminate` | Nhãn tấn công không luật nào xác nhận hay bác bỏ → loại khỏi train và eval | 18,336 |
| `attempted` | Giai đoạn khởi động hoặc không payload → loại | 84 |
| `unchanged` / `not_audited` | Giữ nhãn gốc | 1,006,929 / 1,979,378 |

Thay đổi chính (35,730 row): Benign → Portscan 12,633; Infilteration → Portscan 3,585; Infilteration → Indeterminate 17,082; các nhãn web chuyển sang Benign, Indeterminate hoặc Attempted; 41 flow SQLi thành XSS. Toàn bộ 117,324 nhãn Bot khớp luật C2. Support sau khi sửa: Web 70, XSS 80, SQLi 17, mỗi lớp một episode và một attacker.

Xấp xỉ có khai báo: NetFlow không có độ dài payload, nên "zero payload" được xấp xỉ bằng `IN_PKTS ≤ 3` và `IN_BYTES ≤ 180` (confidence `medium`).

## 7. Kết luận về dữ liệu
| Yếu tố hạn chế | Mức đóng góp |
|---|---|
| Chất lượng nhãn | Chính: 93% nhãn web không credible; train không có XSS hay SQLi credible |
| Thiếu thông tin trong input | Thứ hai, cho XSS và SQLi thật: khác biệt nằm ở payload HTTP mà NetFlow không có |
| Mất cân bằng lớp | Phụ: SMOTE giúp nhưng không giải được hai yếu tố trên |
| Thuật toán | Phụ: đổi model không sửa được nhãn sai hay thêm payload |

Muốn claim tách XSS với SQLi cần episode độc lập thứ hai và nội dung HTTP từ PCAP gốc. Hướng mở rộng PCAP đã được thử ở `research/pcap_feasibility/` và dừng.
