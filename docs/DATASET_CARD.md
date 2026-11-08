# Dataset card — CIC18-Causal-Demo-v1

Subset dẫn xuất từ **NF-CSE-CIC-IDS2018-v3** (NetFlow v3, University of Queensland; bag `f78acbaa2afe1595_NFV3DATA-A11964_A11964`). File gốc không bị di chuyển hay sửa; subset được tái lập bằng `python -m netirava prepare --config configs/demo.yaml`.

## Nguồn (đã xác minh bằng `inspect`, `runs/inspect/INSPECT.json`)
| | |
|---|---|
| CSV | `datasets/NF-CSE-CIC-IDS2018-v3/.../data/NF-CICIDS2018-v3.csv`, 4,222,783,755 byte. Tên file khác tên thư mục; file không bị đổi tên |
| sha1 | `ddcad6d826b73a128a447a0189137efd6c8f70c9`, **khớp** `manifest-sha1.txt` của bagit (cũng trùng checksum của bản sao đã profile ở giai đoạn GraphIDS) |
| Kích thước | 20,115,529 flow; 55 cột (49 feature NetFlow v3 + 2 IP + 2 timestamp + `Label` + `Attack`) |
| Timestamp | epoch **ms** (13 chữ số), diễn giải là UTC: 2018-02-14 12:28:07 → 2018-03-02 20:06:24 |
| Chất lượng | 0 null; 0 giá trị feature âm; 0 flow có `END < START`; 0 trường hợp `Label` mâu thuẫn với `Attack` |
| Nhãn | 15 nhãn gốc, giữ nguyên văn (kể cả chính tả `Infilteration`) |

Mỗi attack class chỉ xuất hiện trong **một ngày UTC**, gần như trong một burst liên tục (`runs/inspect/class_by_utc_day.csv`, khớp với profile GraphIDS ngày 2026-11-07). Hệ quả: không có class nào có hai episode độc lập trong dữ liệu.

## Cập nhật v2 (2026-11-08)
- Thêm **H1_0220_ddos** (holdout, DDoS LOIC-HTTP, 20/02 14:05–14:35; 192,863 flow).
- Bỏ **R2_0222_web** (replay web toàn mạng). Thay bằng **T5_0222_web_head** (train, 12:00–17:00) và **K5_0222_web_tail** (known_replay, 17:00–22:00). Cả hai được **giới hạn phạm vi vào máy chủ web** 172.31.69.28 và 172.31.69.1 (mọi flow đi từ hoặc đến các host này, kể cả benign):
  - T5: Web 903, XSS 223, SQLi 150, Benign 534;
  - K5: Web 715, XSS 257, SQLi 290, Benign 534.
- Web, XSS và SQLi trở thành **known class (lớp hiếm)**.
- Tổng 2,946,797 row (trần 3.2M). Bảng bên dưới là bản v1 (MVP).

## Cách chọn subset
- **Quy tắc:** giữ **mọi flow** có `FLOW_START` thuộc `[start, end)` của một cửa sổ khai báo trong config, trên toàn bộ mạng quan sát được. Không lấy mẫu từng row và không cân bằng class.
- **Thời điểm chốt:** các cửa sổ, vai trò và known class được chốt **sau** `inspect` (chỉ dùng support theo giờ) và **trước** khi train model nào.
- **Ngân sách:** trần 3,000,000 row; thực tế 2,973,401 row.
- **Khoảng trống giữa các cửa sổ** là gap capture của demo; trạng thái policy được reset ở mỗi ranh giới segment.

| Segment | Vai trò | Scenario | UTC | Benign | Attack |
|---|---|---|---|---|---|
| T1_0214_ftp_head | train | known-train | 02-14 14:25–15:05 | 133,273 | FTP-BruteForce 125,700 |
| K1_0214_ftp_tail | known_replay | known-within-episode | 02-14 15:50–16:20 | 91,221 | FTP-BruteForce 81,780 |
| T2_0214_ssh_head | train | known-train | 02-14 17:55–18:50 | 149,678 | SSH-Bruteforce 100,140 |
| K2_0214_ssh_tail | known_replay | known-within-episode | 02-14 19:05–19:40 | 106,364 | SSH-Bruteforce 57,196 |
| T3_0215_gold_head | train | known-train | 02-15 13:20–13:55 | 123,806 | DoS-GoldenEye 50,134 |
| K3_0215_gold_tail | known_replay | known-within-episode | 02-15 13:55–14:20 | 76,197 | DoS-GoldenEye 11,166 |
| T4_0215_slow_head | train | known-train | 02-15 14:55–15:25 | 100,356 | DoS-Slowloris 21,352 |
| K4_0215_slow_tail | known_replay | known-within-episode | 02-15 15:25–15:50 | 72,535 | DoS-Slowloris 14,688 |
| C1_0220_benign | calibration | calibration | 02-20 12:00–14:05 | 278,255 | — |
| R2_0222_web | replay | unknown-web | 02-22 18:00–19:00 | 222,710 | Web 187, SQLi 96, XSS 80 |
| S1_0228_infil | stress | stress-infiltration | 02-28 15:00–15:40 | 160,416 | Infilteration 20,667 (gắn cờ) |
| R1_0302_bot | replay | unknown-bot | 03-02 13:30–17:30 | 858,080 | Bot 117,324 |

**Theo vai trò:** train 804,439 · known_replay 511,147 · calibration 278,255 · replay 1,198,477 · stress 181,083.

## Vai trò và các quyết định đã khóa
- **Known class của A0:** Benign, FTP-BruteForce, SSH-Bruteforce, DoS_attacks-GoldenEye, DoS_attacks-Slowloris.
- **Unknown-to-model:** Bot, Brute_Force_-Web, Brute_Force_-XSS, SQL_Injection, Infilteration.
- **Bot** bị giữ ngoài train và mọi lựa chọn threshold; calibration chỉ có benign.
- **Thứ tự thời gian của luồng chính:** train (14–15/02) → calibration (20/02) → replay (22/02, 02/03) và stress (28/02).
- **known-within-episode** là scenario riêng: phần đuôi của chính các burst đã dùng để train. Giới hạn quan trọng: model còn được train trên phần đầu của các episode *khác* diễn ra **sau** một số đuôi này, ví dụ đầu burst SSH 17:55 nằm sau đuôi FTP 15:50. Đây là bằng chứng closed-set trong cùng episode, **không** phải đánh giá theo thứ tự thời gian và không phải independent episode.
- **Infilteration** nằm trong scenario stress và gắn cờ `label_quality=flagged`. Nó được báo cáo riêng và không dùng cho claim chính. Profile cũ ghi nhận 75% flow Infilteration giống hệt benign khi bỏ port và DNS id; đây là dữ kiện tương thích với giả thuyết gán nhãn theo host và cửa sổ thời gian, nhưng giả thuyết đó chưa được kiểm chứng.
- **Nhãn:** nhãn gốc được giữ nguyên; taxonomy demo (`labels.taxonomy`) chỉ dùng để báo cáo theo họ. Không gộp attack vào benign.

## Causal replay
- `available_at = FLOW_END_MILLISECONDS + export_delay_ms`. Giá trị mặc định 0 ms là **giả định lower bound**, không đo được từ CSV.
- Replay theo `(available_at, flow_id)`; quyết định ở tick đầu tiên ≥ `available_at` (tick 1 s); batching delay được ghi lại.
- Thứ tự trong file gốc không theo thời gian (`row_id` chỉ là chỉ số dòng trong CSV).

## Host overlap và mức trùng (`artifacts/.../AUDIT.json`)
- **FTP, SSH, GoldenEye, Slowloris:** mỗi class có đúng **1 attacker IP**, không bao giờ là nguồn benign, và trùng IP giữa train và known_replay. FTP-BruteForce ở phần đuôi có **100%** fingerprint (49 feature) đã có trong train; SSH 0%, GoldenEye 1%, Slowloris 33%. Kết quả known-class vì vậy rất lạc quan.
- **Bot:** 8 host nguồn; 7/8 (87.5%) cũng là nguồn benign trong cùng cửa sổ (**same-host**). 3,349 flow benign đi từ hoặc đến các host này. 72.9% flow Bot có source IP từng xuất hiện trong train; **0%** có destination từng xuất hiện trong train; 0% fingerprint Bot có trong train.
- **Web:** 87 source IP; 2/3 trong số đó cũng gửi benign trong cùng cửa sổ.
- **Infilteration:** 116 source IP; 76.7% cũng gửi benign trong cùng cửa sổ; 33,615 flow benign đi từ hoặc đến các host này.
- **Fingerprint mang nhiều nhãn trong subset:** XSS|SQLi (32 fingerprint), FTP|SSH (30), Benign|Infilteration (21), Benign|Web (7). Các row này được giữ nguyên, không xóa.

## Giới hạn
- Chỉ là một mạng testbed (CIC-2018, AWS); subset theo cửa sổ thời gian, **không** đại diện toàn bộ dataset hay lưu lượng mạng thực.
- Mỗi class chỉ có một episode, nên không có bằng chứng tổng quát hóa qua episode cho known class.
- Web attack có support rất nhỏ (80–187 flow); Infilteration có chất lượng nhãn đáng ngờ.
- Dữ liệu CIC-2018 đã được dự án dùng ở giai đoạn GraphIDS (profile và same-host validation), nên subset này **không** phải holdout mới của dự án.
