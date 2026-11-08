# FP & label forensics — NF-CSE-CIC-IDS2018-v3 (2026-11-08)

Phạm vi: các flow benign mà A0 v2 báo nhầm ở **α = 0.1%** (threshold 0.8679, khóa trên C1), trong run dev `20261108T122848_a0-shadow_fast`, cùng nhãn của các lớp web. File này **không ghi đè nhãn** hay báo cáo cũ. Mọi con số "nhãn đã sửa" chỉ là **phân tích độ nhạy exploratory**.

Artifacts:
- `runs/forensics_fp_{S1_0228_infil,R1_0302_bot}.csv`: từng flow FP và nhóm đã phân loại;
- `runs/forensics_fp_summary.json`;
- `runs/forensics_web_0222.parquet`: mọi flow mang nhãn web ngày 22/02, kèm cờ `credible`;
- `runs/forensics_web_0223.parquet`.

## 1. Provenance của nhãn và dữ liệu có sẵn
- **NF-v3 tạo nhãn bằng cách** chạy nProbe trên PCAP gốc của CSE-CIC-IDS2018, rồi so khớp **timestamp và 5-tuple** với file ground truth gốc của CIC ([Luay et al., arXiv 2503.04404](https://arxiv.org/pdf/2503.04404), mục Dataset Conversion and Labeling). Như vậy NF-v3 **kế thừa** nhãn gốc, gồm cả các lỗi đã được ghi nhận cho CSE-CIC-IDS2018.
- **Nguồn đối chiếu bên ngoài:** Engelen et al., IEEE CNS 2022 ([tài liệu](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html), [code](https://github.com/GintsEngelen/CNS2022_Code)). Họ phân tích lại PCAP và đưa ra luật gắn nhãn đã sửa cho flow CICFlowMeter.
  - Các luật dựa trên **cặp IP + cửa sổ thời gian** (ví dụ portscan, C2) chuyển được sang flow NetFlow.
  - Các luật dựa trên **payload hay số packet** của CICFlowMeter thì **không** áp nguyên xi được, vì nProbe tách flow khác.
- **Trên máy:** chỉ có CSV của NF-v3 (2 bản sao cùng sha1). **Không có PCAP, log hay nhãn đã sửa**, nên không kiểm chứng được ở mức packet. Mọi kết luận "khớp luật CNS2022" đều dựa trên bằng chứng PCAP **của bên thứ ba**, cộng với việc khớp cặp IP, thời gian, giao thức và cổng trên dữ liệu của chúng ta.
- **Timestamp:** epoch ms. Cửa sổ của CNS2022 (UTC) khớp với lịch tấn công trong NF-v3; ví dụ Bot 14:13–19:54 UTC, cùng mốc với profile của chúng ta.

## 2. Ngày Infiltration 28/02 (S1, 15:00–15:40 UTC)
Benign: 160,416 flow. FP với nhãn gốc: **959 flow (0.598%), 44 incident**.

| Nhóm | Flow | Incident | Bằng chứng | Phân loại |
|---|---|---|---|---|
| 172.31.69.24 → 172.31.69.15 trong cửa sổ NMAP của CNS2022 (14:46:22–18:39:00 UTC, không tính src port 68) | **804** | **2** | TCP, **580 cổng đích khác nhau**, trung vị 1 packet mỗi chiều, 1 ms: đúng dạng SYN scan. CNS2022 nêu đích danh .24 quét 21 host nội bộ, **gồm .15**. NF-v3 gắn **Benign** cho cả **2,445** flow .24 → .15 trong segment. A0 dự đoán 790 flow là Brute_Force_-Web và 14 là FTP-BruteForce | **Confirmed mislabelled theo bằng chứng PCAP bên ngoài** (khớp luật; chưa kiểm chứng packet tại chỗ). Ở mức binary **không phải FP**; ở mức multiclass **vẫn sai lớp** (không có lớp Portscan trong known class) |
| Host Internet → host nội bộ, cổng 23/22/445/6379 (111 IP nguồn khác nhau) | 111 | 39 | Mẫu quét nền Internet (telnet, SMB, redis). Không thuộc kịch bản CIC; CNS2022 không xếp vào tấn công | **Likely suspicious, chưa xác minh** (nhiễu quét Internet; nhãn "Benign" của kịch bản vẫn có thể đúng) |
| UDP 500/5060 → 172.31.69.28 | 44 | 3 | Xem §3 | **Indeterminate**, nhiều khả năng là traffic nền |

- **Phân tích độ nhạy (exploratory):** nếu 804 flow khớp luật NMAP được tính là tấn công, benign FPR của S1 giảm từ **0.598% xuống 0.097%** (155/159,612), tức nằm dưới mục tiêu 0.1%. FP theo incident giảm từ 44 xuống 42.
- **Nhãn Infilteration của NF-v3 trong S1:** chỉ **3,585/20,667 (17%)** flow có dính tới victim .24. Phần lớn là DNS (11,888 flow UDP/53), 443 và RDP 3389 của các host .13, .17, .12, .16. Trong khi đó, **12,633** flow từ .24 tới host nội bộ (phần lớn là portscan) lại mang nhãn Benign. Nhãn Infilteration **lệch theo cả hai chiều**. Điều này củng cố cờ `flagged` đã đặt cho class này từ trước.

## 3. Ngày Bot 02/03 (R1, 13:30–17:30 UTC)
Benign: 858,080 flow. FP với nhãn gốc: **699 flow (0.081%), 28 incident**.

| Nhóm | Flow | Incident | Bằng chứng | Phân loại |
|---|---|---|---|---|
| 13.58.42.57, 52.14.77.172, 13.58.82.37 → 172.31.69.28, **UDP/500 (IKE)** và **UDP/5060 (SIP)** | **524** | **3** | Không khớp luật Ares của CNS2022 (chỉ 18.219.211.138). Ở ngày 23/02, CNS2022 ghi rằng 128 flow UDP tới cổng 500 bị nhãn gốc gắn sai là brute force, tức đây là traffic nền. Trong NF-v3 ngày 22/02, **chính mẫu này** (UDP/500, 6 packet, 3,168 byte) mang nhãn Web/XSS/SQLi (§4) | **Likely genuine FP so với kịch bản.** Nguyên nhân: model học từ **nhãn train sai** (mẫu nền bị gắn nhãn web attack). Bản chất thật của traffic thì **indeterminate** |
| Host nội bộ → HTTP ra ngoài (CDN, OCSP), cùng vài lượt quét telnet từ Internet | 175 | 25 | Không khớp luật nào; giống duyệt web bình thường | **Genuine FP** (phần nhiều), một phần **indeterminate** |

Giả thuyết cũ "IP từng tấn công ⇒ nhãn Benign có thể sai" **không đứng vững**. Các IP này không phải attacker theo CNS2022, và traffic của chúng là UDP/500 và 5060. Lỗi nằm ở **nhãn train ngày 22/02**, không nằm ở nhãn ngày 02/03. FPR với nhãn đã sửa vẫn là 0.081%.

## 4. Nhãn của các lớp web ngày 22/02
CNS2022: mọi web attack đều dùng **18.218.115.60 → 172.31.69.28**:
- BF 14:13:44–15:23:59 (gồm cả khởi động);
- XSS 17:51:39–18:29:41;
- SQLi 20:14:30–20:27:56 (gồm cả khởi động).

| | NF-v3: tổng flow mang nhãn | Có dính cặp attacker ↔ victim | **Credible** (đúng cặp, trong cửa sổ, TCP/80) | Trong train T5 (12–17h): credible/tổng | Trong eval K5 (17–22h): credible/tổng |
|---|---|---|---|---|---|
| Brute_Force_-Web | 1,618 | 115 | **115** | 115/903 | **0/715** |
| Brute_Force_-XSS | 480 | 43 | **41** | **0/223** | 41/257 |
| SQL_Injection | 440 | 93 | **20** | **0/150** | 20/290 |

- **Chỉ 176/2,538 (6.9%)** flow mang nhãn web là credible. **993 flow (39%)** là UDP/500; phần còn lại gồm SMB 445, SSH 22, Telnet 23, ICMP, DHCP và SIP, đến từ **562 IP nguồn**.
- Các flow của attacker mang nhãn XSS hoặc SQLi còn nằm **ngoài cửa sổ** của chúng; ví dụ nhãn SQLi bắt đầu từ 15:09.
- **Model chưa từng thấy một flow XSS hay SQLi credible nào khi train.** "Web F1 0.769" (K5) được đo trên 715 flow **không credible**.
- **A0 trên flow credible của K5** (exploratory):
  - XSS thật: 83% bị đoán Benign, **0%** vượt threshold;
  - SQLi thật (20 flow): 12 flow đoán đúng SQLi, 50% vượt threshold.
- **Ngày 23/02:** CNS2022 ghi có tấn công web, nhưng NF-v3 **không có flow nào** giữa 18.218.115.60 và 172.31.69.28 trong ngày này. Không có episode web độc lập thứ hai.

## 5. Tóm tắt
| Câu hỏi | Trả lời |
|---|---|
| FPR với nhãn gốc (α = 0.1%) | S1 0.598% (44 incident); R1 0.081% (28 incident); known_replay 0.037% |
| Có lỗi nhãn được xác thực không? | Có, **theo bằng chứng PCAP bên ngoài** (CNS2022): portscan của .24 (804 FP flow) bị gắn Benign; phần lớn nhãn web ngày 22/02 không khớp hoạt động tấn công. Chưa kiểm chứng packet tại chỗ |
| Kết luận về FP thay đổi thế nào? | S1: 0.598% → **0.097%** (sensitivity). R1: không đổi; FP ở đó là FP thật, do model học nhãn train sai |
| Còn bao nhiêu FP thật hoặc chưa kết luận được? | S1: 155 flow (42 incident): 111 likely suspicious, 44 indeterminate. R1: 699 flow (28 incident): 524 likely genuine FP do nhãn train sai, 175 phần lớn genuine FP |
| Phân biệt cần giữ | Portscan bị gắn Benign: **không** phải binary FP, nhưng dự đoán "Web Brute Force" **vẫn sai** ở mức multiclass |
