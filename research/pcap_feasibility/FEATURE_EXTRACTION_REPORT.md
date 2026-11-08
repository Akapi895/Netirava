# RQ-PCAP: feature extraction report (Phase 2)

Code: `src/zeeklog.py`, `src/extract.py`, `src/features.py`, `scripts/extract_all.py` · Số liệu: `work/*/extract_stats.json` (gitignored), `results/coverage.json`, `logs/extract.log` · Test: `tests/test_rq_pcap.py` (9/9 pass)

## 1. Pipeline
```
conn.log.labeled (Zeek, IoT-23 cung cấp) ──► flows (uid = định danh flow, nhãn chỉ dùng cho evaluator)
capture.pcap ──dpkt──► packet ──join 5-tuple + thời gian──► thống kê theo uid ──► feature set B
A = cột conn.log · B = feature trích từ pcap · C = A ∪ B   (cùng flow, cùng nhãn, cùng split)
```
- **Không dùng Zeek hay Tshark** vì cả hai đều không được cài. Zeek đã có mặt gián tiếp qua `conn.log.labeled`. Chạy lại Zeek sẽ sinh `uid` mới, không khớp với `uid` có nhãn.
- **Join:**
  - **Khóa:** `(proto, orig_h, orig_p, resp_h, resp_p)`, thử cả hai chiều. Chiều xuôi là packet của orig, chiều ngược là packet của resp.
  - **Thời gian:** packet phải nằm trong `[ts − 1 s, ts + duration + 1 s]`. Nếu có nhiều ứng viên, flow chứa packet đúng thời điểm (không cần dung sai) được ưu tiên, sau đó chọn flow có `ts` gần nhất. Mỗi ca như vậy được **đếm là mơ hồ**.
  - **Fragment không phải fragment đầu** được gắn vào flow của fragment đầu qua `(src, dst, proto, IP-ID)`.
  - **ICMP** được ghép theo cặp host (Zeek ghi type/code vào trường port). Ba capture này không có ICMP.
- **Không bỏ flow nào:** flow không có packet vẫn được giữ, với B = NaN và cờ `b_missing`; cờ này không phải feature.

## 2. Kết quả join (IoT-23)
| | 20-1 Torii | 8-1 Hakai | 34-1 Mirai |
|---|---|---|---|
| Packet trong pcap | 50,156 | 23,623 | 233,865 |
| Không phải IPv4 (ARP/IPv6) | 8,949 | 6,946 | 5,396 |
| Packet được gán cho flow | 41,207 (100% số IPv4) | 16,677 (100%) | 220,928 (96.7%) |
| Fragment UDP được gắn qua IP-ID | 0 | 0 | 38,326 |
| Packet TCP không gán được | 0 | 0 | 7,541 (3.3% số IPv4) |
| Packet có ghép mơ hồ | 0 | 0 | 52,052 |
| **Flow có ≥ 1 packet (tỷ lệ join)** | **3,209 / 3,209 (100%)** | **10,403 / 10,403 (100%)** | **23,145 / 23,145 (100%)** |
| Flow có ít nhất một packet mơ hồ | 0 | 0 | 14,209 (61%) |
| Thời gian parse + tính feature | 0.85 s | 1.19 s | 5.0 s |
| Peak RSS (một process) | 120 MB | 175 MB | 300 MB |

**Lỗi đã sửa trước khi đánh giá** (commit `973b4c8`):
- Bản đầu chỉ xét 50 ứng viên trước thời điểm packet, nên ở 34-1 chỉ join được 46% flow.
- Nguyên nhân là một **artefact của Zeek** (xem §3).
- Lookup đã được sửa: xét lân cận hai phía và ưu tiên flow chứa đúng thời điểm packet. Đồng thời bổ sung xử lý fragment.
- Có test hồi quy: `test_join_direction_time_disambiguation_and_missing_flows`, `test_non_first_fragments_attach_to_first_fragment_flow`.

## 3. Artefact và rủi ro shortcut phát hiện trong dữ liệu
1. **Zeek ghi bản ghi có 0 packet.**
   - 34-1 có **14,260 bản ghi DDoS** với `orig_pkts = resp_pkts = 0`, `conn_state = OTH` và `duration` rỗng.
   - Trong đó 12,451 bản ghi nằm trong một burst khoảng 30 s, cùng một 4-tuple (`192.168.1.195:65279 → 123.59.209.185:80`): Zeek tạo một bản ghi cho mỗi packet. Các packet này có cờ SYN+PSH+ACK+URG và kích thước 1,078 B.
   - Vì vậy **A gần như rỗng** ở các flow này, trong khi **B thấy được kích thước packet và cờ**. Đây là lợi thế của B đến từ cách Zeek ghi log, không phải từ thông tin protocol.
   - Kết quả có phân tích độ nhạy **loại các bản ghi này** (`*_excl_zero_pkt_records`).
   - Phần ghép của các bản ghi này cũng chiếm phần lớn số packet mơ hồ.
2. **Protocol gần như trùng với nhãn.**
   - **Benign: 98.4% UDP** (NTP/123 chiếm 88%, DNS/53 chiếm 11%).
   - **Malicious: 99.99% TCP.**
   - Riêng `proto` và `resp_p` của A đã tách gần hết hai lớp. Mọi feature chỉ tồn tại với TCP (cờ TCP, có hay không có `first_resp_delay`) đều là chỉ báo "đây là TCP".
   - **Hệ quả:** bài toán binary trên ba capture này gần như **đã chạm trần với A**, nên còn rất ít chỗ để B chứng tỏ giá trị.
3. **Metadata protocol chỉ có ở benign.**
   - DNS có trên 10.7% flow benign và 0% flow malicious; HTTP chỉ có trên 0.16% benign.
   - Có metadata tức là benign, nhưng `resp_p = 53` của A đã mang cùng thông tin đó.
4. **Ít đích.**
   - Mỗi họ tấn công chỉ đi tới 1–3 cặp `(resp_h, resp_p)` riêng: Torii 1 đích, Mirai C&C 1, Hakai C&C 2, DDoS 3, PortScan 2.
   - Số flow lớn, nhưng **số "tình huống" độc lập rất nhỏ**.
5. **Nhãn IoT-23 cũng có điểm đáng ngờ.** 65 flow TCP tới `185.244.25.235:80` được gán Benign trong 34-1. Không sửa nhãn; chỉ ghi nhận.

## 4. Source A: kiểm tra join NF-CSE-CIC-IDS2018-v3 ↔ PCAP (không train model)
Script: `scripts/cic2018_join_check.py` · Kết quả: `results/cic2018_join_check.json` · Log: `logs/cic2018_join_check.log`, `logs/cic2018_xss_unmatched.log`.

- **Dữ liệu:**
  - NF-v3: flow có `172.31.69.28` ở hai cửa sổ T5/K5 ngày 22/02 (3,212 flow, chỉ đọc từ `artifacts/` của Netirava);
  - PCAP: `UCAP172.31.69.28` (47,715 packet).
- **Timestamp:** quét độ lệch từ −5 h đến +5 h. Độ lệch **0 h** (cả hai đều UTC) cho tỷ lệ khớp 86.6%; các độ lệch khác chỉ 17–34%.
- **Join theo 5-tuple + `[FLOW_START, FLOW_END] ± 1 s`** (NF-v3 không có uid):
  - **2,752 / 3,212 flow (85.7%)** có packet;
  - 460 flow có packet mơ hồ;
  - với **mọi flow join được, số packet trong pcap bằng đúng `IN_PKTS + OUT_PKTS` của NF-v3** (100%).
- **Theo nhãn gốc:**
  - Benign, Brute_Force_-Web và SQL_Injection: **100%** join được;
  - **Brute_Force_-XSS: 4.2%** (20/480), và 20 flow join được đều là **DHCP (.28 → .1:67)**.
  - 460 flow "XSS" không join được đến từ hai IP AWS (`52.14.77.172`, `13.58.42.57`), đích chủ yếu là **port 500 (IKE)**. Pcap của web server không có packet nào của chúng, dù nằm trong đúng khung giờ.
  - Điều này **xác nhận độc lập** kết luận của `docs/02_data_eda_labels.md`: nhãn XSS trên host này không phải lưu lượng HTTP tấn công.
- **Kết luận:** về kỹ thuật, có thể trích B cho các flow NF-v3 của web server. Ngân sách khá nhỏ (9.6 MB cho một host-ngày), nhưng nhãn web vẫn là nút thắt chính.

## 5. Coverage và giá trị thiếu (IoT-23, 36,757 flow)
| Nhóm B | Số cột | Coverage | Benign | C&C | C&C-Torii | DDoS | PortScan |
|---|---|---|---|---|---|---|---|
| pkt_size_dist | 12 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| timing (IAT, first_resp_delay) | 13 | 0.323 | 0.751 | 0.425 | 0.500 | 0.002 | 0.090 |
| tcp_flags | 12 | 0.805 | 0.016 | 1.000 | 1.000 | 1.000 | 0.992 |
| first_n_sizes (5) | 5 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| dns_meta | 8 | 0.021 | 0.107 | 0 | 0 | 0 | 0 |
| http_meta | 7 | 0.0003 | 0.002 | 0 | 0 | 0 | 0 |
| tls_meta / ssh_meta | 0 | **0** | — | — | — | — | — |
| payload_stats | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| zeek_service | 1 | 0.066 | 0.109 | 0.110 | 0 | 0 | 0 |

- **Tỷ lệ traffic:**
  - mã hóa (TLS/SSH): **0%** → không đánh giá được giới hạn của B khi gặp mã hóa;
  - có metadata DNS/HTTP/TLS/SSH: 2.2%;
  - **không có metadata: 97.8%** (malicious 100%);
  - không có payload ở cả hai chiều: 37.1%.
- **Giá trị thiếu là có cấu trúc, không phải lỗi:**
  - cờ TCP bằng NaN với UDP;
  - IAT bằng NaN khi một chiều chỉ có ≤ 1 packet;
  - DNS/HTTP bằng NaN khi không có protocol đó.
- **Xử lý:** CatBoost nhận NaN trực tiếp (numeric dùng `Min`, categorical dùng `"NA"`). Không impute, không scale, nên không có tiền xử lý nào được fit ngoài train. Chi tiết theo cột ở `results/coverage.json → missing_by_column`.

## 6. Feature set
- **A** (11, chỉ lấy từ conn.log):
  - `duration, orig_bytes, resp_bytes, missed_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes, resp_p`;
  - `proto`, `conn_state` (categorical).
  - **Khác với NetFlow v3 của Netirava** (49 feature, có cờ TCP tích lũy, TTL, IAT, histogram kích thước). A ở đây là bản "flow-only" **nghèo hơn** NF-v3.
  - Hệ quả: một phần lợi ích của B ở IoT-23 (cờ TCP, IAT, kích thước) **đã có sẵn trong NF-v3**, nên không thể suy ra cho Netirava.
- **B** (64 cột trên dữ liệu này): phân bố kích thước packet theo chiều; IAT theo chiều; `first_resp_delay`; số lần xuất hiện mỗi cờ TCP theo chiều; 5 kích thước packet đầu có dấu theo chiều; metadata DNS/HTTP (độ dài, số label, entropy ký tự, qtype, rcode, TTL, method, độ dài URI/UA, status) và TLS/SSH (rỗng ở đây); thống kê payload (tỷ lệ packet có payload, độ dài và entropy của payload đầu); `zeek_service`.
- **Luôn bị loại** (`features.FORBIDDEN`, có test):
  - `ts`, `uid`, IP, `orig_p` (port tạm thời), `local_*`, `history`, `tunnel_parents`;
  - nhãn, `capture_id`;
  - cờ join `b_missing` và `b_ambiguous_pkts`;
  - TTL, IP-ID, TCP window (fingerprint hệ điều hành);
  - mọi chuỗi thô (qname, Host, URI, UA, SNI): chỉ dùng độ dài và entropy.
- **Payload thô:** không được dùng làm feature; chỉ giữ tối đa 2 KB trong RAM để parse protocol.

## 7. Chi phí trích xuất
- **Tốc độ:** dpkt pure-Python, một luồng, khoảng **95k packet/s** (34-1: 233,865 packet trong 2.5 s); feature theo flow khoảng 10k flow/s.
- **RAM:** peak RSS 120–300 MB cho mỗi capture (đã gồm Python, pandas và dpkt khoảng 90 MB).
- **Ngoại suy thô:**
  - một ngày CIC-2018 (38–59 GB nén, cỡ 10⁸ packet) mất khoảng 20–40 phút parse một luồng, chưa tính thời gian tải;
  - ở mức một host (web server 22/02: 25.7 MB, 47,715 packet), parse mất **0.65 s**.
- **Inference:** xem `PCAP_FEASIBILITY_RESULTS.md`.
