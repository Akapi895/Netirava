# RQ-PCAP: data access report (Phase 1)

Ngày: 2026-11-08 · Protocol khóa trước khi tải: commit `2feaa35` (`config.yaml`) · Log: `logs/download.log`, `logs/cic2018_zip_listing.log`, `logs/cic2018_member.log`

## Công cụ trên máy
| Công cụ | Trạng thái | Hệ quả |
|---|---|---|
| Zeek | Không cài | Dùng conn.log có sẵn của IoT-23 (do Zeek sinh) và tự trích feature packet bằng Python |
| Tshark / Wireshark | Không cài | Như trên |
| AWS CLI | Không cài | Truy cập S3 ẩn danh qua HTTPS (`list-type=2`, HEAD, Range) |
| Docker, WSL Ubuntu | Có | **Không dùng.** Image Zeek tốn thêm vài trăm MB tải công cụ. Ngoài ra Zeek sinh `uid` ngẫu nhiên mỗi lần chạy, nên không ghép lại được với `uid` trong `conn.log.labeled` |
| Python | `dpkt 1.9.8` trong venv riêng `research/pcap_feasibility/.venv` (`uv.lock`) | Không đụng tới venv hay lock của Netirava |

## Source A: CSE-CIC-IDS2018 (`s3://cse-cic-ids2018/`)
- **Truy cập:** đọc được ẩn danh qua `https://cse-cic-ids2018.s3.amazonaws.com/`. Có hai prefix:
  - `Original Network Traffic and Log data/<ngày>/` gồm `pcap.zip` (riêng 20/02 là `pcap.rar`) và `logs.zip`;
  - `Processed Traffic Data for ML Algorithms/` gồm CSV của CICFlowMeter.
- **Kích thước** (10 ngày):

| Ngày | pcap | logs.zip |
|---|---|---|
| 14/02 | 39.91 GB | 0.14 GB |
| 15/02 | 41.28 GB | 0.15 GB |
| 16/02 | 38.54 GB | 0.16 GB |
| 20/02 | 44.39 GB (rar) | 0.19 GB |
| 21/02 | 53.46 GB | 0.19 GB |
| 22/02 | 50.24 GB | 0.20 GB |
| 23/02 | 59.09 GB | 0.21 GB |
| 28/02 | 53.25 GB | 0.23 GB |
| 01/03 | 52.36 GB | 0.23 GB |
| 02/03 | 44.79 GB | 0.24 GB |

- **Đánh giá ban đầu:** mỗi object PCAP là một archive 38–59 GB, vượt rất xa ngân sách, nên tôi ghi là "quá lớn" và chuyển sang IoT-23. `logs.zip` là log của host, không phải packet, nên không tải.
- **Kiểm tra bổ sung** (sau khi protocol IoT-23 đã khóa):
  - Đọc *central directory* của `22-02/pcap.zip` bằng HTTP Range, tổng chỉ tải 122 KB.
  - Archive gồm **447 PCAP riêng cho từng host**, nén từ 0.56 MB đến 649 MB.
  - Web server `172.31.69.28`, nạn nhân web attack trong cửa sổ T5/K5 của Netirava, chỉ có **9.49 MB nén / 25.7 MB giải nén**.
  - Đã tải **riêng member này** bằng Range: tải 9.61 MB, sha256 `1488978b…`, xem `data/CIC2018-Thursday-22-02-2018/MEMBER_MANIFEST.json`.
  - **Phạm vi sử dụng:** member này chỉ dùng để **kiểm tra khả năng join**, không dùng để train hay đánh giá model (xem `FEATURE_EXTRACTION_REPORT.md` §4). Đánh giá model vẫn chạy trên IoT-23 đúng như protocol đã khóa.
- **Kết luận Source A:** truy cập được. Ở mức một host, PCAP có kích thước dùng được, và **join với NF-CSE-CIC-IDS2018-v3 là khả thi** (85.7%). Nghĩa là có đường đi để kiểm chứng RQ-PCAP trực tiếp trên dataset của Netirava. Muốn làm vậy cần duyệt **thêm ngân sách và protocol riêng**; chưa làm.

## Source B: IoT-23 (`mcfp.felk.cvut.cz/.../IoT-23-Dataset/IndividualScenarios/`)
- **Truy cập:** HTTP 200, có directory listing. Đã khảo sát 23 thư mục; xem 20-1 trước theo yêu cầu.
- **Ứng viên nhỏ** (pcap + `bro/conn.log.labeled`):

| Capture | Malware (README) | pcap | conn.log.labeled |
|---|---|---|---|
| 20-1 | Torii | 3.9 MB | 410 KB |
| 21-1 | Torii | 3.9 MB | 419 KB |
| 42-1 | Trojan | 2.8 MB | 572 KB |
| 8-1 | Hakai | 2.0 MB | 1.4 MB |
| 3-1 | Muhstik | 55 MB | 23 MB |
| 34-1 | Mirai | 120 MB | 2.8 MB |
| Các capture khác | — | 0.9–21 GB | — |
| Honeypot-5-1 | — | 364 MB | — |

- **Tiêu chí chọn** (khóa trước khi tải, chỉ dựa vào kích thước và README):
  - (1) có cả pcap lẫn conn.log có nhãn;
  - (2) vừa ngân sách;
  - (3) mỗi capture là một **họ malware khác nhau**, để leave-one-capture-out kiểm tra trên một họ chưa thấy khi train;
  - (4) có 20-1.
- **Đã chọn:** 34-1 (Mirai), 8-1 (Hakai), 20-1 (Torii). Không chọn 21-1 vì trùng họ Torii với 20-1. Không chọn 42-1 vì là trojan, README không có mô tả thêm.
- **Đã tải:** 9 file, **137.3 MB** (HEAD kiểm tra trước, mỗi file chỉ tải một lần, kích thước đều khớp). sha256 ghi trong `data/DOWNLOAD_MANIFEST.json`.

## Ngân sách
| Hạng mục | MB |
|---|---|
| IoT-23 (3 capture: pcap, conn.log.labeled, README) | 137.3 |
| CIC-2018: liệt kê S3 và central directory | ≈ 0.25 |
| CIC-2018: member `UCAP172.31.69.28` | 9.61 |
| **Tổng** | **≈ 147.2 (ngân sách 200)** |

## Nhãn (đếm sau khi tải)
| Capture | Benign | Malicious (detailed-label) | Số đích riêng (resp_h, resp_p) của malicious |
|---|---|---|---|
| 34-1 | 1,923 | DDoS 14,394 · C&C 6,706 · PartOfAHorizontalPortScan 122 | DDoS 3 · C&C 3 (gộp với 8-1) · PortScan 2 |
| 8-1 | 2,181 | C&C 8,222 | |
| 20-1 | 3,193 | C&C-Torii 16 | 1 |

**Hệ quả:**
- Mỗi capture chỉ có một thiết bị nhiễm và benign đến từ chính thiết bị đó. Mỗi họ tấn công chỉ đi tới 1–3 đích, nên **kích thước mẫu hiệu dụng rất nhỏ**.
- Tổng benign là 7,297 flow. Mức **FPR 0.1% sẽ thiếu support** ở mọi fold (xem kết quả).

## Bảo mật và giấy phép
- **Dữ liệu tải về:**
  - nằm trong `data/` (gitignored);
  - mọi script đọc nó đều chạy bằng `python -I` và đặt ở ngoài thư mục `data/`;
  - không có file thực thi nào được giải nén. File zip mẫu malware **không** được tải; chỉ tải pcap và log.
- **Giấy phép:**
  - README của một số capture IoT-23 (34-1, 42-1) ghi *"You need authorization from the Stratosphere Lab to use these files"*.
  - Dữ liệu chỉ được dùng nội bộ cho nghiên cứu khả thi và **không được commit hay phân phối lại**.
  - Cần kiểm tra điều khoản trước khi trích dẫn hoặc công bố.
