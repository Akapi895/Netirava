# Data sufficiency decision — XSS vs SQLi (2026-11-08)

Nhiệm vụ này **không** tải, đọc hay xử lý PCAP hoặc payload HTTP.

## Dữ liệu hiện có có đủ không?
| Câu hỏi | Bằng chứng | Kết luận |
|---|---|---|
| Đủ mẫu credible? | Sau khi sửa nhãn theo CNS2022: Web 70, XSS 80, **SQLi 17** flow, mỗi lớp **1 episode, 1 attacker** (18.218.115.60 → 172.31.69.28) | **Không đủ** để đánh giá tổng quát hóa. SQLi có n = 2 trong eval của pilot |
| 49 feature có tách được XSS với SQLi? | Pilot (within-episode): XSS F1 1.00, SQLi 1.00 (n = 2). Hai cửa sổ tách nhau về thời gian, và flow trong cùng cửa sổ gần như lặp lại, nên điểm cao có thể chỉ phản ánh **chữ ký của công cụ tấn công** trong episode đó | **INCONCLUSIVE.** Không phân biệt được "tách theo hành vi" với "nhớ episode" |
| Episode độc lập thứ hai? | CNS2022 ghi có tấn công web ngày 23/02, nhưng NF-v3 **không có** flow 18.218.115.60 ↔ 172.31.69.28 trong ngày đó | **Không có** trong dataset này |

## Thông tin còn thiếu
1. **Episode độc lập** cho XSS và SQLi: ngày khác, attacker khác hoặc công cụ khác.
2. **Nội dung HTTP request** (URI, tham số, body). Khác biệt bản chất giữa XSS (script injection) và SQLi (truy vấn SQL) nằm ở đây. NetFlow v3 không mang thông tin này, nên **không model nào học được nó từ 49 feature**.
3. **Nhãn đã sửa có kiểm chứng ở mức packet** cho NF-v3: các luật CNS2022 hiện được áp bằng xấp xỉ.

## Dữ liệu độc lập cần cho bước sau (đề xuất, chưa làm)
- Trích lại flow ngày 23/02 từ PCAP gốc bằng nProbe: tạo episode web thứ hai cùng representation, gắn nhãn bằng luật CNS2022.
- Nếu cần tách XSS/SQLi theo bản chất: dùng log HTTP từ cùng PCAP (kiểu Zeek `http.log`) làm feature bổ sung có tính causal.
- Cả hai đều cần người dùng duyệt việc mở rộng dữ liệu (PCAP CSE-CIC-IDS2018 trên AWS, cỡ hàng trăm GB; chỉ cần phần của máy chủ web).

## Quyết định
| Hạng mục | Quyết định |
|---|---|
| Corrected-label training (giảm FP) | **GO** (development evidence; ghi kèm đánh đổi về incident và portscan, xem `CORRECTED_LABEL_PILOT_RESULTS.md`) |
| Corrected-label training (phát hiện XSS/SQLi) | **INCONCLUSIVE** (1 episode, n rất nhỏ) |
| Family-aware output | **GO** (không ảnh hưởng FP theo cấu trúc; nhãn mịn sai giảm khoảng 97% trên A0 v2) |
| Mở rộng dữ liệu (PCAP/HTTP) | **Cần thiết** nếu muốn claim phân biệt XSS/SQLi. Chưa thực hiện; chờ người dùng duyệt |
| Thay model hoặc kiến trúc SOTA | **NO-GO** lúc này: không thêm được thông tin còn thiếu |
