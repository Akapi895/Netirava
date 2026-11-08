# Minority information audit — Web / XSS / SQLi (2026-11-08)

Dữ liệu: segment T5 và K5 (22/02, phạm vi máy chủ web 172.31.69.28 và .1), tổng 3,606 flow. Nhãn là nhãn gốc của NF-v3. Nhãn "credible" lấy từ `FP_LABEL_FORENSICS.md` §4.

## 1. Collision fingerprint (49 feature, khớp tuyệt đối)
- 3,606 flow; **1,503 fingerprint khác nhau**; **77 nhóm fingerprint mang nhiều nhãn**.
- **Tập nhãn của các nhóm đó:**
  - XSS|SQLi: 52 nhóm;
  - Web|XSS|SQLi: 11;
  - Web|XSS: 8;
  - Web|SQLi: 5;
  - Benign|XSS: 1.
- **Số row nằm trong nhóm nhiều nhãn:** XSS **480/480 (100%)**, SQLi **382/440 (87%)**, Web 242/1,618 (15%), Benign 32/1,068 (3%).
- **Nhóm lớn nhất:** UDP/500, 6 packet, 3,168 byte. Nó xuất hiện 338 lần với ba nhãn (XSS 169, SQLi 100, Web 69), và còn hai nhóm UDP/500 nữa ở cỡ 292 và 148 row.
- **Đánh giá so với train** (`runs/minority_report.json`): 82% flow XSS và 75% flow SQLi trong eval có fingerprint đã xuất hiện ở train dưới nhãn khác.

**Diễn giải.** Phần lớn collision **không phải** hai tấn công khác nhau có cùng biểu diễn. Đó là **cùng một loại traffic nền** (IKE UDP/500 tới máy chủ web) bị gắn các nhãn web khác nhau tùy thời điểm. Đây là **lỗi nhãn**, không phải giới hạn thông tin giữa XSS và SQLi thật.

## 2. Collision có tạo ra một "trần" F1 không?
Có, nhưng **chỉ có điều kiện**. Với nhãn gốc, một classifier chỉ nhìn 49 feature không thể đúng đồng thời mọi flow trong một nhóm mang nhiều nhãn; tốt nhất là chọn nhãn đa số. Trần này phản ánh **độ nhiễu của nhãn**, không phải khả năng phân biệt XSS và SQLi thật. Nó **không** cho biết F1 tối đa trên nhãn đúng.

## 3. Thông tin phân biệt trong 49 feature: những gì đo được
- **Credible XSS (41 flow) và credible SQLi (20 flow)** đều là TCP/80 từ cùng attacker tới cùng máy chủ, nên chỉ khác nhau ở thống kê flow. Trên nhãn gốc, model chưa bao giờ được train với flow credible của hai lớp này, nên không có số liệu nào cho biết 49 feature có đủ để tách chúng hay không.
- **Nhận định có điều kiện:** khác biệt giữa XSS và SQLi nằm ở **nội dung HTTP request** (tham số URL, body có `<script>` hay từ khóa SQL). NetFlow v3 không có trường payload hay URI; chỉ có `L7_PROTO` (ID giao thức), byte, packet và thời gian. Phân biệt hai lớp này bằng thống kê flow là **có thể nhưng yếu**, và kết quả nếu có cũng dễ phụ thuộc vào công cụ tấn công (Selenium script) hơn là vào hành vi tấn công.
- **Mức họ Web:** F1 0.851 đo trên nhãn gốc, nên cũng bị nhiễm nhãn sai (90% flow web không credible).

## 4. Thông tin bổ sung: giá trị và tính khả thi
| Nguồn | Giá trị cho XSS và SQLi | Causal / realistic | Khả thi |
|---|---|---|---|
| HTTP request (URI, body) từ PCAP | **Cao**: đây chính là tín hiệu tấn công | Có: IDS có parser HTTP (Zeek `http.log`, Suricata) là thực tế | PCAP gốc của CSE-CIC-IDS2018 khoảng 450 GB trên AWS S3. Chỉ cần PCAP của máy chủ 172.31.69.28 ngày 22–23/02 (vài GB), nhưng phải tải dataset gốc, tức là mở rộng dữ liệu. **Không có trên máy** |
| Log của máy chủ web, Windows event | Trung bình | Có | CIC công bố log theo host; cũng phải tải. Chưa kiểm tra có log web hay không |
| Nhãn sửa theo CNS2022 | **Cao cho tính đúng của đánh giá** | Không phải feature, mà là sửa ground truth | Luật IP + thời gian áp được ngay trên CSV; luật dựa payload của CICFlowMeter thì không áp nguyên xi được |
| Source IP, lịch tấn công | Không dùng: shortcut | Không | — |

## 5. Kết luận: hạn chế chủ yếu do đâu?
| Yếu tố | Mức đóng góp (có điều kiện) |
|---|---|
| **Chất lượng nhãn** | **Chính.** 93% nhãn web không credible; train không có XSS hay SQLi credible; collision chủ yếu là cùng traffic nền mang nhiều nhãn |
| **Thiếu thông tin trong input** | **Thứ hai, áp dụng cho XSS và SQLi thật.** Khác biệt nằm ở payload HTTP mà NetFlow không có. Chưa đo được, vì chưa có nhãn sạch |
| Mất cân bằng lớp | Phụ. SMOTE tốt hơn không xử lý (3 seed), nhưng không giải được hai yếu tố trên |
| Thuật toán | Phụ. Đổi model **không** sửa được nhãn sai hay tạo ra payload còn thiếu |
