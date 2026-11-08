# RQ-PCAP: research decision

> **RQ-PCAP:** Việc bổ sung thông tin packet-level và protocol-level có cải thiện khả năng phát hiện/phân loại tấn công so với flow-only features, khi đánh giá trên cùng dữ liệu và kiểm soát False Positives hay không?

## Quyết định: **NO-GO** (trong thiết lập đã thử)
**Áp luật đã khai báo trước** (`config.yaml → decision_rule`, commit `2feaa35`):
- C không vượt A ở ≥ 2/3 fold LOCO, xét theo recall tại threshold FPR 1% đã khóa:
  - ΔRecall = 0 ở 34-1 và 20-1;
  - ở 8-1 chỉ có +0.25 trên một seed, nhỏ hơn độ dao động giữa seed, và control A + noise đạt +1.0 trên chính seed đó.
- C cũng không vượt control A + B hoán vị.
- Mức 1% đủ support ở cả ba fold.

Theo luật, kết quả là **NO-GO**.

**Không được đọc quyết định này là "PCAP không có giá trị".** Thiết lập IoT-23 có khả năng phân biệt thấp:
- A đã chạm trần nhờ shortcut `proto` (benign gần như toàn UDP, malicious gần như toàn TCP);
- không có traffic mã hóa, gần như không có metadata ứng dụng;
- mỗi họ chỉ có 1–3 đích;
- FPR 0.1% thiếu support.

Vì vậy NO-GO ở đây nghĩa là: **trong thiết lập này không có cải thiện đủ rõ, và chưa có lý do để đầu tư tích hợp PCAP vào Netirava.** Câu hỏi trên NF-CSE-CIC-IDS2018-v3 vẫn **chưa được trả lời**.

## Trả lời 6 câu hỏi
1. **Pipeline PCAP → features → model → evaluation có chạy được không?**
   - **Có, end-to-end:**
     - tải trong ngân sách: 147 MB / 200 MB;
     - dpkt parse pcap và join với Zeek uid (**100% flow** ở cả 3 capture; 3.3% packet TCP ở 34-1 không gán được, có báo cáo);
     - trích 64 feature B;
     - CatBoost LOCO với control, ablation và kiểm tra shortcut;
     - 9 test pass.
   - **Hai trục trặc dữ liệu đã được phát hiện và xử lý minh bạch:**
     - Zeek ghi 14,260 bản ghi có 0 packet;
     - packet UDP bị phân mảnh, đã gắn qua IP-ID.
   - **Trên Source A:** join NF-v3 ↔ PCAP một host đạt 85.7%, và số packet khớp chính xác.
2. **Những protocol feature mới nào thực sự được trích xuất?**
   - **Thực sự có dữ liệu** (coverage 100%):
     - phân bố kích thước packet theo chiều;
     - 5 kích thước packet đầu có dấu;
     - thống kê payload (tỷ lệ packet có payload, độ dài và entropy của payload đầu).
   - **Có dữ liệu một phần:**
     - cờ TCP theo chiều (80%; chỉ với TCP);
     - IAT và `first_resp_delay` (32%).
   - **Gần như rỗng:**
     - metadata DNS (2.1%, chỉ có ở benign);
     - HTTP (0.03%);
     - `zeek_service` (6.6%).
   - **Không có:** TLS và SSH (0%).
   - **Kết luận:** "protocol-level" gần như **không được kiểm tra**; chỉ "packet-level" được kiểm tra.
3. **Có bằng chứng cải thiện so với flow-only không?**
   - **Không**, ở mọi metric chính và mọi họ:
     - PR-AUC: Δ ≤ ±0.008;
     - recall @1%: Δ = 0;
     - macro-F1 exploratory: giống hệt;
     - per-family: không có họ nào cải thiện ổn định.
   - **Hai quan sát không đủ để claim:**
     - B đứng riêng có FPR thực tế thấp hơn ở 20-1 (0.023 so với 0.158), nhưng C không thừa hưởng, và xếp hạng bằng nhau. Đây là hiệu ứng khi chuyển threshold, không phải thông tin;
     - false incidents của C thấp hơn ở 2 fold, nhưng sd qua seed lớn.
4. **Việc cải thiện có làm tăng FPR hoặc chi phí không?**
   - **FPR:** C ≈ A. Cả hai đều vi phạm mục tiêu 1% ở 2/3 fold (7.5% và 16%), vì threshold không chuyển giao qua capture; đây là vấn đề chung, không do B. **FPR ≤ 0.1%: INSUFFICIENT SUPPORT.**
   - **Chi phí:**
     - inference ≈ 2.1× (1.94 so với 0.92 µs/flow);
     - fit +22%;
     - cần PCAP và bước parse (≈ 95k packet/s, peak RSS ≤ 300 MB / capture);
     - lưu trữ PCAP lớn hơn flow 2–3 bậc độ lớn.
   - **Kết luận:** có chi phí, nhưng chưa có lợi ích tương ứng.
5. **Có thể tích hợp thực tế theo kiểu causal/streaming không?**
   - **Về nguyên tắc có.** Mọi feature B được tính từ chính các packet của flow cho tới khi flow kết thúc, với trạng thái có giới hạn (mẫu tối đa 2,000 packet mỗi chiều, 2 KB payload đầu). Do đó B **khớp với contract "flow đã hoàn tất"** của Netirava (feature có sẵn tại `available_at`).
   - **Trên thực tế, hiện chỉ khả thi offline:**
     - parse Python một luồng (≈ 95k packet/s) không theo kịp line rate;
     - streaming cần exporter (Zeek hoặc plugin nProbe), và chính nProbe đã xuất phần lớn feature packet-level này vào NetFlow v3 (cờ TCP, IAT, histogram kích thước).
   - **Cho replay Netirava:** cần PCAP của từng host-ngày, nên là offline enrichment, có chọn lọc.
6. **Đã có đủ bằng chứng để phát triển tiếp hướng PCAP-enriched Netirava chưa?**
   - **Chưa.** IoT-23 không cho thấy giá trị bổ sung.
   - Mọi lợi ích tiềm năng trên NF-v3 phải vượt qua một baseline **mạnh hơn A ở đây**: 49 feature NetFlow v3 vốn đã có thông tin packet-level.
   - Kết quả IoT-23 **không** được dùng làm bằng chứng cải thiện hay không cải thiện Netirava.

## Nếu muốn tiếp tục (chưa làm; cần duyệt)
**Hướng hợp lý duy nhất là kiểm tra trực tiếp trên dataset của Netirava**, nhưng nhỏ và có protocol riêng.

1. **Dữ liệu:**
   - Range-fetch PCAP từng host cho các host-ngày liên quan (ví dụ web server 22/02 đã có; thêm 23/02 cho web, mỗi member khoảng 10 MB nén);
   - chỉ dùng host bị tấn công, không tải cả ngày.
2. **Thiết kế:**
   - A = 49 feature NF-v3 hiện tại; B = feature packet/HTTP từ PCAP, ưu tiên những gì NF-v3 **không** có (method / URI / độ dài và entropy của header HTTP);
   - **dùng nhãn đã sửa (CNS2022);**
   - split theo đợt hoặc ngày;
   - control giống hệt nghiên cứu này.
3. **Rủi ro chính:**
   - sau khi sửa nhãn, Web/XSS/SQLi còn rất ít mẫu đáng tin (pilot: Web 27, XSS 30, SQLi 2);
   - kiểm tra join đã cho thấy "XSS" trên host này không phải HTTP.
   - Khả năng cao kết quả lại là **INCONCLUSIVE do support**.
4. **Ước tính:** khoảng 20–50 MB dữ liệu, cộng 1 ngày công.

**Không đề xuất** tích hợp PCAP vào model đang chạy, Family-aware hay UI ở thời điểm này. Nghiên cứu này không sửa thành phần nào trong số đó.

## Sai lệch so với protocol (deviation log)
| Sai lệch | Lý do | Ảnh hưởng |
|---|---|---|
| Bản đầu của hàm lookup chỉ join 46% flow ở 34-1; đã sửa (xét lân cận hai phía, gắn fragment qua IP-ID) **trước khi đánh giá** | Bug, kèm artefact của Zeek | Không ảnh hưởng: mọi đánh giá chạy trên code đã sửa (`973b4c8`) |
| Thêm kiểm tra join trên Source A (CIC-2018, một member 9.6 MB) sau khi protocol IoT-23 đã khóa | Lúc đầu đánh giá Source A là "quá lớn" mà chưa xem bên trong archive. Brief yêu cầu thử Source A | Chỉ kiểm tra join, không có model; vẫn trong ngân sách 200 MB |
| Quyết định dựa trên mức FPR 1% và PR-AUC, không dựa trên 0.1% | 0.1% thiếu support ở mọi fold (luật đã khai báo trước cho phép) | Ràng buộc ưu tiên FPR ≤ 0.1% **không được đánh giá** |
| Ngoài 3 control đã khai báo, có thêm phân tích độ nhạy loại bản ghi 0 packet | Artefact chỉ phát hiện được sau khi tải dữ liệu | Chỉ báo cáo, không đổi quyết định |
