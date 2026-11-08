# Pre-registration: đánh giá ngoài trên NF-UNSW-NB15-v3 và cổng cho lượt train cuối (2026-11-09)

Commit trước khi đọc nhãn hay chạy model nào trên NF-UNSW-NB15-v3 trong repo Netirava. Hệ thống cuối (`pilot_cns/s0`) và demo không đổi theo kết quả của tài liệu này.

## Nguồn
- `../GraphIDS/data/NF-UNSW-NB15-v3/NF-UNSW-NB15-v3.csv`: cùng schema NetFlow v3 49 feature với NF-CSE-CIC-IDS2018-v3, do cùng nhóm UQ sinh từ PCAP của UNSW-NB15. Traffic do IXIA PerfectStorm tạo, trong hai phiên capture.
- **Lịch sử dùng trong dự án** (ngoài repo Netirava):
  - GraphIDS và Run 1 dùng split ngẫu nhiên;
  - NP-v1 dùng period B (18/02/2015) để phát triển và period A (22/01/2015) để đánh giá, rồi giữ công thức A0 dựa trên kết quả đó.
- Vì vậy: UNSW là nguồn mới với **model** CIC (chưa từng thấy UNSW), nhưng **không** mới với **recipe** A0.

## E1. Đánh giá model frozen (không train)
- **Model:** `pilot_cns/s0` (cuối) và A0 v2 (baseline), không đổi gì. Threshold khóa trên C1 của CIC, α ∈ {0.1%, 1%}. Không calibrate lại trên UNSW.
- **Dữ liệu:**
  - mọi row, chia theo ngày capture (ngày UTC của `FLOW_START`), mỗi ngày báo riêng;
  - loại bản trùng toàn phần (timestamp, IP, 49 feature, giữ bản đầu tiên); báo cả số raw.
- **Metric:**
  - benign FPR kèm Wilson;
  - recall theo lớp UNSW, kèm số flow, số host nguồn, số host đích và số episode (nhãn + nguồn + đích, nghỉ > 30 phút) có ít nhất một flow bị alert;
  - lớp CIC mà model gán cho flow tấn công (mô tả);
  - AUROC theo lớp so với benign (không dùng threshold).
- **Diễn giải** (khai báo trước):
  - "Threshold giữ được" ở một α nếu FPR ≤ 2α ở **mọi** ngày.
  - Recall chỉ mô tả khả năng chuyển giao của score; không có lớp UNSW nào là known class của model.

## E2. Cổng cho lượt train duy nhất còn lại
Đánh giá chỉ trên nhãn, host, thời gian và hash của row, trước mọi fit.

| # | Điều kiện | Ngưỡng |
|---|---|---|
| G1 | Lớp thiểu số có đủ mẫu thực và đủ nhóm độc lập | Lớp thiểu số = lớp chiếm < 1% flow tấn công sau khi loại trùng. Cần ≥ 2 lớp thiểu số có ≥ 30 flow (đã loại trùng) ở **cả hai** ngày capture, và host nguồn hoặc episode ở mỗi phía |
| G2 | Biết ý nghĩa của timestamp, host và kịch bản | Tài liệu nguồn và dữ liệu khớp nhau: hai phiên capture, subnet attacker và victim, nhãn sinh từ ground truth của IXIA |
| G3 | Không có bản trùng xuyên split | 0 bản trùng toàn phần giữa hai ngày. Báo thêm tỷ lệ fingerprint 49 feature (không có timestamp/IP) của lớp thiểu số xuất hiện ở cả hai ngày, như một rủi ro |
| G4 | Benign calibration và test riêng | Có benign đủ lớn ở ngày train để tách một khối calibration (20% cuối theo thời gian, ≥ 100,000 flow) và benign ở ngày test |
| G5 | Trong ngân sách tài nguyên | Ước tính RAM < 8 GB, thời gian fit < 10 phút trên máy hiện tại |
| G6 | Phần test chưa từng dùng để chọn recipe | Ngày test không phải period A hay B của NP-v1, và không thuộc split ngẫu nhiên của Run 1 hay GraphIDS |

**Luật:**
- Train chỉ khi **G1–G6 đều đạt**.
- G6 được thêm vào năm điều kiện của người dùng vì câu hỏi của lượt train là "recipe khóa trước đạt gì trên một nguồn mới". Nếu phần test đã dùng để chọn chính recipe đó, kết quả không trả lời được câu hỏi.
- Nếu một điều kiện không đạt: **không train**, ghi lý do, giữ lượt train.

**Thiết kế nếu cổng đạt** (khóa ngay ở đây):
- CatBoost multiclass, công thức A0, `auto_class_weights = Balanced`, không SMOTENC, seed 0;
- train trên một ngày capture, 20% cuối của ngày đó làm calibration benign, test trên ngày còn lại; taxonomy của UNSW;
- báo theo lớp: support, precision, recall, F1, số host và episode; recall ở α = 0.1% và 1%.

## E3. Thử nghiệm với người (formative)
Kit `task-make` / `task-run` / `task-score` đã có. Chỉ chạy được khi có người tham gia. Nếu có, đổi thứ tự C0/C1 giữa các người, ghi số người và kinh nghiệm, và gọi kết quả là formative.
