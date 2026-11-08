# Pre-registration: ablation imbalance sạch, kiểm kê cohort thiểu số, thử nghiệm triage (2026-11-09)

Commit trước khi chạy cả ba việc. Không có model nào được train cho các việc này trước commit này. Model cuối của hệ thống không đổi theo kết quả các việc dưới đây.

## A. Ablation xử lý mất cân bằng trên cùng điều kiện
**Câu hỏi:** trên cùng dữ liệu, nhãn, feature, split, calibration, dedup và seed, SMOTENC có tốt hơn không resampling hay class weighting không?

- **Dữ liệu train:** `configs/fe_study.yaml`, `fe.study_frame` (đã loại bản trùng toàn phần), `fe.final_train_mask`: toàn bộ T1–T4 và phần train của pilot ở web; nhãn sửa CNS2022; bỏ `attempted`/`indeterminate`. Đây đúng là tập train cuối của feature study (650,248 row).
- **Feature:** 49 cột NetFlow v3 thô (`features.matrix`).
- **Model:** công thức A0 (CatBoost 1000 iteration, depth 6, l2 3, learning rate dò trên CPU rồi train GPU).
- **Arm:**
  - `none`: không resampling, không trọng số;
  - `cw`: `auto_class_weights = "Balanced"`, không resampling;
  - `smotenc`: luật A0 (lớp < 1,000 row → 1,000, SMOTENC k = 5, mã phân loại copy từ láng giềng).
- **Seed:** 0, 1, 2 cho mọi arm (9 model). Không HPO.
- **Threshold:** α ∈ {0.1%, 1%}, chọn trên benign của C1 (đã loại trùng).

**Đánh giá DEV:**
- web: các row eval của pilot (`study_role = inner_val` trong T5/K5), nhãn sửa, P/R/F1 theo lớp kèm support và Wilson;
- known K1–K4 (`known_tail`): P/R/F1 theo lớp;
- benign FPR và số false source incident trên S1, R1;
- recall Portscan trên S1 (nhãn sửa).

**Đánh giá EXP** (holdout đã dùng, chỉ để mô tả): H3, H4 (`configs/fe_study.yaml`) và H5–H9 (`configs/ops_holdout.yaml`), đều loại bản trùng; benign FPR và recall LOIC-UDP, HOIC, Infilteration.

**Luật kết luận:**
- Lớp có support < 30 trong eval (SQLi n = 2, Web 27, XSS 30 → Web và SQLi) được gắn **INCONCLUSIVE**; vẫn báo số.
- "Arm X tốt hơn arm Y" trên một metric chỉ khi X tốt hơn Y ở cả 3 seed. Ngược lại: không phân biệt được.
- Kết quả **không** dùng để đổi model cuối.

## B. Kiểm kê cohort thiểu số độc lập trong NF-CSE-CIC-IDS2018-v3
**Câu hỏi:** trong chính dataset, còn cohort nào của lớp thiểu số (Web, XSS, SQLi; báo kèm Bot, Infilteration và các lớp khác) vừa độc lập, vừa đáng tin, vừa chưa dùng không?

- **Quét** toàn bộ CSV gốc, chỉ dùng nhãn, IP, port, thời gian và một hash của toàn bộ row (để đếm bản trùng toàn phần). Không có score của model nào.
- **Episode:** cùng nhãn + cùng IP nguồn + cùng IP đích, tách khi nghỉ > 30 phút.
- **Đã dùng:** episode giao với bất kỳ cửa sổ nào trong `demo.yaml`, `fe_study.yaml`, `ops_holdout.yaml`.
- **Đáng tin:**
  - lớp web: khớp luật CNS2022 đã chuyển thể (cặp 18.218.115.60 ↔ 172.31.69.28, trong cửa sổ, TCP/80);
  - lớp khác hoặc ngày khác: "chưa kiểm chứng" (không có luật).
- **Cohort đủ điều kiện:** chưa dùng **và** đáng tin **và** ≥ 30 flow sau khi loại trùng **và** khác episode với mọi dữ liệu train.
- Nếu không có cohort nào đủ điều kiện, kết luận là robustness của lớp thiểu số **chưa thể xác nhận** trong dataset này. Không tạo test bằng random split hay oversampling.

## C. Thử nghiệm triage nhỏ có đáp án tham chiếu
**Câu hỏi:** cùng tập alert và cùng số quyết định, hàng source incident của Netirava có giúp reviewer gặp nhiều loại tấn công hơn, mở ít mục nhầm hơn, quyết định đúng hơn so với hàng flow xếp theo score không?

- **Nguồn:** model cuối `pilot_cns/s0`, run `20261108T211057_a0_fast` (H5–H9, α = 0.1%). H5–H9 đã dùng để chọn model, nên kết quả là EXP.
- **Điều kiện** (cùng ngân sách 20 quyết định, 4 mỗi segment):
  - **C0, hàng flow theo score (không gom):** mỗi segment lấy 4 flow bị alert có score cao nhất (hòa thì flow sớm hơn). Card là một flow: giờ tương đối, token nguồn/đích, port, protocol, L7, byte, packet, thời lượng, score, lớp dự đoán.
  - **C1, hàng source incident của Netirava:** mỗi segment lấy 4 incident đầu tiên theo (giờ review, `queue_rank_severity`). Card là bằng chứng tại thời điểm review: số flow, số đích, số port, nhãn family-aware, severity, score lớn nhất, top port đích, thống kê byte, 5 flow ví dụ.
- **Làm mù:** IP thay bằng token theo từng task; không có ngày; không có nhãn. File đáp án ghi riêng, reviewer chỉ đọc sau khi đã lưu verdict.
- **Đáp án tham chiếu:** mục là attack nếu có ít nhất một flow (của card, tại thời điểm review) mang nhãn tấn công. Dùng nhãn sửa nếu ngày đó đã được audit, ngược lại dùng nhãn gốc; Infilteration được báo riêng vì nhãn lớp này bị gắn cờ.
- **Reviewer:**
  - Lượt chạy trong repo dùng **một reviewer là LLM (Claude), đã làm mù**. Đây không phải analyst người. Thời gian ghi là thời gian xử lý của reviewer, không suy ra cho người.
  - Kit có chế độ chạy tương tác cho người (`task-run`), ghi thời gian từng quyết định.
  - Thứ tự: C1 trước, C0 sau, để mọi hiệu ứng học được trong lúc làm nghiêng về phía baseline.
- **Kết quả báo cáo** (không kiểm định ý nghĩa thống kê):
  - (1) độ đúng của verdict so với đáp án;
  - (2) số loại tấn công (segment + nhãn) xuất hiện trong các mục đã xem, và số loại được xác nhận đúng;
  - (3) số mục benign phải mở;
  - (4) thời gian theo điều kiện.
- Gọi đúng tên là **đánh giá thử nghiệm nhỏ** (formative), không phải bằng chứng hiệu quả SOC.
