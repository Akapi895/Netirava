# 01. Đề bài, câu hỏi nghiên cứu và protocol

## 1. Đề bài
Nguồn: [DN-CY-01](https://datanovathon.com/problems/gamswulvrvtidne).

| Mục | Nội dung |
|---|---|
| Mục tiêu | Model phát hiện xâm nhập mạng xử lý được dữ liệu mất cân bằng nặng và thích nghi với kiểu tấn công thay đổi |
| Expected outcome | (a) *"A detection model with robust performance on minority classes"*; (b) *"an alert triage interface"* |
| Nộp | Code, tài liệu, phần đánh giá, slide (hạn 10/11/2026) |
| Gợi ý công nghệ | Python, deep learning, SMOTE, ensemble |
| Metric chấm | Không công bố |
| Tiêu chí chung | Problem understanding, innovation, technical depth, data usage và methodology, AI/ML approach, solution quality, feasibility, real-world impact, presentation |

Netirava trả lời bằng một method ứng dụng có bằng chứng định lượng. Innovation nằm ở cách tích hợp ba thành phần và cách chứng minh (protocol chống leakage, CI, holdout khai báo trước, báo cả kết quả âm), không phải thuật toán mới hay SOTA.

## 2. Hai output, hai đơn vị đo
| Output | Đơn vị | Metric |
|---|---|---|
| (a) Model vững trên lớp thiểu số | Flow | P/R/F1 theo lớp kèm support và CI Wilson; macro-F1 lớp hiếm; benign FPR thực ở threshold đã khóa |
| (b) Triage | Incident (source IP + cooldown 15 phút event time, cùng một luật cho mọi phương pháp) | Số incident/giờ, tỷ lệ nén flow → incident, precision của incident, độ phủ episode @ budget B, thời gian tới lần xem đầu |

## 3. Câu hỏi nghiên cứu
| RQ | Câu hỏi | Trả lời ở |
|---|---|---|
| RQ1 | A0 có vững trên lớp hiếm không; SMOTE hay class weight giúp hay hại? | `04` §3 |
| RQ2 | A0 bỏ sót họ tấn công chưa thấy nào? | `04` §2, §6 |
| RQ3 | Gom anomaly score theo host có giúp phát hiện họ lạ? | `04` §2 (bác bỏ trên holdout) |
| RQ4 | Gom incident giảm tải analyst bao nhiêu, giữ được bao nhiêu episode dưới budget? | `06` |
| RQ5 | Chi phí vận hành? | `04` §7 |
| RQ-L | Nhãn NF-v3 có đáng tin cho lớp hiếm và FP không? | `02` §4–6 |
| RQ-F | Preprocessing và nhóm feature nào cải thiện được FP trên ngày khác? | `03` |
| RQ-C, RQ-D, RQ-M | Correlation theo campaign, drift monitor, chọn model trên holdout mới | `06`, `07`, `04` §6; protocol ở [`protocols/ops_study_prereg.md`](protocols/ops_study_prereg.md) |

## 4. Protocol chung
- **Thời gian:** train (14–15/02, phần đầu mỗi burst) → calibration (20/02, chỉ benign) → replay và stress (22/02, 28/02, 02/03). Replay causal theo `available_at = FLOW_END + export_delay`, quyết định ở tick 1 s.
- **Nhãn chỉ ở evaluator.** Stream của runtime không có cột nhãn; `features.flow_event_batch` từ chối cột nhãn.
- **Threshold** trên `attack_score = 1 − p(Benign)`, chọn trên benign của C1 ở α ∈ {0.05%, 0.1%, 0.5%, 1%}, rồi khóa. Mức chính α = 0.1%.
- **Known class:** train trên phần đầu, đánh giá trên phần đuôi của cùng episode (within-episode). Mỗi lớp chỉ có một episode nên con số known-class là lạc quan.
- **Holdout:** chọn chỉ từ support nhãn theo giờ, khai báo trong config trước khi có score, chạy một lần sau khi khóa phương pháp, không dùng lại cho phương pháp mới.

| Holdout | Cửa sổ | Dùng cho | Trạng thái |
|---|---|---|---|
| H1 | 20/02 14:05–14:35 DDoS LOIC-HTTP | Decision layer V4b | Đã dùng |
| H2 | 16/02 17:35–18:05 DoS-Hulk | Hệ thống v3 | Đã dùng |
| H3, H4 | 23/02 benign; 21/02 14:00–15:00 LOIC-UDP | Feature study | Đã dùng |
| H5–H9 | 21/02 HOIC; 01/03; 16/02 và 20/02 19:00; 28/02 19:00 | Ops study | Đã dùng |

## 5. Luật kết luận
- Chỉ claim "vững trên lớp hiếm" khi có F1 và recall của từng lớp kèm support, CI và FPR thực. Biến thể tăng recall nhưng giảm precision hay tăng FPR phải báo cả hai chiều.
- Lợi ích triage thể hiện bằng tỷ lệ nén và độ phủ episode @ B ở cùng budget.
- Mọi claim nằm trong phạm vi: replay flow đã hoàn tất, một testbed. Không gọi là SOTA, zero-day detection hay IPS.
