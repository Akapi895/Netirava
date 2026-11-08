# Research framing — Netirava cho DataNovathon 2026 (DN-CY-01)

Ngày 2026-11-08.

**Nguồn:**
- trao đổi với GPT Astra (`../ChatGPT-Astra - datanova-20261108-1122.md`);
- rubric chính thức (`../references/DataNova_DN-CY-01_GraphIDS_Problem_Gap_Innovation_Data_Review.md` §1.1);
- kết quả đã đo: [`RESULTS_MVP.md`](RESULTS_MVP.md), `../experiments/NEXT_PHASE_RESULTS.md`, `../experiments/RUN1_BENCHMARK_RESULTS.md`.

**Nhãn trạng thái dùng trong tài liệu:**
- **[ĐÃ ĐO]**: số liệu có trong artifacts;
- **[DẤU HIỆU]**: phân tích chẩn đoán, chưa phải kết quả vận hành;
- **[CHƯA ĐO]**: chưa có số liệu.

## 1. Bài toán và điều cần chứng minh
Đây là **datathon**: giá trị nằm ở một luận điểm được chứng minh bằng dữ liệu. Replay, log và giao diện chỉ dùng để đo và trình diễn, không thay cho bằng chứng định lượng.

> **Luận điểm mở đầu:** NIDS thông thường làm tốt trên dữ liệu đã biết, nhưng gặp hạn chế khi dữ liệu mất cân bằng, khi tấn công thay đổi, hoặc khi nguồn lực xử lý cảnh báo có giới hạn. Netirava khắc phục ít nhất một hạn chế và chứng minh lợi ích bằng thí nghiệm có đối chứng.

Câu chuyện nộp bài phải trả lời đủ năm câu: **baseline bỏ sót gì → xử lý bằng cách nào → cải thiện bao nhiêu → trả giá gì → còn giới hạn nào.**

**Đề bài** DN-CY-01, *Network Intrusion Detection with Imbalanced Threat Data*: *"handles highly imbalanced threat data and adapts to evolving attack patterns"* (OFFICIAL).
- **Chưa xác minh:** dataset bắt buộc, metric chấm chính thức, và đầu ra là binary hay multiclass.
- **Deliverable:** PPT, link demo chạy được, video (tùy chọn).

## 2. Trọng số chấm → bằng chứng cần nộp
| Tiêu chí (Devpost) | Trọng số | Bằng chứng | Trạng thái |
|---|---|---|---|
| Technical Implementation | **25%** | Pipeline chạy thật: causal replay, A0, anomaly, decision layer, evaluator, 14 test | MVP xong; decision layer V3/V4 [CHƯA ĐO] |
| Innovation & Originality | **20%** | **Một** cơ chế kết hợp hoặc quyết định đã qua ablation, vượt cả A0 **và** luật OR; không gọi là SOTA | [CHƯA ĐO] |
| Problem Relevance | 15% | Đúng hai trục của đề: mất cân bằng (lớp hiếm) và tấn công thay đổi (unknown family, chuyển giai đoạn) | Đã thiết kế |
| Data & Analytical Rigor | 15% | Protocol chống leakage; threshold khóa trước; CI; kết quả âm được báo trung thực (GraphIDS NO-GO; A1+B2 không chuyển giao qua đợt) | [ĐÃ ĐO] một phần |
| Impact & Feasibility | 15% | FP trên 1M flow benign, alert/giờ theo budget, latency, RAM | Có cho A0 |
| Presentation & Documentation | 10% | Dataset card, model card, report số liệu, demo replay | Có bản MVP |

Technical, Innovation, Rigor và Impact chiếm 75% → **bằng chứng định lượng là trọng tâm**.

## 3. Research questions
**Giả thuyết chính (cần kiểm chứng, chưa phải claim):**
> Trên dữ liệu mạng mất cân bằng được đánh giá theo thời gian, thêm tín hiệu bất thường vào bộ phân loại lớp đã biết làm tăng khả năng phát hiện attack family không có trong huấn luyện, trong khi vẫn kiểm soát báo động giả và giữ chất lượng các lớp đã biết.

| RQ | Câu hỏi | Trạng thái |
|---|---|---|
| **RQ1, gap** | A0 bỏ sót những tấn công chưa thấy nào? | **[ĐÃ ĐO]** Ở FPR 0.1% (khóa trên calibration, FPR thực đạt 0.0995%): Bot 0/8 episode (recall flow 0.000); Web 2/97 (0.0055); Infiltration 3/118 (0.0016, nhãn gắn cờ). Known-within-episode: recall 0.9985, macro-F1 0.993 (lạc quan, xem §5) |
| **RQ2, tính bổ sung** | Anomaly có thông tin về đúng các mẫu A0 bỏ sót không? | **[DẤU HIỆU]** AUROC Bot: IsolationForest 0.923 so với A0 0.718. Nhưng ở FPR 0.1% theo từng flow, IsolationForest cho recall 0 và chỉ thêm alert benign (FPR shadow 0.05–0.15%) |
| **RQ3, fusion** | Cơ chế kết hợp có vượt A0 **và** OR ở **cùng** FPR tổng và cùng budget không? | **[ĐÃ ĐO]** ([`RESULTS_DECISION.md`](RESULTS_DECISION.md)). V4b (đã khóa) giúp Bot trên dev ở α = 1% nhưng **không cải thiện trên holdout DDoS**, và kém A0 ở α = 0.5–1%. Claim bị bác bỏ |
| **RQ4, không gây hại** | Chất lượng known class, benign FPR và tải cảnh báo có giữ được không? | Baseline A0 [ĐÃ ĐO]; biến thể [CHƯA ĐO] |
| **RQ5, thời gian** | Model và threshold đã khóa có ổn định ở giai đoạn sau không? | **[ĐÃ ĐO] một phần:** benign FPR trên các replay sau calibration là 0.007–0.029%; chưa có bảng theo từng cửa sổ |

- Mất cân bằng là **điều kiện đánh giá bắt buộc** (báo cáo lớp hiếm riêng, kèm support và CI), không phải mục tiêu cải thiện chính.
- Adaptation bằng nhãn mới là hướng mở rộng có điều kiện, chỉ làm sau RQ3.

## 4. Architecture baseline để thử nhiều hướng
```mermaid
flowchart LR
  D[(Replay theo thời gian<br/>available_at = end + delay)] --> FE[FlowEvent<br/>không nhãn, allowlist 49 feature]
  FE --> A0[A0: CatBoost known-class<br/>p(class), attack_score]
  FE --> AN[Anomaly: IsolationForest<br/>novelty score]
  A0 --> DL{Decision layer}
  AN --> DL
  DL -->|V1 A0 only<br/>V2 Anomaly only<br/>V3 OR<br/>V4 cơ chế đề xuất| CAL[Threshold khóa trên calibration<br/>cùng FPR tổng mục tiêu]
  CAL --> POL[Gom incident chung<br/>entity + cooldown + budget B]
  POL --> OUT[(Alert / incident log)]
  OUT --> EV[Evaluator: nhãn chỉ ở đây]
```
**Bất biến giữa các biến thể:** cùng stream, cùng feature, cùng calibration window, **cùng FPR tổng**, cùng cách gom incident, cùng budget B.
- Luật OR phải được calibrate lại để FPR tổng bằng mục tiêu, không chồng hai ngưỡng 0.1% lên nhau.
- **Đã có trong repo:** stream không nhãn, A0, anomaly ở shadow, policy, evaluator, test về prefix invariance và shadow cô lập.
- **Cần thêm:** V3/V4 chạy offline trên `detections.parquet` đã lưu, không phải chạy lại model.

## 5. Protocol đánh giá
| Điều kiện | Thiết lập | Câu hỏi |
|---|---|---|
| Known class | Train trên phần đầu episode, đánh giá phần đuôi (**within-episode**). Lạc quan vì mỗi class chỉ có 1 attacker IP và đuôi FTP trùng fingerprint 100% với train | Phương pháp mới có làm giảm năng lực đang có không? |
| **Unknown family** | Family bị loại khỏi train **và** khỏi mọi lựa chọn (detector, threshold, trọng số fusion). **Family dùng để phát triển tách khỏi family đánh giá cuối** | Có phát hiện được attack ngoài các lớp đã học không? |
| Chuyển giai đoạn | Khóa model và threshold, chạy trên các ngày sau; báo cáo theo cửa sổ | Recall và FPR thay đổi thế nào? |

**Luật dữ liệu:**
- Giữ phân bố tự nhiên; không kéo dữ liệu tương lai về train.
- Công bố support theo từng giai đoạn; báo cáo riêng row trùng và row chưa thấy.
- Nhãn chỉ dành cho evaluator.
- Một episode Bot hay Infiltration duy nhất chỉ là bằng chứng cho đúng tình huống đó.

## 6. Metric gắn với claim và luật chứng minh
| Claim | Metric (chính được in đậm) |
|---|---|
| Phát hiện unknown tốt hơn | **Unknown recall (episode và flow) tại FPR đã khóa**; PR-AUC; Δ so với A0 **và** so với OR |
| Không tăng báo động sai | Benign FPR thực tế, FP trên 1M flow benign, kèm CI |
| Giữ chất lượng known class | Macro-F1 known; P/R/F1 theo class; confusion matrix |
| Lớp hiếm | Kết quả theo class kèm support và CI; gắn cờ khi n nhỏ |
| Ổn định theo thời gian | Recall và FPR theo cửa sổ |
| Phù hợp nguồn lực SOC | Precision@B, recall@B (cùng B, cùng đơn vị incident); alert/giờ |
| Chi phí | Throughput, latency p95, RAM, thời gian tạo feature |

- **Kết quả vận hành:** threshold chọn trên calibration rồi khóa.
- **Đường recall–FPR trên tập đánh giá:** chỉ dùng để phân tích, không lấy điểm tối ưu trên đó làm kết quả triển khai.

**Luật chứng minh (khai báo trước khi chạy).** Phương pháp đề xuất chỉ được gọi là cải tiến khi thỏa đủ các điều kiện sau trên family đánh giá cuối:
1. Δ unknown recall so với A0 **và** so với OR > 0, với CI bootstrap theo episode/entity loại trừ 0;
2. FPR thực tế ≤ mục tiêu, và known macro-F1 không giảm quá `MAT`;
3. ablation chỉ ra được thành phần nào tạo ra lợi ích.

Nếu OR đã bằng cơ chế phức tạp thì giữ OR. Nếu anomaly không giúp gì ở FPR chấp nhận được thì bỏ nhánh anomaly. Chưa có so sánh đủ rộng thì gọi là "cải tiến được kiểm chứng trong phạm vi bài thi", không gọi là SOTA.

## 7. Câu chuyện năm bước: đã có và còn thiếu
| Bước | Đã có | Còn thiếu |
|---|---|---|
| Baseline bỏ sót gì | A0 có Bot recall 0, Web và Infiltration gần 0 ở FPR 0.1% [ĐÃ ĐO]; GraphIDS NO-GO; A1+B2 không chuyển giao qua đợt (NP-v1) | Family đánh giá cuối chưa được chạm tới |
| Xử lý bằng cách nào | Anomaly xếp hạng Bot tốt hơn A0 (AUROC 0.92 so với 0.72) [DẤU HIỆU] | V3 (OR có calibrate lại); V4 (một cơ chế, ví dụ gom anomaly score theo entity/cửa sổ một cách causal) |
| Cải thiện bao nhiêu | — | Δ ở cùng FPR và cùng budget, kèm CI |
| Trả giá gì | Shadow tốn 3.7–10.8 µs/event; shadow tạo 1,320 alert benign trong scenario Bot [ĐÃ ĐO] | FP/1M và alert/giờ của từng biến thể |
| Giới hạn | Mỗi class chỉ một episode; known là within-episode (lạc quan); export delay giả định bằng 0; cùng một testbed | Kết quả trên family cuối |

## 8. Quyết định còn mở (chốt trước khi chạy V3/V4)
1. **Family dùng để đánh giá cuối.**
   - Bot đã được xem ở bước chẩn đoán AUROC. Nếu dùng Bot làm family đánh giá cuối thì phải khai báo rõ điều đó.
   - Phương án sạch hơn: Bot và Web làm *development unknown*; holdout cuối là một family chưa đưa vào subset, ví dụ DDoS LOIC-HTTP hoặc HOIC (20–21/02), hoặc DoS-Hulk (16/02).
   - SlowHTTPTest không dùng được: feature trùng hệt FTP-BruteForce.
   - Phương án này cần mở rộng subset, vì subset hiện có 2.97M flow, sát trần 3M.
2. **Đơn vị budget B:** incident theo source IP (như MVP) hay theo flow.
3. **FPR vận hành mục tiêu:** giữ 0.1%, hay báo cáo thêm nhiều mức (ví dụ 0.05%, 0.5%), mọi mức đều chọn trên calibration.
