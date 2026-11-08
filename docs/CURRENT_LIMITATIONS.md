# Netirava: các hạn chế hiện tại (2026-11-08)

Tổng hợp từ mọi artifact và báo cáo hiện có. Không có thí nghiệm mới, không sửa số liệu lịch sử.

## Cách đọc
**Trạng thái bằng chứng**
- **CM: đã chứng minh.** Đo được, tái lập được từ artifact; với kết quả "HO", phương pháp đã được khóa trước khi chạy holdout.
- **TĐ: chưa đủ bằng chứng.** Có đo, nhưng support nhỏ, within-episode, exploratory hoặc phương pháp được chọn trên chính dữ liệu đó.
- **GT: giả thuyết.** Chưa đo.

**Mức độ** (ảnh hưởng tới claim của bài nộp)
- **Nghiêm trọng:** làm sai claim nếu không ghi rõ.
- **Cao:** giới hạn đáng kể khả năng dùng thực tế.
- **Trung bình.**
- **Thấp.**

**Nhãn:** "gốc" là nhãn của NF-v3; "sửa" là nhãn theo luật CNS2022 (`truth_cns2022.parquet`).

## Tóm tắt cho slide (5 hạn chế phải nói)
1. **Nhãn lớp hiếm trong NF-v3 phần lớn sai.**
   - Chỉ 6.9% flow web là credible.
   - F1 lớp hiếm trên nhãn gốc đo khả năng *tái tạo nhãn*, không đo khả năng phát hiện XSS hay SQLi thật.
   - XSS và SQLi thật chỉ có 1 episode, với 17–80 flow.
2. **Không phát hiện được họ tấn công lạ ở FPR thấp:**
   - Bot 0/8 episode;
   - DDoS (holdout): recall 0 ở FPR 0.1%.
   - Phương pháp anomaly đề xuất (V4b) đã **bị bác bỏ** trên holdout.
3. **FPR thay đổi theo ngày ở cùng một threshold:** từ 0.037% tới 0.598% (nhãn gốc). Model train trên nhãn đã sửa giảm FP theo flow, nhưng làm **tăng số incident báo nhầm mỗi giờ** ở một số kịch bản.
4. **Gom incident theo source IP không hợp với tấn công nhiều nguồn:** web brute-force đến từ 562 IP. Ưu tiên theo severity không tốt hơn ưu tiên theo khối lượng.
5. **Một testbed, phần lớn các lớp chỉ có một episode.** Hai holdout đã dùng hết (H2 chỉ có 1 episode). Chưa có đánh giá độc lập nào cho model train trên nhãn đã sửa.

---

## 1. Minority classes
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 1.1 | Rất ít mẫu đáng tin của XSS và SQLi | **Credible theo cặp IP + cửa sổ + TCP/80:** Web 115, XSS 41, SQLi 20. **Sau khi sửa theo CNS2022:** Web 70, XSS 80, SQLi 17. **Eval của pilot:** Web 27, XSS 30, **SQLi 2** | `FP_LABEL_FORENSICS.md` §4, `DATA_SUFFICIENCY_DECISION.md`, `CORRECTED_LABEL_PILOT_RESULTS.md` | CM | Nghiêm trọng |
| 1.2 | F1 trên nhãn gốc không phản ánh khả năng phát hiện thật | Web F1 0.769 đo trên 715 flow eval **không có flow credible nào** (0/715). Train không có XSS hay SQLi credible. Rare macro-F1 0.494 (3 seed) là mức tái tạo nhãn NF-v3 | `RESULTS_FINAL_ADDENDUM.md`, `FP_LABEL_FORENSICS.md` §4 | CM | Nghiêm trọng |
| 1.3 | A0 v2 (train nhãn gốc) thất bại trên nhãn đã sửa | XSS F1 **0.00** ở cả 3 seed; SQLi 0.01–0.12; Web 0.52–0.62. Benign FPR trong phạm vi web **47.7%** (traffic nền UDP/500) | `CORRECTED_LABEL_PILOT_RESULTS.md` §1 | CM (dev) | Nghiêm trọng nếu A0 v2 là model cuối |
| 1.4 | Pilot rất tốt nhưng chỉ within-episode | Trên nhãn đã sửa: Web F1 0.98, XSS 1.00, SQLi 1.00 (n = 2). Cùng attacker, cùng cửa sổ, chia theo thời gian, nên không tách được "học hành vi" với "nhớ episode" | Như trên | TĐ (INCONCLUSIVE) | Cao |
| 1.5 | Lợi ích của SMOTE chưa chắc chắn | Bỏ SMOTE: Δ rare macro-F1 −0.048, −0.061, −0.143 (cùng dấu ở 3 seed), nhưng CI bootstrap của seed 0 là [−0.162, +0.003], chưa loại trừ 0. So với SqrtBalanced: −0.010, −0.028, +0.059 (không nhất quán) | `RESULTS_FINAL.md` §2, §7 | TĐ | Trung bình |
| 1.6 | Mỗi lớp hiếm chỉ có 1 episode, 1 attacker | 18.218.115.60 → 172.31.69.28 ngày 22/02. Ngày 23/02 không có flow web nào trong NF-v3 | `DATA_SUFFICIENCY_DECISION.md` | CM | Nghiêm trọng (giới hạn tổng quát hóa) |
| 1.7 | Chưa chứng minh được hiệu quả trên lớp hiếm theo nghĩa "vững" | Theo 1.1–1.6: chỉ có within-episode, trên một episode | — | TĐ | Nghiêm trọng |

## 2. Unknown / zero-day detection
Netirava **không** claim phát hiện zero-day. Tấn công chưa thấy chỉ có thể lộ ra qua `attack_score` cao.

| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 2.1 | A0 bỏ sót họ lạ ở FPR thấp | **Bot (dev):** 0/8 episode ở mọi α ≤ 1%. **DDoS LOIC-HTTP (holdout H1, model v1):** recall **0** ở α = 0.1% (FPR thực tế 0.122%); 0.707 ở 0.5%; 0.757 ở 1% | `RESULTS_DECISION.md` | CM (HO cho DDoS) | Cao |
| 2.2 | Họ gần với họ đã biết thì phát hiện được, nhưng chỉ có 1 episode | **Holdout H2 DoS-Hulk:** recall 0.928 ở FPR 0.050%. 1 attacker, không có CI | `RESULTS_FINAL.md` §7 | TĐ | Trung bình |
| 2.3 | Anomaly gom theo entity (V4b) không tổng quát hóa | Dev Bot: 8/8 ở α = 1% (tham số chọn trên chính Bot). H1 DDoS: Δ so với A0 là **−0.685** [−0.700, −0.671] ở 0.5% và **−0.050** ở 1% | `RESULTS_DECISION.md` | CM (kết quả âm, HO) | Cao |
| 2.4 | IsolationForest đứng một mình không bắt được gì ở FPR chấp nhận được | DDoS recall 0 ở mọi α. Bot AUROC 0.92 (A0 chỉ 0.72), nhưng recall = 0 ở 0.1% | `RESULTS_DECISION.md`, `RESULTS_MVP.md` | CM | Trung bình (đã đưa ra ngoài phạm vi) |
| 2.5 | "Gom A0 score theo entity" mới chỉ là ý tưởng hậu nghiệm | Bắt 78% DDoS ở 0.1%, nhưng được chọn **sau khi** đã xem holdout, và làm FPR ngày Infiltration lên 3.5–6% | `RESULTS_DECISION.md` | GT | — (không theo đuổi) |
| 2.6 | Pilot mất khả năng "bắt nhầm đúng" portscan | Recall portscan (nhãn đã sửa): pilot 0.5–0.7%, A0 v2 6–11% | `CORRECTED_LABEL_PILOT_RESULTS.md` §2 | CM (dev) | Trung bình |

## 3. False positives
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 3.1 | FPR thay đổi theo ngày ở cùng threshold (A0 v2, α = 0.1%, nhãn gốc) | Known 0.037% · Bot 02/03 0.081% · H2 16/02 0.050% · **Infiltration 28/02 0.598%** (gấp 6 mục tiêu). Model v1 trên H1: 0.122% | `RESULTS_FINAL.md` §2, §7; `RESULTS_DECISION.md` | CM | Cao |
| 3.2 | FPR phụ thuộc mạnh vào seed | S1, A0 v2 seed 0/1/2: 0.598 / 0.350 / 0.158%. Threshold 0.868 / 0.876 / 0.887 | `CORRECTED_LABEL_PILOT_RESULTS.md` §2, registry | CM | Cao |
| 3.3 | Phần lớn FP của 28/02 là lỗi nhãn | 804/959 flow FP là NMAP .24 → .15 bị gắn Benign. Với nhãn đã sửa (sensitivity): 0.097%. Kết luận dựa trên PCAP của bên thứ ba, chưa kiểm chứng packet tại chỗ | `FP_LABEL_FORENSICS.md` §2 | CM có điều kiện | Trung bình |
| 3.4 | FP ngày Bot là FP thật, do học nhãn train sai | 524/699 flow là UDP/500 và 5060 tới .28; chính mẫu này mang nhãn web ngày 22/02 | `FP_LABEL_FORENSICS.md` §3 | CM | Cao (với A0 v2) |
| 3.5 | Pilot: FP theo flow giảm, nhưng **số incident báo nhầm mỗi giờ tăng** | **R1:** FPR 0.065–0.081% → 0.008–0.012%, nhưng incident báo nhầm/giờ 5.6 / 3.8 / 3.2 → **11.4 / 6.8 / 8.8**. **Known K1–K4:** 5.0 / 5.0 / 4.8 → **8.3 / 7.2 / 6.3** | `CORRECTED_LABEL_PILOT_RESULTS.md` §2 | CM (dev, 3 seed) | Cao (ảnh hưởng trực tiếp tới tải analyst) |
| 3.6 | **Đính chính:** pilot không giảm FP "nhất quán" trên S1 với nhãn đã sửa | Pilot / A0 v2 theo seed: 0.093 / 0.105, 0.016 / 0.068, **0.096 / 0.074** (seed 2 tệ hơn). Câu "giảm nhất quán qua 3 seed trên S1 và R1" trong báo cáo pilot chỉ đúng với nhãn gốc trên S1 và với R1 | Như trên | CM | Trung bình |
| 3.7 | Mức FPR mục tiêu là 0.1% trên **flow**, trong khi tải thực của analyst đo theo **incident** | S1: 959 flow FP nhưng chỉ 44 incident, 84% số flow đến từ 1 cặp host. R1: 699 flow, 28 incident | `RESULTS_FINAL.md` §7 | CM | Trung bình |
| 3.8 | Thêm lớp web làm threshold kém chuyển giao | A0 v1 (không có lớp web) chỉ có FPR 0.029% trên S1 ở α = 0.1% | `RESULTS_FINAL.md` §2 | CM | Trung bình |

## 4. Family-aware
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 4.1 | Không tăng accuracy của detection; chỉ là abstention | Precision, recall và alert của họ Web không đổi. K5 ở τ = 0.8: coverage 0.562, độ chính xác nhãn mịn khi phát 0.918, nhãn mịn sai 344 → 52, **44%** dự đoán trong họ Web bị trả về uncertain | `FAMILY_AWARE_FINAL_REPORT.md` §3 | CM | Trung bình |
| 4.2 | Không sửa được lỗi Benign → Web | Toàn stream: 6,765 flow bị đoán Web; precision họ Web 0.161 (nhãn gốc), 0.003 (nhãn đã sửa). Nhãn mịn sai chỉ giảm 5,979 → 5,129 | Như trên | CM | Cao (với A0 v2) |
| 4.3 | Accuracy–coverage trên nhãn đã sửa rất thấp (A0 v2) | K5, nhãn đã sửa: coverage 0.13, độ chính xác nhãn mịn 0.05 | Như trên | CM | Cao (với A0 v2) |
| 4.4 | **Severity của incident lộ nhãn mịn đã bị giấu** | `triage.incident_table` gán `severity = top_class.map(severity)`, với `top_class` là argmax mịn. Một incident "uncertain" vẫn có severity của SQLi (5) hoặc XSS (4) | `src/netirava/triage.py` | CM (đọc code) | Trung bình. Mâu thuẫn với yêu cầu nhất quán |
| 4.5 | Chỉ định nghĩa họ mơ hồ cho Web | Các họ khác (DoS GoldenEye/Slowloris, FTP/SSH) luôn phát nhãn mịn | `configs/demo.yaml → family` | CM (thiết kế) | Thấp |
| 4.6 | τ = 0.8 chỉ được kiểm tra trên một segment | Risk–coverage chỉ đo trên K5 (1,796 flow, nhãn gốc). Pilot: precision 1.00, recall 0.983, không có nhãn nào bị từ chối, n nhỏ | `FAMILY_AWARE_FINAL_REPORT.md` | TĐ | Thấp |
| 4.7 | Hai tài liệu ghi mức giảm nhãn mịn sai khác nhau | `DATA_SUFFICIENCY_DECISION.md` ghi "khoảng 97%"; báo cáo cuối ghi 344 → 52 (khoảng 85%) | 2 tài liệu | CM | Thấp. Sửa ở P4 của plan |

## 5. Fine-grained classification (XSS vs SQLi)
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 5.1 | Trên nhãn gốc, XSS và SQLi không tách được | 222/290 flow SQLi bị đoán thành XSS. 77 nhóm fingerprint mang nhiều nhãn; **100%** row XSS và **87%** row SQLi nằm trong các nhóm đó; nhóm lớn nhất là UDP/500 (338 row, 3 nhãn) | `MINORITY_INFORMATION_AUDIT.md` §1 | CM | Nghiêm trọng (với claim nhãn mịn) |
| 5.2 | Không có nhãn sạch đủ lớn để đo khả năng tách thật | Xem 1.1 và 1.4 | — | TĐ (INCONCLUSIVE) | Nghiêm trọng |
| 5.3 | Input (NetFlow v3) có lẽ thiếu thông tin phân biệt | Khác biệt nằm ở payload HTTP (URI, body), mà NetFlow không có. RQ-PCAP: join NF-v3 ↔ PCAP khả thi (85.7%), nhưng hướng này đã dừng | `MINORITY_INFORMATION_AUDIT.md` §3, `research/pcap_feasibility/` | GT | Cao (nhưng ngoài phạm vi) |
| 5.4 | "XSS" của NF-v3 trên máy chủ web không phải HTTP | 460/480 flow là IKE/500 từ IP AWS và không có trong pcap của host; 20 flow còn lại là DHCP | `research/pcap_feasibility/FEATURE_EXTRACTION_REPORT.md` §4 | CM | Nghiêm trọng (với nhãn gốc) |

## 6. Incident triage
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 6.1 | Gom theo source IP không xử lý được chiến dịch nhiều nguồn | Web brute-force đến từ 562 IP nguồn, tạo 386 episode nhỏ, vượt xa budget 10–30/giờ. Episode phủ @ B = 30 trên known: 0.306 | `RESULTS_FINAL.md` §3, §7 | CM | Cao |
| 6.2 | Ưu tiên theo khối lượng hoặc severity bỏ quên tấn công ít flow | Severity ≈ volume (episode@30: 0.311 so với 0.313 ở α = 0.5%), có lúc làm SSH rơi khỏi hàng | `RESULTS_FINAL.md` §7 | CM (dev) | Cao |
| 6.3 | Luật ưu tiên được đặt sau khi thấy FIFO thất bại | H1: priority 10/10 so với FIFO 0/10 là **exploratory** | `RESULTS_FINAL.md` §3 | TĐ | Trung bình |
| 6.4 | Số triage trên holdout dùng model v1 | H1 được chấm bằng `artifacts/models_v1`; triage v2 chỉ có trên dev, H2 có 1/1 episode | `EXPERIMENT_REGISTRY.md` | CM | Trung bình |
| 6.5 | **Notification lúc chạy (FIFO theo budget) khác với hàng xem xét trên UI** (severity/volume) | `policy.py` notify B incident đầu tiên mỗi giờ; UI xếp lại top-B mỗi giờ theo severity hoặc volume. Cột `status` lại phản ánh FIFO | `src/netirava/policy.py`, `app.py` | CM (đọc code) | Trung bình. Dễ gây hiểu nhầm khi demo |
| 6.6 | Feedback được ghi nhưng không được dùng | Append-only, không có vòng học lại (cố ý). Chưa có đánh giá usability với analyst thật | `storage.py` | — (chưa đánh giá) | Thấp |
| 6.7 | Gom theo chiến dịch (đích + họ) chưa làm | — | `RESULTS_FINAL.md` §7 | GT | — |
| 6.8 | Budget B = 10/30 incident/giờ chỉ là giả định | Chưa đối chiếu với năng lực của SOC thật | `configs/demo.yaml` | GT | Thấp |

## 7. Generalization
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 7.1 | Một testbed, một dataset (theo quyết định) | NF-CSE-CIC-IDS2018-v3, subset 3.14M row | `DATASET_CARD.md` | CM | Cao |
| 7.2 | Known class được đánh giá within-episode | Known macro-F1 0.993 là lạc quan: mỗi class có 1 attacker IP, FTP trùng 100% | `RESEARCH_FRAMING.md`, `RESULTS_DECISION.md` | CM | Cao |
| 7.3 | Holdout ít và đã dùng hết | H1: 10 attacker IP, model v1. H2: 1 episode. Không dùng lại được cho model mới | `EXPERIMENT_REGISTRY.md` | CM | Cao |
| 7.4 | Model train trên nhãn đã sửa chưa có đánh giá độc lập | Pilot train trên 60% đầu mỗi cửa sổ web CNS2022, nằm **bên trong K5**, nên K5 không sạch cho pilot. Chưa chạy holdout nào | `src/netirava/pilot.py` | CM | Nghiêm trọng nếu pilot là model cuối |
| 7.5 | Chuyển giao giữa các đợt yếu (tiền lệ) | NP-v1: A1+B2 thắng ở E nhưng thất bại ở đợt A | `../experiments/NEXT_PHASE_*.md` | CM | Trung bình |

## 8. Data quality
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 8.1 | Lỗi nhãn kế thừa từ CIC | Nhãn web: 6.9% credible. Infilteration: chỉ 17% flow dính tới victim, trong khi 12,633 flow .24 → nội bộ mang nhãn Benign | `FP_LABEL_FORENSICS.md` | CM | Nghiêm trọng |
| 8.2 | Feature collision | 77 nhóm fingerprint mang nhiều nhãn trên 22/02. SlowHTTPTest trùng feature với FTP-BruteForce, nên bị loại khỏi thiết kế. Infilteration: 75% trùng với benign nếu bỏ port và DNS id | `MINORITY_INFORMATION_AUDIT.md`, `../GraphIDS/outputs/class_diagnostics/NF-CSE-CIC-IDS2018-v3_profile/PROFILE.md` | CM | Cao |
| 8.3 | Rủi ro shortcut từ port, TTL và `DNS_QUERY_ID` (giữ trong 49 feature) | Chưa có ablation bỏ các feature này cho model cuối. GraphIDS NO-GO là do shortcut cùng host | `MODEL_CARD_A0_v2.md` | GT | Trung bình |
| 8.4 | Nhãn đã sửa dùng xấp xỉ | Luật payload của CICFlowMeter được chuyển sang NetFlow bằng proxy. 17,082 nhãn Infilteration trở thành indeterminate. Chưa kiểm chứng ở mức packet, trừ kiểm tra join của web server | `CORRECTED_LABEL_AUDIT.md`, `research/pcap_feasibility/` | TĐ | Trung bình |
| 8.5 | Subset theo cửa sổ, không phải toàn bộ dataset | 14 cửa sổ, 3,139,471 row | `DATASET_CARD.md` | CM (thiết kế) | Thấp |

## 9. Operational constraints
| # | Hạn chế | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 9.1 | Chi phí chỉ đo trong replay | **A0:** 0.4–0.8 µs/flow. **Replay dev v2:** 1.67M flow trong 10.7 s. **Peak RSS khoảng 3.5 GB** (cả run nằm trong RAM). **Shadow:** 3.7–10.8 µs/flow | `RESULTS_FINAL.md` §5 | CM (replay) | Trung bình |
| 9.2 | Độ trễ export NetFlow giả định bằng 0 | `export_delay_ms: 0`; active/inactive timeout của nProbe không được mô hình hóa, nên latency phát hiện thật chưa được xác nhận | `configs/demo.yaml` | GT | Trung bình |
| 9.3 | Calibration drift | Một cửa sổ calibration duy nhất (20/02 12:00–14:05), không calibrate lại theo ngày; FPR thay đổi (3.1, 3.2) | `configs/demo.yaml`, mục 3 | CM | Cao |
| 9.4 | Chưa chạy trên traffic thật hay luồng streaming | Không có ingest nProbe hay Kafka; phản ứng chỉ là mô phỏng | `README.md` | — | Trung bình (đúng phạm vi datathon) |
| 9.5 | Phụ thuộc thiết bị khi train | Train trên GPU kèm learning rate probe theo CPU; kết quả có thể lệch nhẹ giữa các thiết bị | `MODEL_CARD_A0_v2.md` | CM | Thấp |

## 10. Cập nhật sau ops study (2026-11-08; số cũ ở trên giữ nguyên)
| # | Hạn chế / thay đổi | Bằng chứng định lượng | Nguồn | Trạng thái | Mức độ |
|---|---|---|---|---|---|
| 10.1 | **L-4.4 đã sửa:** severity của incident lấy từ nhãn family-aware | Flow uncertain lấy severity của họ (Web = 4) | `family.flow_severity`, test | CM | — |
| 10.2 | **L-6.5 đã sửa:** UI và export tách `notified` (budget FIFO) khỏi `queue_rank_*` | `incidents.csv` có cả hai cột | `triage.py` | CM | — |
| 10.3 | **L-7.4 giảm một phần:** pilot có đánh giá độc lập đầu tiên | H5–H9: FPR 0.065% [0.060, 0.070]; HOIC recall 0.81. Lớp hiếm của pilot vẫn chỉ within-episode | `OPS_STUDY_RESULTS.md` §6 | CM (HO) | Cao → Trung bình |
| 10.4 | **L-6.1/6.7: gom theo chiến dịch đã thử, NO-GO** | HOIC: episode phủ 0.80 → 1.00 và 46 → 5 mục/giờ, nhưng 6.9% (A0 v2) và 7.0% (pilot) incident chỉ-benign bị gộp vào campaign có tấn công (luật ≤ 5%) | `OPS_STUDY_RESULTS.md` §4 | CM (HO, kết quả âm) | Cao |
| 10.5 | Pilot bỏ sót Infilteration trên ngày mới | H6: recall 0.012 (A0 v2: 0.194); nhãn lớp này bị flag | §6 | CM (HO) | Trung bình |
| 10.6 | Pilot có FPR cao hơn A0 v2 ở α = 0.5% trên ngày benign | 0.51–0.59% so với 0.23–0.44% | §6 | CM (HO) | Trung bình |
| 10.7 | **L-9.3: drift monitor đã có nhưng chưa kiểm chứng được recall** | Chỉ 1–3 cửa sổ có FPR > 2α trên DEV + HO; TR theo FPR với pilot (ρ 0.56 [0.32, 0.73]), không với A0 v2 (ρ 0.32); α·TR sai số trung vị 0.3–0.6 bậc log10 | §5 | TĐ (INCONCLUSIVE) | Trung bình |
| 10.8 | Một holdout nhiều nguồn duy nhất | H5 HOIC, 10 attacker, một đích | §7 | CM | Trung bình |
| 10.9 | Holdout H5–H9 nay đã dùng | Không chạy lại với phương pháp mới | `OPS_STUDY_PREREG.md` | CM | — |

## Kết quả âm được giữ làm bằng chứng
- GraphIDS: NO-GO.
- V4a: không có lợi trên dev.
- **V4b: bị bác bỏ trên H1.**
- Severity không tốt hơn volume.
- NP-v1: A1+B2 không chuyển giao qua đợt.
- A0 v2: XSS F1 = 0 trên nhãn đã sửa.
- RQ-PCAP: NO-GO trên IoT-23.
- Pilot làm tăng số incident báo nhầm mỗi giờ trên R1 và known.
- Ops study: campaign correlation NO-GO (contamination 5–7%); campaign "open-once" (bản pre-register) che một SQLi thật trên DEV; drift monitor INCONCLUSIVE.
