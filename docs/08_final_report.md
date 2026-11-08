# Báo cáo tổng: Netirava cho DN-CY-01

Đề bài: *Network Intrusion Detection with Imbalanced Threat Data*. Hai output được yêu cầu: (a) model vững trên lớp thiểu số, (b) giao diện triage alert.

Dữ liệu: NF-CSE-CIC-IDS2018-v3, replay flow đã hoàn tất trong một testbed. Mọi số liệu ghi rõ bộ nhãn (gốc NF-v3 hoặc sửa theo CNS2022) và loại bằng chứng:
- **DEV:** dùng để phát triển hoặc chọn;
- **EXP:** phân tích hậu nghiệm;
- **HO:** holdout khai báo trước, chạy một lần sau khi khóa phương pháp.

Chi tiết từng phần nằm ở các tài liệu `01`–`07`; bảng hạn chế ở [`09_limitations.md`](09_limitations.md).

## 1. Câu chuyện năm bước
| Bước | Nội dung |
|---|---|
| Baseline bỏ sót gì | Ở FPR 0.1%, A0 bỏ sót Bot (0/8 episode), DDoS LOIC-HTTP (recall 0) và hầu hết HOIC (0.04). SQLi gần như luôn bị đoán thành XSS (222/290 flow). Với hàng FIFO (B incident mở đầu tiên mỗi giờ), 10 incident/giờ toàn là benign và cả 10 episode DDoS bị bỏ lỡ |
| Nguyên nhân đo được | **Nhãn**: chỉ 6.9% flow web của NF-v3 là tấn công thật; 804 flow portscan bị gắn Benign. **Dữ liệu**: NF-v3 xuất phần lớn flow tấn công hai lần; mỗi lớp chỉ có một episode và một attacker. **Thông tin**: NetFlow không có payload HTTP để tách XSS với SQLi |
| Xử lý | SMOTE theo quy tắc cho lớp hiếm; train trên nhãn sửa CNS2022; nhãn family-aware (không đoán bừa lớp mịn); gom alert thành incident có budget và hàng ưu tiên; thử correlation theo campaign và drift monitor |
| Cải thiện bao nhiêu | SMOTE tốt hơn không xử lý ở cả 3 seed (rare macro-F1 0.469 so với 0.421, seed 0). Model nhãn sửa giữ FPR 0.065% trên 5 cửa sổ chưa từng chạm và bắt 81% HOIC. Family-aware giảm nhãn mịn sai 344 → 52. Gom incident nén 243–1,024 lần |
| Trả giá và giới hạn | Model nhãn sửa kém ở Infiltration, portscan và ở FPR α = 0.5%. Bằng chứng lớp hiếm là within-episode. Correlation theo campaign gộp nhầm benign (NO-GO). Drift monitor chưa đủ bằng chứng |

## 2. Các giai đoạn: đã thử gì, kết quả, quyết định
### 2.1 Dữ liệu và EDA ([`02_data_eda_labels.md`](02_data_eda_labels.md))
| Đã làm | Kết quả | Quyết định |
|---|---|---|
| `inspect` toàn bộ CSV (20,115,529 flow, 55 cột) | sha1 khớp bagit; 0 null, 0 giá trị âm, 0 timestamp ngược; mỗi lớp tấn công chỉ nằm trong một ngày UTC | Chia theo cửa sổ thời gian, không chia ngẫu nhiên |
| Subset theo cửa sổ, chốt trước khi train | 14 cửa sổ, 3,139,471 flow; train → calibration → replay theo thời gian | Subset `CIC18-Causal-Demo-v1` |
| Audit host và fingerprint | Mỗi lớp known có 1 attacker IP; FTP ở phần eval trùng 100% fingerprint với train | Báo known-class là within-episode, lạc quan |
| EDA chống leakage (FE study) | **310,892 flow là bản trùng toàn phần**, khoảng 50% flow FTP/SSH/GoldenEye; giá trị 0 mang tính cấu trúc; artefact `ICMP_TYPE` trên flow TCP (40% Slowloris); src port và TTL trôi theo ngày (PSI 0.165) | Loại bản trùng; đưa src port, TTL vào danh sách ứng viên shortcut |

### 2.2 Nhãn ([`02_data_eda_labels.md`](02_data_eda_labels.md) §4–6)
| Đã làm | Kết quả | Quyết định |
|---|---|---|
| Forensics FP của A0 ở α = 0.1% | S1: 804/959 flow FP là NMAP .24 → .15 bị gắn Benign; FPR 0.598% → 0.097% nếu sửa (EXP). R1: FP do model học nhãn web sai (UDP/500) | Lỗi nhãn là nguyên nhân chính |
| Đối chiếu nhãn web với CNS2022 | 176/2,538 (6.9%) flow web credible; train không có XSS hay SQLi credible | F1 lớp hiếm trên nhãn gốc chỉ đo khả năng tái tạo nhãn |
| Áp luật CNS2022 thành `truth_cns2022.parquet` (file riêng) | 35,730 flow đổi nhãn; nhãn Bot đúng 100%; support thật còn Web 70, XSS 80, SQLi 17, mỗi lớp 1 episode | Báo cả hai bộ nhãn |
| Collision fingerprint | 77 nhóm fingerprint mang nhiều nhãn; 100% XSS và 87% SQLi nằm trong các nhóm này, chủ yếu là IKE UDP/500 | XSS/SQLi: INCONCLUSIVE; cần payload HTTP |

### 2.3 Preprocessing và feature ([`03_preprocessing_features.md`](03_preprocessing_features.md))
| Đã thử | Kết quả DEV (3 seed) | Kết quả HO (H3, H4) | Quyết định |
|---|---|---|---|
| G_prep: categorical, port top-k, NaN cấu trúc, gom trùng, SMOTE có scale | M1 +0.026; FPR R1 tăng | — | Loại |
| G_ratio (+14 tỷ lệ), G_flag (+25 bit cờ) | Không vượt control hoặc FPR R1 tăng | — | Loại |
| **G_shortcut_drop** (bỏ src port, DNS id, TTL, TCP window) | FPR S1 0.099% → 0.057%; adversarial AUC 0.818 → 0.795 | **Kém hơn reference** ở H3 FPR (0.026% so với 0.013%) và H4 recall α = 1% (0.28 so với 0.87) | Chấp nhận ở DEV, **bị holdout bác bỏ** |
| G_ctx (ngữ cảnh causal theo host, 60 s) | Bắt 71% scan S1, incident báo nhầm giảm 3 lần; FPR R1 tăng 3 lần | — | Loại theo luật; giả thuyết cho bước sau |
| Loại bản trùng toàn phần | Sửa dữ liệu, không chọn theo metric | — | Giữ |

Pipeline cuối giữ **49 feature NetFlow v3** (không có IP, timestamp tuyệt đối hay nhãn). Ở H3 (234,262 flow benign, ngày chưa chạm), mọi model đạt FPR 0.007–0.052% ở mục tiêu 0.1%.

### 2.4 Modeling ([`04_modeling.md`](04_modeling.md))
| Đã thử | Kết quả | Quyết định |
|---|---|---|
| A0 v1: CatBoost 5 known class (công thức NP-v1) | Known recall 0.9985, FPR 0.025% (within-episode); Bot 0/8 | Baseline MVP |
| IsolationForest shadow | Thêm 0 phát hiện ở FPR 0.1% dù AUROC Bot 0.92 (A0 0.72) | Chỉ chạy shadow |
| Decision layer V1–V4b (A0 + anomaly gom theo host) | V4b bắt 8/8 Bot ở α = 1% (DEV); trên H1 DDoS kém A0 (Δ −0.685 ở 0.5%) | **Bị holdout bác bỏ** |
| A0 v2: đưa Web/XSS/SQLi vào known class; SMOTE quy tắc | Rare macro-F1 0.469 (3 seed TB 0.494); F1 Web 0.769, XSS 0.528, SQLi 0.109 (nhãn gốc) | Model triển khai v2 |
| Ablation imbalance: không SMOTE (A1), SqrtBalanced (A2) | Bỏ SMOTE giảm rare macro-F1 ở cả 3 seed (−0.048, −0.061, −0.143); A2 không nhất quán | Giữ SMOTE; chưa hơn class weight |
| A0 v2 trên holdout H2 DoS-Hulk | Recall 0.928 ở FPR 0.050% (1 episode) | HO |
| Pilot: cùng công thức, train trên nhãn sửa (3 seed) | Trên nhãn sửa: A0 v2 có XSS F1 = 0, pilot 0.98–1.00 (within-episode, SQLi n = 2). FPR R1 0.065–0.081% → 0.008–0.012%; incident báo nhầm/giờ tăng trên R1 và known | GO cho giảm FP; INCONCLUSIVE cho XSS/SQLi |
| Review SOTA (HCE-Boost, HICID, DIDS-MFL, hierarchical IDS) | Không phương pháp nào thêm được thông tin còn thiếu hay sửa nhãn | NO-GO đổi kiến trúc; lấy ý tưởng bảo toàn khối xác suất cho family-aware |
| So sánh A0 v2 và pilot trên holdout mới H5–H9 | Pilot: FPR 0.065% [0.060, 0.070] so với 0.085% [0.080, 0.092]; incident báo nhầm 15.9 so với 24.1/giờ; HOIC 0.81 so với 0.04; Infiltration 0.012 so với 0.194 | Khuyến nghị pilot theo luật khai báo trước; **chờ người dùng chốt** |

### 2.5 Family-aware ([`05_family_aware.md`](05_family_aware.md))
| Đã làm | Kết quả | Quyết định |
|---|---|---|
| Họ Web (Web/XSS/SQLi): phát nhãn mịn khi tỷ trọng trong họ ≥ τ = 0.8 | K5 (nhãn gốc): nhãn mịn sai 344 → 52, coverage 0.562, độ chính xác khi phát 0.918. Không đổi xác suất, alert hay incident (có test và hash) | GO, như abstention trung thực |

### 2.6 Triage và correlation ([`06_triage_correlation.md`](06_triage_correlation.md))
| Đã thử | Kết quả | Quyết định |
|---|---|---|
| Gom incident theo source IP + cooldown 15 phút, budget theo giờ | Nén 243–1,024 lần; H1 DDoS: hàng ưu tiên phủ 10/10 episode với 10 incident/giờ, FIFO 0/10 (EXP) | Thành phần triage |
| Hàng theo severity (khai báo trước) so với volume | Severity ≈ volume (episode@30: 0.311 so với 0.313) | Giữ severity; nay theo nhãn family-aware |
| Correlation theo campaign (đích + họ, causal), campaign update mỗi giờ | HOIC: episode phủ 0.80 → 1.00, 46 → 5 mục/giờ (A0 v2); nhưng 6.9–7.0% incident benign bị gộp vào campaign tấn công (luật ≤ 5%) | **NO-GO**; chỉ là view thử nghiệm |

### 2.7 Drift monitoring ([`07_drift_monitoring.md`](07_drift_monitoring.md))
| Đã thử | Kết quả | Quyết định |
|---|---|---|
| Monitor không nhãn theo cửa sổ 15 phút so với C1: tỷ lệ alert (AR), tỷ lệ đuôi dưới ngưỡng (TR), score PSI, feature PSI | Holdout mới gần như không có cửa sổ FPR > 2α. TR theo FPR với pilot (ρ 0.56 [0.32, 0.73]), không với A0 v2. Không báo trên giờ chỉ có benign | INCONCLUSIVE; chỉ báo trên UI, không phải ước lượng FPR |

### 2.8 Hướng đã dừng
| Hướng | Kết quả |
|---|---|
| GraphIDS / GNN | NO-GO (shortcut theo host) |
| PCAP và feature HTTP (RQ-PCAP) | NO-GO trên IoT-23; join NF-v3 ↔ PCAP khả thi nhưng chưa trả lời câu hỏi XSS/SQLi |
| NP-v1 A1+B2 | Không chuyển giao qua đợt |
| HICID, DIDS-MFL, full HPO | Không triển khai (xem review SOTA) |

## 3. Hệ thống cuối
| Thành phần | Trạng thái |
|---|---|
| 1. Minority-aware detection | CatBoost 8 known class, SMOTE quy tắc, threshold khóa trên C1 ở α = 0.1%. Hai model: A0 v2 (nhãn gốc, baseline) và `pilot_cns/s0` (nhãn sửa). `configs/demo.yaml → final_system.model_dir` hiện đặt pilot theo luật RQ-M; quyết định cuối thuộc người dùng |
| 2. Family-aware classification | Tích hợp, có test |
| 3. Incident triage UI | Streamlit: hàng source incident (mặc định), view campaign (thử nghiệm), tab "Threshold reliability", feedback append-only, export |

Audit thay đổi của ops study: training invariance PASS, inference invariance PASS; thay đổi duy nhất làm đổi detection là model mặc định ([`ops_change_audit.md`](ops_change_audit.md)).

## 4. Số liệu dùng cho slide
| Claim | Số | Nhãn | Loại | Nguồn |
|---|---|---|---|---|
| Nhãn web NF-v3 phần lớn sai | 6.9% credible | gốc vs CNS2022 | EXP | `02` §4 |
| FPR giữ được trên ngày chưa chạm | 0.007–0.052% (H3); 0.026–0.127% (H5–H9) | gốc | HO | `03` §4, `04` §6 |
| SMOTE giúp lớp hiếm | −0.048 / −0.061 / −0.143 khi bỏ SMOTE | gốc | DEV | `04` §3 |
| Nhãn sửa giảm FP và bắt HOIC | FPR 0.065% vs 0.085%; HOIC 0.81 vs 0.04 | sửa nếu có | HO | `04` §6 |
| Family-aware giảm nhãn mịn sai | 344 → 52 | gốc | DEV | `05` §3 |
| Gom incident giảm tải | nén 243–1,024 lần; 10/10 vs 0/10 episode DDoS | gốc | EXP | `06` §2 |
| Correlation theo campaign | 46 → 5 mục/giờ, nhưng contamination 6.9% | gốc | HO, NO-GO | `06` §4 |
| Drift monitor | ρ(TR, FPR) 0.56 (pilot); recall INCONCLUSIVE | sửa | DEV + HO | `07` §3 |
