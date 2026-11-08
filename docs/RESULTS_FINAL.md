# Netirava — kết quả cuối cho DataNovathon 2026 (DN-CY-01)

Ngày 2026-11-08. Khung đánh giá: [`RESEARCH_FRAMING.md`](RESEARCH_FRAMING.md) v2.

**Dataset duy nhất:** NF-CSE-CIC-IDS2018-v3 (subset theo cửa sổ thời gian, xem [`DATASET_CARD.md`](DATASET_CARD.md)). Kết quả là **development evidence** trên replay flow đã hoàn tất, trong một testbed duy nhất. Không phải external validation, không phải SOTA.

**Hai output theo đề bài:**
- **(a)** model vững trên minority classes (đo theo **flow**);
- **(b)** alert triage interface (đo theo **incident**).

**Run và artifact** (ngoài git):

| Loại | Đường dẫn |
|---|---|
| Model A0 v2 | `artifacts/models/{a0,a1,a2}` |
| IsolationForest | `artifacts/models/anomaly` |
| Run dev v2 | `runs/20261108T122848_a0-shadow_fast` (`DECISIONS_dev.json`, `EVALUATION.json`) |
| Ablation imbalance | `runs/ablate_imbalance.json` |
| Holdout | `runs/20261108T115320_a0-shadow_fast` (`DECISIONS_holdout.json`, `DECISIONS_holdout_triage.json`), chấm bằng model v1 đã khóa (`artifacts/models_v1`) |

## 1. Câu chuyện trong một slide
| Bước | Số liệu |
|---|---|
| **Baseline bỏ sót gì** | Lớp hiếm bị gộp hoặc nhầm: SQL_Injection có F1 chỉ 0.11, vì 222/290 flow bị đoán thành XSS (hai lớp trùng feature). Tấn công chưa thấy bị bỏ sót ở FPR 0.1%: Bot 0/8 episode, DDoS 0/10. Xử lý alert theo từng flow vô dụng: 30 incident đầu tiên mỗi giờ toàn là benign, nên cả 10 episode DDoS đều bị bỏ lỡ |
| **Xử lý bằng cách nào** | (1) Đưa lớp hiếm vào known class và dùng SMOTE theo quy tắc (class < 1000 row → 1000, SMOTENC). (2) Gom incident theo host nguồn + cooldown 15 phút, rồi xếp hàng ưu tiên theo khối lượng mỗi giờ. (3) Ở chế độ shadow, gom anomaly score theo host (V4b) để phát hiện C&C đều đặn |
| **Cải thiện bao nhiêu** | Rare macro-F1 với SMOTE 0.469, so với 0.421 khi không SMOTE (Δ +0.048, CI [−0.003, +0.162]; chưa loại trừ 0). Ở FPR 0.5%, phát hiện lớp hiếm: Web 0.945, XSS 1.0, SQLi 1.0. Triage: 71,774 flow alert được gom thành 175 incident (nén 410 lần); với 10 incident/giờ, hàng ưu tiên phủ **10/10 episode DDoS** (FIFO: 0/10). Bot: V4b ở FPR 1% bắt 8/8 episode (A0: 0/8) |
| **Trả giá gì** | Thêm lớp web vào known class làm FPR thực tăng ở ngày khác (Infiltration 0.60% ở mục tiêu 0.1%). Ưu tiên theo khối lượng đẩy các tấn công web ít flow xuống cuối hàng. V4b bị bác bỏ trên holdout DDoS |
| **Còn giới hạn nào** | Mỗi lớp chỉ có một episode (within-episode); một testbed; SQLi và XSS không tách được về mặt feature; export delay giả định bằng 0; luật ưu tiên được đặt ra sau khi thấy kết quả FIFO |

## 2. Output (a): model vững trên minority classes
**Thiết lập:**
- Known class gồm 8 lớp: Benign, FTP, SSH, GoldenEye, Slowloris, **Brute_Force_-Web, Brute_Force_-XSS, SQL_Injection**.
- Lớp web lấy từ 22/02, giới hạn phạm vi vào máy chủ web (172.31.69.28, 172.31.69.1). Train 12:00–17:00, đánh giá 17:00–22:00 (**cùng episode**).
- Model triển khai được chốt trước là **A0** (công thức NP-v1: CatBoost 1000 iteration, GPU, learning rate theo CPU, SMOTE quy tắc LCCDE).
- A1 (không SMOTE) và A2 (SqrtBalanced) **chỉ là ablation**; không chọn model theo dữ liệu đánh giá.

**Theo class** (argmax, flow; CI Wilson 95% của recall giả định các row độc lập):

| Lớp | Support | A0 Precision | A0 Recall [CI] | A0 F1 | F1 không SMOTE (A1) | F1 SqrtBalanced (A2) |
|---|---|---|---|---|---|---|
| Benign | 346,851 | 0.997 | 0.999 | 0.998 | 0.998 | 0.999 |
| FTP-BruteForce | 81,780 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| SSH-Bruteforce | 57,196 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| DoS-GoldenEye | 11,166 | 0.982 | 1.000 | 0.991 | 0.999 | 0.991 |
| DoS-Slowloris | 14,688 | 0.997 | 0.939 [0.935, 0.943] | 0.967 | 0.967 | 0.971 |
| **Brute_Force_-Web** | 715 | 0.762 | 0.776 [0.744, 0.805] | **0.769** | 0.726 | 0.738 |
| **Brute_Force_-XSS** | 257 | 0.386 | 0.833 [0.782, 0.873] | **0.528** | 0.517 | 0.526 |
| **SQL_Injection** | 290 | 0.810 | 0.059 [0.037, 0.092] | **0.109** | 0.020 | 0.111 |
| **Macro-F1 lớp hiếm** | | | | **0.469** | 0.421 | 0.458 |
| Macro-F1 cả 8 lớp | | | | 0.795 | 0.778 | 0.792 |

- **Δ macro-F1 lớp hiếm so với A0**, bootstrap theo 9,458 source IP: A1 −0.048 [−0.162, +0.003]; A2 −0.010 [−0.025, +0.009]. Hướng có lợi cho SMOTE nhưng **chưa có ý nghĩa thống kê**.
- **SQLi:** 222/290 flow bị đoán thành XSS. Subset có 32 fingerprint mang cả hai nhãn XSS và SQLi, nên đây là giới hạn của input, không phải lỗi cân bằng.
- **Phát hiện (attack hay benign) của A0**, threshold khóa trên benign của C1:

| FPR mục tiêu | 0.05% | 0.1% | 0.5% | 1% |
|---|---|---|---|---|
| Recall Web / XSS / SQLi | 0.26 / 0.76 / 0.82 | 0.40 / 0.76 / 0.82 | **0.945 / 1.0 / 1.0** | 0.987 / 1.0 / 1.0 |
| FPR thực trên known_replay | 0.015% | 0.037% | 0.108% | 0.656% |
| FPR thực trên ngày Infiltration (28/02) | 0.066% | **0.598%** | 1.805% | 2.464% |
| FPR thực trên ngày Bot (02/03) | 0.068% | 0.081% | 0.140% | 0.752% |

- **Cái giá:** với A0 v1 (không có lớp web), FPR trên ngày Infiltration ở mục tiêu 0.1% chỉ là 0.029%. Thêm lớp web làm threshold calibration kém chuyển giao sang ngày 28/02.

## 3. Output (b): alert triage theo incident
**Luật chung cho mọi phương pháp:** flow bị alert → incident gom theo **source IP + cooldown 15 phút** (event time). Có hai chính sách xem xét với cùng budget **B incident/giờ**:
- **FIFO:** B incident mở đầu tiên mỗi giờ (causal);
- **priority:** hàng xem xét cuối mỗi giờ, lấy B incident có nhiều flow bị alert nhất.

| Scenario · FPR · phương pháp | Flow bị alert | Incident | Nén (flow/incident) | Episode phủ với B = 10/h: FIFO → **priority** | Precision của incident với B = 10/h (priority) |
|---|---|---|---|---|---|
| Holdout DDoS · 0.5% · A0 (v1 đã khóa) | 71,774 | 175 | **410** | 0/10 → **10/10** | 1.00 |
| Holdout DDoS · 1% · A0 | 77,062 | 317 | 243 | 0/10 → **10/10** | 1.00 |
| Bot · 1% · V4b (shadow) | 121,353 | 266 | 456 | 0/8 → **8/8** | 0.16 |
| Known within-episode · 0.1% · A0 | 164,781 | 161 | 1,024 | 0.148 → 0.137 (B = 30: 0.306) | 0.74 |

- **Đọc kết quả:** gom incident giảm tải analyst **2–3 bậc độ lớn**, và hàng ưu tiên biến một chế độ vận hành vô dụng (FIFO bỏ lỡ toàn bộ DDoS) thành phủ đủ 10/10 episode với 10 incident/giờ.
- **Giới hạn:**
  - (i) luật ưu tiên theo khối lượng được đặt ra **sau** khi thấy FIFO thất bại, kể cả trên holdout, nên số liệu holdout ở bảng này là **exploratory**;
  - (ii) ưu tiên theo khối lượng làm các episode web rất ít flow (562 attacker IP, mỗi IP vài flow) xuống cuối hàng; known chỉ phủ 31% ở B = 30;
  - (iii) incident tính theo source IP, nên một tấn công nhiều nguồn tạo ra nhiều incident.

**Giao diện triage** (`python -m netirava ui --run <run_id>`, Streamlit):
- hàng incident xếp theo ưu tiên; lọc theo segment, class dự đoán, lớp hiếm; chế độ top-B mỗi giờ;
- chi tiết incident gồm flow, đích, port, byte, score và lý do policy;
- ghi feedback append-only (true/false positive, uncertain), lưu vào `alerts.db`.

Giao diện không đọc nhãn thật. Ví dụ run dev v2: 166,636 flow bị alert gom thành 238 incident (khoảng 700 flow mỗi incident); 210 incident có class dự đoán là lớp hiếm; 217 incident được notify và 21 bị chặn bởi budget demo 30/giờ.

## 4. Tấn công thay đổi (bằng chứng phụ)
- **Dev Bot:** V4b (A0 + trung bình anomaly score theo host trong 60 s) bắt **8/8 episode ở FPR 1%** (recall 0.958); A0 và OR đều 0/8. Ở FPR ≤ 0.5%, không biến thể nào bắt được.
- **Holdout DDoS LOIC-HTTP**, chạy một lần với phương pháp đã khóa: V4b **bị bác bỏ**. Ở FPR 0.1% không có lợi ích; ở 0.5–1% V4b kém A0 (Δ −0.685 và −0.050, CI < 0). Chi tiết ở [`RESULTS_DECISION.md`](RESULTS_DECISION.md).

## 5. Chi phí
| Thành phần | Chi phí |
|---|---|
| A0 inference | 0.4–0.8 µs/flow |
| Shadow (IsolationForest) | 3.7–10.8 µs/flow |
| Replay dev v2 (1.67M flow) | 10.7 s wall |
| Peak RSS | khoảng 3.5 GB |
| Train A0 trên GPU | khoảng 20 s |
| Decision layer và triage | Offline, vài giây mỗi run |

## 6. Lệnh tái lập
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava prepare --config configs/demo.yaml
& $py -m netirava train-a0 --config configs/demo.yaml --variant a0   # also a1, a2
& $py -m netirava ablate-imbalance --config configs/demo.yaml
& $py -m netirava train-anomaly --config configs/demo.yaml
& $py -m netirava score-calibration --config configs/demo.yaml
& $py -m netirava replay --config configs/demo.yaml --mode a0-shadow
& $py -m netirava decide --run <run_id>
& $py -m netirava ui --run <run_id>
```
