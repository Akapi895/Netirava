# Netirava MVP — Kết quả run đầu tiên (2026-11-08)

**Phạm vi:** replay các flow đã hoàn tất (NetFlow v3) trên subset CIC18-Causal-Demo-v1 (`docs/DATASET_CARD.md`). Gồm A0 ở chế độ active và một anomaly detector ở chế độ shadow; mọi phản ứng chỉ là mô phỏng. Đây là **development evidence** trên dữ liệu dự án đã từng dùng. Không phải external validation, không phải zero-day detection đã được chứng minh, không phải IPS.

**Các run dùng cho báo cáo** (`runs/`, ngoài git):

| Run | Mô tả |
|---|---|
| `20261108T110255_a0_fast` | Chỉ A0 |
| `20261108T110215_a0-shadow_fast` | A0 + shadow, trên cùng luồng 1,890,707 event |
| `20261108T110325_a0-shadow_paced` | Demo paced: 30k event đầu của R1, speed 60 |

Hash quyết định active giống nhau ở mọi run fast (`cee3147f…`), kể cả run trước khi tối ưu cách load.

**Model:**
- **A0-CIC** `be8f6d84bf2d`: threshold 0.003938 trên `attack_score`.
- **IsolationForest** `2840a4698e7c`: threshold 0.6489.

Cả hai threshold được chọn trên 278,255 flow benign của calibration với mục tiêu FPR 0.1%. FPR thực đạt trên calibration là 0.0995% và 0.0974%.

## 1. Kết quả theo scenario (không gộp)
Binary: một flow là candidate khi `attack_score ≥ threshold`. CI là Wilson 95% theo row, giả định các row độc lập.

| Scenario | Flow (attack) | A0 attack recall | A0 benign FPR [CI] | Alert precision (flow) | Proxy episode phát hiện / tổng | Shadow attack recall | Shadow benign FPR |
|---|---|---|---|---|---|---|---|
| **known-within-episode** | 511,147 (164,830) | **0.9985** | 0.025% [0.021, 0.031] | 0.9995 | 4/4, TTFA trung vị 0.8 s | **0** | 0.072% |
| **unknown-bot** (held-out class) | 975,404 (117,324) | **0.000** | 0.018% [0.015, 0.021] | 0.000 | **0/8** | **0** | 0.154% |
| unknown-web (support nhỏ) | 223,073 (363) | 0.0055 | 0.007% | 0.118 | 2/97 | 0 | 0.094% |
| stress-infiltration (nhãn gắn cờ) | 181,083 (20,667) | 0.0016 | 0.029% | 0.420 | 3/118 | 0 | 0.047% |

- **Known class (argmax, within-episode):** macro-F1 0.993. F1 theo class: FTP 1.000, SSH 1.000, GoldenEye 1.000, Slowloris 0.967 (recall 0.939; 900 flow bị đoán Benign), Benign 0.999. Phần đuôi FTP trùng fingerprint 100% với train, và mỗi known class chỉ có một attacker IP, nên con số này rất lạc quan và **không** nói lên khả năng tổng quát hóa.
- **Bot:** A0 dự đoán Benign cho cả 117,324 flow. Benign FPR trên các host same-host là 0 (n = 3,349), trên các host đối chứng là 0.018%.
- **Chẩn đoán xếp hạng, không dùng threshold** (chỉ để đọc, không chỉnh gì):

| | AUROC Bot so với benign trong R1 | Web (Web / SQLi / XSS) | Infilteration |
|---|---|---|---|
| A0 `attack_score` | 0.718 | 0.91 / 0.97 / 0.97 | 0.457 |
| IsolationForest score | 0.923 | 0.76 / 0.99 / 0.98 | 0.434 |

  Shadow xếp hạng Bot cao hơn benign, nhưng ở điểm vận hành FPR 0.1% theo từng flow thì không bắt được flow Bot nào. Với Infilteration, cả hai detector đều không tách được (AUROC < 0.5); nhãn của class này đã được gắn cờ.

## 2. Shadow so với active
- **Event bị A0 bỏ sót mà shadow báo:** 0 flow và 0 episode ở mọi scenario.
- **Alert benign mà chỉ shadow tạo:** known 251, Bot 1,320, web 209, infiltration 76.
- **Overlap Jaccard** giữa alert của hai nhánh: 0.
- **Kết luận:** ở cấu hình này, shadow **không bổ sung tín hiệu có ích** mà chỉ thêm báo động sai. Shadow giữ nguyên chế độ shadow và **không được promote**.
- **Trạng thái:** run fast có 1,890,707/1,890,707 event được chấm, 0 missing, 0 late, `degraded = false`. Run paced có 294/30,000 event bị đánh dấu late (vượt deadline 1 ms/event); không event nào bị bỏ.

## 3. Vận hành
| | A0 | A0 + shadow |
|---|---|---|
| Wall time cho 1,890,707 event (khoảng 386 giờ event time, gồm các gap giữa cửa sổ) | 1.1 s | 8.5–22.9 s (giữa các lần chạy) |
| Compute | A0 0.4–0.8 µs/event (CatBoost predict trên CPU) | shadow 3.7–10.8 µs/event |
| Throughput | khoảng 1.7M event/s wall | 83k–224k event/s wall |
| Peak RSS (cả process, gồm stream và detections) | 3.55 GB | 3.68 GB |
| Batching delay theo event time | p50 khoảng 0.5 s, p95 khoảng 0.95 s (tick 1 s; export delay giả định 0) | như nhau |
| Paced (speed 60, 578 s mô phỏng) | — | wall 10.5 s; độ trễ so với lịch p95 1.08 s, max 1.15 s |

**Policy active** (`a0-policy-v1`: entity là source IP, cooldown 15 phút theo event time, budget 30 notification mỗi giờ mô phỏng; budget là giả định, chọn trước khi replay):

| Scenario | Candidate / giờ | Incident = notification | Notification / giờ | Bị gộp do cooldown | Bị chặn bởi budget |
|---|---|---|---|---|---|
| known | 27,446 | 49 | 8.2 | 164,625 | 0 |
| Bot | 31 | 70 (đều là benign) | 14.0 | 85 | 0 |
| web | 8.5 | 16 | 8.0 | 1 | 0 |
| infiltration | 81 | 17 | 17.0 | 64 | 0 |

Với Bot, cả 70 notification trong 5 giờ đều là báo động sai trên benign: precision ở mức alert bằng 0. Shadow thêm 53 shadow-incident mỗi giờ, không chiếm budget.

## 4. Đã làm và chưa làm
- **Đã làm:**
  - repo, môi trường, config và CLI;
  - `inspect` (sha1 khớp bagit) và `prepare` (2.97M flow, manifest, truth riêng);
  - audit;
  - A0-CIC và model card; anomaly model;
  - replay fast và paced; shadow; evaluate; feedback (append-only, có correction);
  - 14 test (`docs/TEST_REPORT.txt`).
- **Chưa làm:**
  - không có feature ngữ cảnh hay rolling statistics;
  - không đo export delay thật;
  - không có known-class trên independent episode (dữ liệu không có);
  - không có stateful resume (mỗi lần chạy là một run mới);
  - không có UI;
  - không có SHAP;
  - không retrain từ feedback.
- **Feedback trong run `20261108T110255_a0_fast`:** id 1–2 do agent nhập để thử lệnh (ghi `source = analyst`, trước khi có cờ provenance); id 3 có `provenance = demo`. Không có review nào của analyst thật.

## 5. Một bước tiếp theo
**Thử gom anomaly score theo entity và cửa sổ thời gian một cách causal, vẫn ở chế độ shadow.**
- **Ý tưởng:** tính thống kê rolling theo source IP chỉ từ các event đã có, đặt threshold trên các entity benign của calibration, và so với A0 dưới cùng alert budget.
- **Căn cứ:** shadow xếp hạng Bot khá (AUROC 0.92) nhưng threshold theo từng flow ở FPR 0.1% cho recall 0.
- **Lưu ý:** Bot đã được xem ở bước chẩn đoán này. Vì vậy mọi claim về bước tiếp theo cần một scenario held-out khác, hoặc khai báo rõ rằng Bot là development scenario.
