# 10. Ledger bằng chứng của hệ thống cuối

Mọi headline của bài nộp lấy từ tài liệu này. Số máy đọc nằm ở `runs/final_evidence/` (`LEDGER.json`, `LEDGER_flows.md`, `LEDGER_classes.md`), sinh bởi `python -m netirava ledger` (`src/netirava/ledger.py`). Ledger chỉ đọc run đã lưu; không model nào chạy lại.

## 1. Hệ thống cuối (chốt 2026-11-09)
| Thành phần | Giá trị |
|---|---|
| Model | `pilot_cns/s0`, hash `f964bde1ef5c`: CatBoost 8 known class, SMOTENC theo luật A0, train trên nhãn CNS2022-adapted (bản trùng **chưa** loại) |
| Operating point | α = 0.1%, threshold 0.009242 khóa trên 278,255 flow benign của C1 |
| Hàng xem xét | Source incident (source IP + cooldown 15 phút), severity family-aware, B = 10 mục/giờ; campaign chỉ là view thử nghiệm |
| Run DEV | `20261108T190143_a0_fast` (`configs/demo.yaml`, K1–K5, S1, R1) |
| Run holdout | `20261108T211057_a0_fast` (`configs/ops_holdout.yaml`, H5–H9) |
| Baseline | A0 v2 `f32899bde8b4` (nhãn gốc), threshold 0.867873, run `20261108T190136_a0_fast` và `20261108T211051_a0_fast` |
| Luật chọn | RQ-M khai báo trước ([`protocols/ops_study_prereg.md`](protocols/ops_study_prereg.md) §5): FPR không cao hơn, false source incident ≤ 1.5 lần, recall HOIC ≥ A0 v2 − 0.05. Luật này **không** có điều kiện bảo toàn lớp thiểu số, portscan hay Infiltration |

Lợi ích của pilot là của **cả gói can thiệp**: nhãn sửa, split web của pilot và fit lại. Ledger không cô lập riêng tác dụng của việc sửa nhãn. Ablation imbalance sạch ở [`11_ablation_and_cohorts.md`](11_ablation_and_cohorts.md) cho thấy SMOTENC không phải nguồn của lợi ích này.

## 2. Bảng bằng chứng (α = 0.1%)
**Quy ước:**
- **Nhãn:** CNS2022-adapted nếu ngày đó được audit (22/02, 28/02, 02/03), nhãn gốc NF-v3 ở các ngày khác. Row `attempted`/`indeterminate` không tính là attack hay benign.
- **Raw:** stream như đã replay. **Dedup:** sau khi bỏ bản trùng toàn phần, incident được gom lại theo cùng luật.
- **Exposure:** tổng độ dài các cửa sổ khai báo (theo `FLOW_START`). Flow kết thúc sau cửa sổ vẫn được tính, nên số "/giờ" chỉ là xấp xỉ; ledger báo số đếm là chính.

| Cohort | Loại | Model | Benign n (dedup) | FP | Benign FPR raw → dedup [Wilson, dedup] | Attack support (dedup) và recall | False source incident (tổng incident) | Exposure |
|---|---|---|---|---|---|---|---|---|
| H5–H9 gộp | HO, sau khi dùng để chọn | **pilot** | 906,279 | 591 → 584 | 0.065% → **0.064%** [0.059, 0.070] | HOIC 534,025: **0.813**; Infilteration 23,450: **0.012** | **143** (156) | 4.5 h |
| | | A0 v2 | 906,279 | 779 → 701 | 0.085% → 0.077% [0.072, 0.083] | HOIC 0.036; Infilteration 0.195 | 217 (254) | 4.5 h |
| H5 HOIC 21/02 | HO | pilot / A0 v2 | 92,745 | 91 / 118 | 0.098% / 0.127% | HOIC 0.813 / 0.036 | 14 / 36 | 0.5 h |
| H6 01/03 | HO | pilot / A0 v2 | 248,156 | 153 / 140 | 0.062% / 0.056% | Infilteration 0.012 / 0.195 (nhãn gắn cờ, ngày chưa audit) | 16 / 18 | 1 h |
| H7, H8 benign | HO | pilot / A0 v2 | 175,955; 180,583 | 46, 58 / 76, 152 | 0.026%, 0.032% / 0.043%, 0.084% | — | 14, 43 / 11, 78 | 1 + 1 h |
| H9 28/02 19:00 | HO | pilot / A0 v2 | 208,840 | 236 / 215 | 0.113% / 0.103% | 2,067 Infilteration thành indeterminate, bị loại | 56 / 74 | 1 h |
| S1 28/02 | DEV (đã xem nhiều lần) | pilot / A0 v2 | 144,760 | 138 / 155 | 0.095% / 0.107% | Portscan 15,746: 0.006 / 0.063 | 16 / 42 | 0.67 h |
| R1 02/03 | DEV | pilot / A0 v2 | 854,221 | 99 / 433 | 0.012% / 0.051% (raw A0 v2: 0.081%) | Bot 62,793: **0 / 0** | 57 / 28 | 4 h |
| K1–K4 known tails | DEV, within-episode | pilot / A0 v2 | 342,285 | 93 / 126 | 0.027% / 0.037% | FTP, SSH, GoldenEye 1.000; Slowloris 0.965 / 0.939 | 50 / 30 | 1.92 h |
| K5 web, chỉ row eval của pilot | DEV, within-episode | pilot / A0 v2 | 658 | 0 / 263 | 0% / 40.0% | XSS 15: 1.000 / 0.000; SQLi 2: 1.000 / 1.000 | 0 / 6 | 5 h |

**Lớp thiểu số theo lớp** (argmax, dedup):

| Cohort | Lớp | Support | Pilot: P / R [Wilson] / F1 | A0 v2: P / R / F1 |
|---|---|---|---|---|
| K5, row eval của pilot | Brute_Force_-XSS | 15 | 1.000 / 1.000 [0.796, 1.000] / 1.000 | 0.000 / 0.000 / 0.000 |
| | SQL_Injection | 2 | 1.000 / 1.000 [0.342, 1.000] / 1.000 | 0.286 / 1.000 / 0.444 |
| Eval web của pilot trong T5 (không được replay) | Brute_Force_-Web | 27 | 26/27 đúng lớp (`runs/pilot_cns_results.json`) | — |

Cả ba lớp có support < 30 và cùng episode với train: **INCONCLUSIVE**. Trước khi loại trùng, XSS có 30 row eval; 15 trong số đó là bản sao y hệt.

## 3. Đánh đổi khi chuyển từ A0 v2 sang pilot
| Chỉ tiêu (α = 0.1%) | A0 v2 → pilot | Đánh giá |
|---|---|---|
| FPR trên 906,279 benign (H5–H9, dedup) | 0.077% → 0.064% | Giảm khoảng 17% (raw: 0.085% → 0.065%, khoảng 24%) |
| False source incident (H5–H9) | 217 → 143 | Giảm 34%; không đổi khi loại trùng |
| Recall HOIC | 3.6% → 81.3% | Cải thiện lớn nhất; một kịch bản, 10 attacker, chỉ là binary detection |
| Recall Infilteration (H6) | 19.5% → 1.2% | Đánh đổi lớn; nhãn lớp này bị gắn cờ và ngày 01/03 chưa audit |
| Recall Portscan (S1, nhãn sửa) | 6.3% → 0.6% | Đánh đổi |
| Recall Bot (R1) | 0 → 0 | Chưa giải quyết |
| FPR ở α = 0.5%, H7 / H8 | 0.231 / 0.386% → 0.510 / 0.575% | Pilot kém hơn ở ngân sách FPR cao hơn |
| False source incident trên R1 / known | 28 / 30 → 57 / 50 | Pilot kém hơn trên DEV |
| Lớp thiểu số (nhãn sửa) | XSS 0 → 15/15; SQLi 2/2 → 2/2 | INCONCLUSIVE |

Đây là bằng chứng cải thiện trên replay cùng testbed. Nó chưa chứng minh tiết kiệm thời gian analyst hay hiệu quả triển khai thực tế.

## 4. Split thật sự
Các cửa sổ không xếp thành chuỗi toàn cục train → calibration → tương lai. Đây là **đánh giá theo cửa sổ hồi cứu** (retrospective window evaluation):

| Ngày | Cửa sổ | Vai trò |
|---|---|---|
| 14/02 | T1, K1, T2, K2 | Train (phần đầu) và eval known (phần đuôi) cùng ngày |
| 15/02 | T3, K3, T4, K4 | Như trên |
| 16/02 | H2; H7 (19:00) | Holdout |
| 20/02 | C1 (12:00–14:05); H1; H8 (19:00) | Calibration, rồi holdout cùng ngày |
| 21/02 | H4 (14:00); H5 (18:05) | Holdout |
| 22/02 | T5 (12:00–17:00), K5 (17:00–22:00) | Train web **sau** calibration; eval web cùng episode |
| 23/02 | H3 | Holdout |
| 28/02 | S1 (15:00); H9 (19:00) | Stress DEV; holdout cùng ngày |
| 01/03 | H6 | Holdout |
| 02/03 | R1 | Replay DEV |

- Một số holdout (H2, H7, H8, H1) sớm hơn dữ liệu train web.
- Pilot train trên 60% đầu của mỗi cửa sổ web CNS2022, nằm bên trong T5 và K5. Replay toàn bộ K5 vì vậy chứa row train của pilot; ledger chỉ tính row eval.
- Purge và luật "flow kết thúc trước điểm cắt" chỉ có ở inner split T1–T4 của feature study. Số flow bắc qua ranh giới cửa sổ chưa được đếm.

## 5. Ma trận dedup theo phiên bản
| Thí nghiệm hoặc artifact | Bản trùng toàn phần |
|---|---|
| A0 v1, A0 v2, pilot (train và eval gốc) | Giữ nguyên |
| Feature study (EDA, các arm, H3/H4) | Đã loại |
| Ops study (replay H5–H9, metric correlation và drift) | Giữ nguyên (theo protocol) |
| Ablation imbalance sạch (`11`) | Đã loại |
| Ledger này | Báo cả raw và dedup |

## 6. Sửa đo lường và hiển thị (2026-11-09, commit `e5168f8`)
Đây là sửa cách đo trên output đã lưu, không đổi model hay threshold, không mở lại việc chọn phương pháp. Các quyết định GO của ops study và luật chọn model **không đổi** sau khi tính lại (`runs/ops_study/holdout/GO.json`; bản trước khi sửa: `GO_before_exposure_fix.json`).

| Vấn đề | Sửa |
|---|---|
| Số "/giờ" chia cho số ô giờ có event (H5–H9 là 9 ô cho 4.5 giờ), nên số cũ như 24.1 → 15.9 incident/giờ bị thấp đi | Mẫu số là exposure khai báo; báo số đếm là chính (217 → 143). Bảng "/giờ" trong `decision.py` và `pilot.py` (số lịch sử) vẫn theo ô giờ |
| ρ(TR, FPR) = 0.56 là số gộp DEV + holdout | Số chính là của holdout riêng: ρ = 0.06 [−0.45, 0.57] cho pilot ([`07`](07_drift_monitoring.md)) |
| Nhãn incident lấy mode của family và fine label độc lập, có thể ghép cặp không tồn tại | Mode của cặp (family, fine label). Trên 4 run nghiên cứu: 0/789 incident bị ảnh hưởng |
| UI xếp hạng theo bằng chứng tại lúc review nhưng hiển thị số trọn đời; chỉ lấy 200 flow đầu mà không nói | Hiện `review_utc`, `n_at_review`, `severity_at_review`; bật/tắt "bằng chứng tại lúc review"; ghi "N đầu trên M flow"; thống kê bên phải tính trên mọi flow được chọn |
| UI có thể mở run bằng sai config (join đích từ derived khác) | Chặn khi sha1 stream của run khác sha1 stream của config đang mở |
| `replay.run()` mặc định A0 v2, CLI mặc định pilot | Cả hai theo `final_system.model_dir` |
| Feedback "correction" có thể trỏ sang alert khác; chưa có verdict mới nhất | Chặn correction khác alert; UI có cột `verdict` mới nhất |
| Portscan thiếu trong taxonomy và trọng số rủi ro | Khai báo tường minh với đúng giá trị mặc định đã dùng (3) |

## 7. Được và không được claim
| Được claim (kèm điều kiện) | Không được claim |
|---|---|
| Ở α = 0.1%, FPR trên 5 cửa sổ chưa từng chạm (trước khi chọn) ≤ 0.113% với pilot; giảm FP và false incident so với A0 v2 | Model vững trên lớp thiểu số |
| Pilot phát hiện 81% flow HOIC, A0 v2 4% | Phát hiện zero-day; gọi đúng tên HOIC |
| Nhãn web NF-v3 phần lớn sai (6.9% credible) | Tiết kiệm thời gian analyst (thử nghiệm ở [`12`](12_triage_trial.md) chỉ là formative, reviewer là LLM) |
| Gom incident nén flow thành incident 2–3 bậc độ lớn | Thích nghi (adaptation): feedback chỉ là nhật ký, monitor không đổi threshold |
| Family-aware giảm nhãn mịn sai 344 → 52 trên A0 v2 | Family-aware có lợi tăng thêm trên pilot (pilot không có lỗi nhãn mịn trên eval web) |
