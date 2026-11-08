# Ops study: kết quả (incident correlation + drift monitoring)

Protocol: [`OPS_STUDY_PREREG.md`](OPS_STUDY_PREREG.md) (commit `e1b473a`). Tài liệu này được lập thành hai bước: mục 1 (sai lệch so với pre-registration) được commit **trước** tag `ops-v1-frozen` và trước khi chạy holdout H5–H9; các mục sau được thêm sau khi chạy holdout đúng một lần.

## 1. Sai lệch so với pre-registration (ghi trước holdout)
| # | Thay đổi | Phát hiện trên | Lý do | Ảnh hưởng |
|---|---|---|---|---|
| S1 | **Đơn vị xem xét của campaign đổi thành "campaign update"**: mỗi giờ, các source incident mở trong giờ đó và thuộc cùng một campaign tạo thành một mục. Đơn vị pre-register ("open-once": mỗi campaign chỉ vào hàng một lần, lúc mở) vẫn được báo cáo với tên `campaign_open_once` | DEV K5, nhãn sửa, α = 0.1% | SQL injection thật (18.218.115.60 → .28, 20:16–20:27) gia nhập campaign 23 đã mở từ 17:00 trên cùng máy chủ web (80 nguồn, phần lớn benign). Với open-once, campaign này đã được xem lúc 18:00 nên SQLi không bao giờ được xem: loại tấn công bị phủ giảm từ 0.833 (source) xuống 0.667. Nếu analyst đã đóng campaign là FP, tấn công thật bị che | Campaign update phủ 0.833 (bằng source). Mỗi giờ, số campaign update ≤ số source incident mở trong giờ đó, nên đơn vị mới vẫn là phép gộp thuần. Test hồi quy: `test_new_source_joining_old_campaign_is_a_new_review_item` |
| S2 | Contamination đo thêm ở mức campaign update (`contamination_share_update_items`) | — | Với S1, analyst xem theo update nên đây là mức thực tế analyst thấy | **G3 vẫn dùng mức campaign** (đã pre-register, chặt hơn) |
| S3 | Với nhãn sửa, các row `attempted`/`indeterminate` được giữ trong hàng xem xét nhưng không tính là attack hay benign | Khi viết evaluator | Hàng xem xét không được phụ thuộc nhãn | Không đổi luật |
| S4 | Cửa sổ monitor căn từ quyết định đầu tiên của segment (pre-registration ghi "từ đầu segment") | Khi viết code | Tương đương trong replay (flow đầu tiên quyết định ngay sau khi segment bắt đầu) | Không |

Không có tham số nào (khóa campaign, cooldown, budget, α, ngưỡng PSI/TR, luật GO) bị đổi sau khi xem kết quả DEV.

**Kết quả DEV và EXP** (`runs/ops_study/{dev,exp_h2}/`, chi tiết ở mục 4.4) chỉ dùng để phát hiện lỗi; chúng không được dùng để chọn tham số.

---
*Các mục dưới đây được thêm **sau** khi chạy holdout H5–H9 đúng một lần (tag `ops-v1-frozen`, commit `9ab983c`).*

## 2. Kết luận trong một bảng
| RQ | Câu hỏi | Kết quả trên holdout mới (HO) | Quyết định theo luật khóa trước |
|---|---|---|---|
| RQ-C1 | Campaign có giúp analyst xem được nhiều tấn công hơn trong cùng budget? | **Có, với A0 v2:** HOIC (10 nguồn → 1 đích): episode phủ (strict) **0.80 → 1.00**, số mục 46 → 5/giờ. Pilot đã phủ 1.00 bằng source nên không có chỗ cải thiện | G1 đạt (A0 v2), không đạt (pilot) |
| RQ-C2 | Có làm mất loại tấn công hay làm chậm lần xem đầu? | Không mất loại nào (mọi B, mọi chính sách); trung vị độ trễ không đổi (Δ = 0 s) | G2, G4 đạt |
| RQ-C3 | Có gom nhầm benign vào chiến dịch tấn công? | **Có: 15/217 (6.9%) source incident chỉ-benign của A0 v2 và 10/143 (7.0%) của pilot** bị gom vào campaign có tấn công (nhãn sửa: 5.07% với A0 v2) | **G3 không đạt (> 5%) → NO-GO** |
| RQ-D1/D2 | Tín hiệu không nhãn có theo được FPR thực của threshold? | HO: không cửa sổ nào của A0 v2 có FPR > 2α (FPR thực 0.007–0.174%), pilot có 1. Gộp DEV + HO (46 cửa sổ): TR theo được FPR với pilot (**ρ = 0.56 [0.32, 0.73]**) nhưng không với A0 v2 (ρ = 0.32 [0.01, 0.58]). Chỉ 1–3 cửa sổ vượt ngưỡng | Recall báo động **INCONCLUSIVE**; luật "hữu ích" không đạt → **chỉ báo thay đổi phân phối, không phải ước lượng FPR** |
| RQ-D3 | α·TR có xấp xỉ FPR thực? | Không đủ tốt: chỉ 48% (A0 v2) và 20% (pilot) cửa sổ nằm trong khoảng 2 lần FPR thực | Không dùng làm ước lượng FPR |
| RQ-D4 | Monitor có báo khi có họ tấn công mới? | Có: báo động tập trung ở cửa sổ có tấn công (HOIC, Infiltration); **0 báo động** của AR, S_PSI, F_PSI trên cửa sổ chỉ-benign | Hiển thị như chỉ báo |
| RQ-M | Model nào giữ FPR và tải tốt hơn trên ngày mới? | Pilot: FPR 0.065% [0.060, 0.070] so với 0.085% [0.080, 0.092]; incident báo nhầm 15.9 so với 24.1/giờ; recall HOIC **0.81 so với 0.04** | **Chọn pilot `pilot_cns/s0` làm model cuối (D1)**; A0 v2 là baseline |

**Một câu cho slide:** gom theo chiến dịch giảm số mục phải mở khoảng 6 lần và giúp phủ đủ DDoS nhiều nguồn, nhưng gộp nhầm khoảng 7% incident benign vào chiến dịch tấn công, nên Netirava giữ source incident làm đơn vị mặc định và chỉ dùng campaign làm ngữ cảnh. Drift monitor chưa đủ bằng chứng để ước lượng FPR, nhưng không báo trên giờ chỉ có benign và có báo khi xuất hiện họ tấn công mới.

## 3. Thiết lập
- **Model:** A0 v2 (`f32899bde8b4`, threshold 0.8679) và pilot `pilot_cns/s0` (`f964bde1ef5c`, threshold 0.00924), cả hai khóa trên benign của C1 ở α = 0.1%. Không train lại.
- **Runs:**
  - DEV: `20261108T190136_a0_fast` (A0 v2; `active_decisions_sha1` = `1c7b4b31…`, trùng run trước khi tích hợp) và `20261108T190143_a0_fast` (pilot);
  - EXP H2: `20261108T132246_a0-shadow_fast`;
  - **HO:** `20261108T211051_a0_fast` (A0 v2) và `20261108T211057_a0_fast` (pilot) trên `configs/ops_holdout.yaml` (1,489,831 flow).
- **Kết quả máy đọc:** `runs/ops_study/{dev,exp_h2,holdout,pooled}/` (`CORRELATION.json`, `DRIFT.json`, `drift_windows.csv`, `GO.json`, `SUMMARY_*.md`).
- **Support của HO:** H5 HOIC 534,025 attack + 92,941 benign; H6 39,455 Infilteration + 252,503 benign; H7 177,986 benign; H8 180,753 benign; H9 3,140 Infilteration + 209,028 benign. Nhãn sửa CNS2022 chỉ có ở H9 (02-28); các cửa sổ khác dùng nhãn gốc.
- Số "mỗi giờ" chia cho số giờ đồng hồ mô phỏng có dữ liệu (H5 dài 30 phút được tính là 1 giờ).

## 4. RQ-C: incident correlation
### 4.1 Holdout, α = 0.1%, hàng severity, B = 10 mục/giờ, nhãn gốc
| Model | Scenario | Đơn vị | Mục/giờ | Mục báo nhầm/giờ | Episode phủ (strict) | Attack flow phủ (case) | Contamination |
|---|---|---|---|---|---|---|---|
| A0 v2 | **H5 HOIC** | source | 46.0 | 36.0 | 0.80 | 0.031 | |
| A0 v2 | **H5 HOIC** | **campaign** | **5.0** | **4.0** | **1.00** | 0.036 | 0.00 |
| A0 v2 | H6 Infiltration 03-01 | source | 22.0 | 9.0 | 0.033 | 0.193 | |
| A0 v2 | H6 Infiltration 03-01 | campaign | 4.0 | 2.5 | 0.116 | 0.194 | **0.61** |
| A0 v2 | H7 benign 02-16 | source → campaign | 5.5 → 3.0 | 5.5 → 3.0 | – | – | – |
| A0 v2 | H8 benign 02-20 | source → campaign | 39.0 → 5.0 | 39.0 → 5.0 | – | – | – |
| A0 v2 | H9 02-28 tối | source → campaign | 37.5 → 6.0 | 37.0 → 5.5 | 0.00 → 0.05 | 0.000 → 0.000 | 0.05 |
| pilot | **H5 HOIC** | source → campaign | 24.0 → 7.0 | 14.0 → 6.0 | 1.00 → 1.00 | 0.813 → 0.813 | **0.57** |
| pilot | H6 Infiltration 03-01 | source → campaign | 9.5 → 8.0 | 8.0 → 7.0 | 0.011 → 0.017 | 0.012 → 0.012 | 0.13 |

- **Gộp HO (9 giờ):** A0 v2 28.2 → 4.6 mục/giờ (báo nhầm 24.1 → 4.0); pilot 17.3 → 9.0 (15.9 → 8.7). Ở α = 0.5%: A0 v2 112.7 → 15.0; pilot 138.1 → 59.9.
- **Đọc đúng "mục báo nhầm/giờ giảm":** đây là **giảm số lần analyst phải mở một mục**, không phải giảm false positive. Số flow benign bị alert và FPR không đổi; nhiều nguồn benign tới cùng một đích chỉ được gộp thành một mục.
- Nhãn sửa cho cùng kết luận (khác biệt chỉ ở H9).

### 4.2 Luật GO (`runs/ops_study/holdout/GO.json`)
| Luật | A0 v2 (nhãn gốc / sửa) | Pilot (nhãn gốc / sửa) |
|---|---|---|
| G1 lợi ích ≥ +0.05 trên H5 | **đạt** (episode strict 0.80 → 1.00 ở α = 0.1%) | không đạt (1.00 → 1.00) |
| G2 không mất loại tấn công | đạt (0 loại) | đạt |
| G3 contamination ≤ 5% | **không đạt** (6.9% / 5.07%) | **không đạt** (7.0% / 7.0%) |
| G4 độ trễ ≤ +15 phút | đạt (Δ trung vị 0 s) | đạt |
| **Kết luận** | **NO-GO** | **NO-GO** |

### 4.3 Cơ chế của contamination (vì sao NO-GO là đúng)
- **A0 v2, H6 và H9:** nguồn Internet mang nhãn `Infilteration` (lớp nhãn đã bị flag chất lượng; ví dụ 77.72.82.96, 222.186.50.156) và nguồn benign cùng nhắm 172.31.69.15 / .7 với họ dự đoán Web, nên chung khóa (đích, họ). Một phần contamination có thể đến từ nhãn sai của chính NF-v3, nhưng luật không cho loại trừ sau khi xem kết quả.
- **Pilot, H5:** HOIC bị chấm argmax Benign (vượt threshold nhưng không giống lớp đã biết nào), nên họ là `Unknown`. 8 nguồn benign cũng có alert `Unknown` tới 172.31.69.28 bị gộp vào campaign DDoS 434,279 flow: analyst xem campaign này sẽ thấy 8 host vô hại như thành viên của DDoS.
- Khóa chỉ theo đích (ablation) gộp mạnh hơn nữa (A0 v2: 3.8 mục/giờ), không giải quyết vấn đề.

### 4.4 DEV và EXP (chỉ để phát hiện lỗi, không dùng để chọn)
| Run | Quan sát |
|---|---|
| DEV K1–K5, nhãn gốc, A0 v2 | Episode phủ (strict) 0.132 → **0.303**: 386 "episode web" từ hàng trăm IP được gom về vài campaign trên máy chủ web. Nhưng **93% nhãn web của NF-v3 không credible** (`FP_LABEL_FORENSICS.md`), nên phần lớn lợi ích này nằm trên nhãn sai |
| DEV K1–K5, nhãn sửa, A0 v2 | Chỉ còn 6 episode thật. Source 0.833, campaign update **0.833**, open-once (pre-register) **0.667**: dẫn tới sai lệch S1 (mục 1) |
| DEV S1, A0 v2 | Contamination **0.805** (nhãn gốc), 0.31 (nhãn sửa): scan .24 → .15 bị NF-v3 gắn Benign. Đây là cảnh báo sớm cho G3 |
| EXP H2 DoS-Hulk | Source 4.5 → campaign 1.5 mục/giờ, cùng phủ 1/1 episode, contamination 0 |

## 5. RQ-D: drift monitoring
### 5.1 Tín hiệu ở α = 0.1% (nhãn sửa)
| Pool | Model | Cửa sổ | Cửa sổ E (FPR > 2α) | ρ(TR, FPR) [CI 95%] | ρ(AR, FPR) [CI 95%] | Tỷ lệ báo của TR trên cửa sổ không-E: chỉ-benign / có tấn công | Của AR |
|---|---|---|---|---|---|---|---|
| HO | A0 v2 | 18 | 0 | 0.33 [−0.25, 0.73] | 0.61 [0.09, 0.93] | 0.17 / 1.00 | 0.00 / 1.00 |
| HO | pilot | 18 | 1 | 0.06 [−0.45, 0.57] | 0.54 [0.01, 0.93] | 0.00 / 0.80 | 0.00 / 0.60 |
| DEV + HO | A0 v2 | 46 | 2 | 0.32 [0.01, 0.58] | 0.24 [−0.13, 0.63] | 0.13 / 0.32 | 0.00 / 0.54 |
| DEV + HO | **pilot** | 46 | 1 | **0.56 [0.32, 0.73]** | 0.50 [0.18, 0.78] | 0.00 / 0.21 | 0.00 / 0.38 |

- **Data drift (trung vị feature PSI) và prediction drift (score PSI)** không theo được FPR (ρ từ −0.19 đến 0.04 trên DEV + HO), nhưng không báo trên cửa sổ chỉ-benign nào.
- **AR (tỷ lệ alert)** bắt mọi cửa sổ E trên DEV (3/3, nhãn gốc), nhưng cũng báo trên phần lớn cửa sổ có tấn công: AR đo khối lượng alert, không phân biệt attack với FP.
- **TR** là tín hiệu duy nhất đạt tiêu chí tương quan (với pilot), nhưng cũng báo trên cửa sổ có tấn công, vì dải ngay dưới threshold chứa cả attack có score trung bình.
- **α·TR không phải ước lượng FPR dùng được:** sai số trung vị 0.30 (A0 v2) và 0.58 (pilot) bậc log10.

### 5.2 Vì sao kết luận là INCONCLUSIVE chứ không phải "không hoạt động"
Trên 5 cửa sổ mới, cả hai model **giữ FPR gần mục tiêu** (A0 v2: 0.043–0.127%, pilot: 0.026–0.113%), nên gần như không có sự kiện suy giảm threshold để kiểm chứng monitor. Đây là tin tốt cho detector (mục 6) và là giới hạn của bằng chứng cho monitor. Cả DEV + HO chỉ có 1–3 cửa sổ E, ít hơn ngưỡng 5 đã khai báo.

### 5.3 Monitor được đưa vào sản phẩm thế nào
Tab "Threshold reliability" trên UI, chỉ để hiển thị: trạng thái theo cửa sổ 15 phút, AR, TR, PSI và các feature thay đổi nhiều nhất. UI ghi rõ đây là **chỉ báo thay đổi phân phối, không phải ước lượng FPR**, và không bao giờ đổi alert (`configs/demo.yaml → ops.ui_monitor_note`).

## 6. RQ-M: model nào trên các ngày chưa từng chạm
| α = 0.1% (khóa trên C1) | A0 v2 | Pilot `pilot_cns/s0` |
|---|---|---|
| FPR benign gộp H5–H9 (n = 913,211) | 0.085% [0.080, 0.092] | **0.065% [0.060, 0.070]** |
| FPR theo cửa sổ: H7 / H8 / H5 / H6 / H9 | 0.043 / 0.084 / 0.127 / 0.086 / 0.103% | 0.026 / 0.032 / 0.098 / 0.063 / 0.113% |
| Source incident báo nhầm/giờ | 24.1 | **15.9** |
| Recall flow HOIC (H5) | 0.036 | **0.813** |
| Recall flow Infilteration (H6, lớp nhãn bị flag) | **0.194** | 0.012 |

**Luật RQ-M đạt** (FPR không cao hơn, incident ≤ 1.5 lần, HOIC ≥ A0 v2 − 0.05) → **pilot là model cuối** (`final_system.model_dir`, mặc định của `replay`). A0 v2 giữ làm baseline.

**Cái giá phải ghi rõ:**
- pilot gần như không bắt Infilteration trên H6 (0.012 so với 0.194); nhãn Infilteration có chất lượng thấp (bị flag) và Netirava không claim lớp này;
- ở α = 0.5%, pilot có FPR cao hơn trên ngày benign (0.51–0.59% so với 0.23–0.44% của A0 v2);
- K5 vẫn không sạch cho pilot (pilot train trên phần đầu các cửa sổ web CNS2022), nên bằng chứng lớp hiếm của pilot vẫn là within-episode (L-1.4, L-7.4).

**Kết quả vững:** ở α = 0.1%, FPR thực trên 5 cửa sổ chưa từng chạm luôn ≤ 0.127%, tức không quá 1.3 lần mục tiêu, với cả hai model.

## 7. Giới hạn của study
1. **Chỉ một holdout nhiều nguồn** (H5 HOIC, 10 attacker, một đích): G1 dựa vào một chiến dịch.
2. **Quá ít cửa sổ E** để đánh giá recall của monitor (1–3); kết luận về TR dựa vào tương quan trên 46 cửa sổ.
3. **Nhãn:** Infilteration của NF-v3 bị flag; CNS2022 chỉ sửa 3 ngày. Contamination ở H6/H9 có thể một phần do nhãn.
4. **Budget giả định** (10 và 30 mục/giờ), cửa sổ monitor 15 phút và ngưỡng PSI 0.25 là quy ước, không tune.
5. **Case-attached coverage** giả định analyst thấy các flow đến sau trong một case đang mở; strict coverage là cận dưới.
6. Replay flow đã hoàn tất trong một testbed, export delay = 0.

## 8. Tái lập
Xem `README.md` (mục "Ops study"). Thứ tự:
1. `drift-reference` cho hai model;
2. `replay` DEV, rồi `ops-study --tag dev`;
3. `prepare` và `relabel --config configs/ops_holdout.yaml`;
4. `replay --unlock-holdout` cho hai model (một lần);
5. `ops-study --tag holdout`, `ops-go`, `ops-pool --tags dev holdout --out pooled`, `ops-summary`.
