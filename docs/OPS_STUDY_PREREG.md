# Ops study: incident correlation và drift monitoring (pre-registration, 2026-11-08)

Tài liệu này được commit **trước** khi viết code của hai thành phần và trước khi tính bất kỳ số nào của chúng trên dữ liệu. Các holdout mới H5–H9 được chọn **chỉ từ support nhãn theo giờ/5 phút** (`runs/inspect/hourly_class_counts.csv` và đếm theo 5 phút của 02-21), chưa có score nào của model Netirava trên các cửa sổ này.

Nguồn ý tưởng: `improvement-plan.md` (ngoài repo), tham khảo NoDoze (NDSS 2019) cho contextual alert triage; CADE (USENIX Sec 2021), Thirumuruganathan et al. (USENIX Sec 2024) và Rabanser et al. "Failing Loudly" (NeurIPS 2019, black-box shift detection trên output của model) cho drift monitoring. Không sao chép phương pháp nào: NetFlow không có provenance graph như NoDoze, và Netirava không train representation mới như CADE.

## 0. Hai thành phần làm gì, không làm gì
| | Incident correlation (C) | Drift monitoring (D) |
|---|---|---|
| Vị trí | Sau detector, trước hàng xem xét (thành phần 3, triage) | Nhánh giám sát song song |
| Thay đổi alert binary? | **Không** | **Không** |
| Thay đổi model / threshold? | Không | Không (chỉ cảnh báo, không tự calibrate lại) |
| Tác dụng kỳ vọng | Analyst xem được nhiều tấn công hơn trong cùng budget | Biết khi nào threshold đã khóa không còn đáng tin, **trước khi có nhãn** |
| Không được claim | Giảm FPR; phát hiện thêm attack flow | Giảm FPR; phát hiện zero-day |

## 1. Research questions
**Incident correlation**
- **RQ-C1 (lợi ích).** Với cùng alert, cùng chính sách xem xét và cùng budget B mục/giờ, đơn vị **campaign** (source incident nối với nhau theo host đích + họ tấn công dự đoán, causal) có tăng độ bao phủ tấn công (episode, attack flow, risk-weighted) so với đơn vị **source incident** (source IP + cooldown 15 phút) không?
- **RQ-C2 (không gây hại).** Campaign có làm mất loại tấn công ít flow (loại được phủ khi dùng source incident nhưng không được phủ khi dùng campaign) hoặc làm chậm lần xem xét đầu tiên không?
- **RQ-C3 (chất lượng gom, không ngụy trang FP).** Bao nhiêu source incident benign bị gom vào campaign có tấn công, bao nhiêu campaign trộn nhiều loại tấn công, và còn bao nhiêu mục báo nhầm mỗi giờ?

**Drift monitoring**
- **RQ-D1.** Tín hiệu không cần nhãn nào (feature PSI, score PSI, tỷ lệ alert, tỷ lệ "đuôi dưới ngưỡng") theo được **FPR thực tế** của threshold đã khóa qua các cửa sổ thời gian?
- **RQ-D2.** Với luật báo động khai báo trước, monitor bắt được bao nhiêu cửa sổ có FPR vượt mục tiêu, và **tỷ lệ báo động giả của chính monitor** là bao nhiêu (tách cửa sổ chỉ có benign và cửa sổ có tấn công)?
- **RQ-D3.** Ước lượng không nhãn α·TR có xấp xỉ FPR thực tế (sai số log10) không?
- **RQ-D4 (sanity).** Monitor có báo khi có họ tấn công mới (HOIC, Infiltration)? Báo riêng là "distribution drift", không tính vào claim về FPR.

**Bằng chứng phụ cho D1 (chọn model cuối)**
- **RQ-M.** Trên các ngày/giờ chưa từng chạm (H5–H9), A0 v2 (nhãn gốc) và pilot `pilot_cns/s0` (nhãn sửa) giữ FPR ở α = 0.1% thế nào, sinh bao nhiêu incident báo nhầm/giờ, và phát hiện HOIC/Infiltration ra sao? Đây là đánh giá độc lập đầu tiên của pilot (L-7.4).

## 2. Dữ liệu và vai trò
| Tập | Cửa sổ | Vai trò trong study |
|---|---|---|
| Dev (đã dùng nhiều lần) | K1–K5, S1, R1 (`configs/demo.yaml`) | Phát triển, sửa lỗi. Kết quả = **DEV** |
| Holdout đã dùng | H2 (run `20261108T132246`, A0 v2) | **EXP** (exploratory), không dùng để chọn tham số |
| **Holdout mới** (`configs/ops_holdout.yaml`, derived riêng `artifacts/ops_holdout_v1`) | **H5** 02-21 18:05–18:35 DDoS-HOIC (10 nguồn → 1 đích, bắt đầu 18:11) · **H6** 03-01 14:00–15:00 (ngày mới, giờ có support Infilteration lớn nhất) · **H7** 02-16 19:00–20:00 (chỉ benign) · **H8** 02-20 19:00–20:00 (chỉ benign) · **H9** 02-28 19:00–20:00 (cùng ngày S1, 3 giờ sau) | **HO**: chạy **một lần** sau tag `ops-v1-frozen`, cho cả hai model |

Tiêu chí chọn holdout mới (khách quan, không xem score): (i) chưa thuộc cửa sổ nào của demo/fe_study; (ii) H5 là họ tấn công chưa thấy có nhiều nguồn (kiểm tra RQ-C); (iii) H6 là ngày chưa chạm; (iv) H7/H8 là giờ 19:00 chỉ có benign của hai ngày có holdout cũ nhưng giờ đó chưa chạm (kiểm tra false campaign và drift trên benign); (v) H9 kiểm tra nguồn FP của S1 có kéo dài trong ngày không. Nhãn sửa CNS2022 chỉ có cho 02-22, 02-28, 03-02; các cửa sổ khác dùng nhãn gốc (ghi rõ). Exact duplicate không bị loại (giữ semantics của demo; FE study cho thấy HOIC/LOIC có thể nhân đôi số flow, không đổi số incident).

## 3. Thiết kế C (khóa)
**Đầu vào:** các flow bị alert (`a0_score ≥ threshold` ở mức α), theo thứ tự quyết định trong từng segment; mỗi flow có source incident (luật cũ), host đích và họ tấn công family-aware (`predicted_family`; argmax Benign → `Unknown`).

**Gán campaign (causal, online):**
1. Khi một source incident mở (flow alert đầu tiên của nó) với khóa k = (đích, họ): nếu có campaign đang hoạt động giữ k (flow cuối trên k cách ≤ cooldown 15 phút) thì source incident **gia nhập** campaign đó; ngược lại tạo campaign mới giữ k.
2. Mỗi flow alert sau đó của source incident đăng ký khóa (đích, họ) của nó cho campaign của incident, nếu khóa chưa bị campaign hoạt động khác giữ. **Không bao giờ gộp hai campaign đã tồn tại.**
3. Reset ở ranh giới segment. Không dùng thông tin tương lai, không dùng nhãn.

**Ablation (báo cáo, không chọn):** khóa chỉ là đích (bỏ họ).

**Hàng xem xét (một hàm chung cho mọi đơn vị):** mục = source incident hoặc campaign; giờ mở h = giờ của flow alert đầu tiên; xem xét ở cuối giờ h; mỗi giờ chọn B mục trong số mục mở trong giờ đó:
- `fifo`: mở sớm nhất;
- `volume`: nhiều flow alert nhất **tính tới lúc xem xét** (causal);
- `severity` (đã khai báo trước, D4): severity family-aware lớn nhất tới lúc xem xét, rồi volume.

**Severity family-aware (sửa L-4.4):** flow có nhãn mịn → severity của lớp; flow `uncertain` → severity của **họ** (`family.severity`, Web = 4); argmax Benign → 4 ("unknown suspicious"). Bảng lớp giữ nguyên `triage.severity`.

**Metric** (evaluator, theo scenario, B ∈ {10, 30}, ba chính sách, α ∈ {0.1%, 0.5%, 1%}):
- tải: số mục, mục/giờ, **mục báo nhầm/giờ** (không chứa attack flow), flow/mục, precision của mục được xem;
- độ phủ: **source-episode coverage@B** (episode = nhãn + source IP, tách khi nghỉ > 30 phút) ở hai mức: *strict* (có attack flow quyết định trước lúc xem xét nằm trong mục được xem) và *case-attached* (mọi flow của mục được xem, kể cả flow đến sau, như cập nhật vào case đang mở); **attack-type coverage** (loại tấn công = segment + nhãn, strict); **attack-flow coverage** (case-attached); **risk-weighted episode coverage** với trọng số tác động khai báo trước theo họ thật: Web 4, BruteForce 3, DoS 3, DDoS 4, Bot 5, Infiltration 5;
- độ trễ: thời gian từ attack flow đầu tiên của mỗi loại tấn công tới lần xem xét đầu tiên phủ nó;
- chất lượng gom (chỉ campaign): số campaign nhiều nguồn; source incident chỉ-benign bị gom vào campaign có tấn công (**contamination**); campaign chứa ≥ 2 nhãn tấn công thật (**over-merge**); số mục mà mỗi loại tấn công bị chia ra (**fragmentation**).

**Luật GO cho C** (xác nhận trên H5–H9, model chính A0 v2 ở α = 0.1%, severity, B = 10; các mức khác báo kèm):
- **G1 lợi ích:** trên H5, source-episode coverage@B (strict) **hoặc** attack-flow coverage@B của campaign ≥ source + 0.05 (tuyệt đối), ở ít nhất một mức α mà A0 có alert trên HOIC;
- **G2 không mất tấn công:** không có loại tấn công nào (trên H5–H9, mọi B, mọi chính sách, α = 0.1%) được phủ bởi source mà không được phủ bởi campaign (strict);
- **G3 không ngụy trang FP:** source incident chỉ-benign bị gom vào campaign có tấn công ≤ 5% tổng số source incident chỉ-benign (gộp H5–H9);
- **G4 độ trễ:** trung vị thời gian tới lần xem xét đầu tiên không chậm hơn > 15 phút.

GO ⇔ G1 ∧ G2 ∧ G3 ∧ G4 → campaign là đơn vị mặc định của hàng xem xét trên UI. NO-GO → source incident vẫn là mặc định; campaign chỉ là ngữ cảnh (cột/khung phụ, ghi "experimental"). **Trong mọi trường hợp không claim giảm FPR.**

## 4. Thiết kế D (khóa)
**Reference:** cửa sổ calibration C1 (20/02 12:00–14:05, cùng dữ liệu đã khóa threshold), chấm bằng **cùng model**. Lưu cạnh model (`drift_reference.json`): quantile score, threshold theo α, bin của từng feature.

**Cửa sổ monitor:** 15 phút event time (theo `decision_at`), căn từ đầu segment; bỏ cửa sổ < 2,000 flow. Monitor chỉ dùng flow của cửa sổ và reference (causal, không nhãn); độ trễ = 1 cửa sổ.

**Tín hiệu:**
| Tên | Định nghĩa | Báo động (khai báo trước) |
|---|---|---|
| `AR` alert-rate ratio | tỷ lệ flow có score ≥ t_α, chia α | AR ≥ 2 và p nhị thức một phía < 0.001 |
| **`TR` tail ratio (chính)** | tỷ lệ flow có q_ref(1 − 10α) ≤ score < t_α, chia 9α (khối reference của dải này) | TR ≥ 2 và p < 0.001 |
| `S_PSI` prediction drift | PSI của score trên bin quantile reference (thập phân vị, 0.95, 0.99, 0.999) | ≥ 0.25 |
| `F_PSI` data drift | trung vị PSI qua 49 feature (feature số: bin thập phân vị reference; mã phân loại: top-20 giá trị reference + "khác") | ≥ 0.25 |

Lý do chọn TR làm tín hiệu chính: alert ở mức α nằm ở đuôi rất mỏng (ít mẫu, lẫn attack); nếu phân phối benign dịch lên, khối ngay **dưới** ngưỡng (gấp 9 lần) tăng theo, nên ổn định hơn về thống kê và ít bị attack có score ≈ 1 chi phối. Đây là giả thuyết cần kiểm chứng, không phải kết quả.

**Ground truth (evaluator):** FPR benign thực tế của cửa sổ tại t_α; cửa sổ đánh giá được khi có ≥ 5,000 flow benign; sự kiện **E = FPR > 2α**. Hai bộ nhãn: gốc và sửa (sửa là chính ở các ngày được audit; ngày khác giống gốc). K5 (phạm vi máy chủ web, khác reference toàn mạng) báo riêng là "scope mismatch".

**Metric:** Spearman ρ(tín hiệu, FPR thực) kèm bootstrap CI theo cửa sổ; AUROC cho E; tại luật báo động: recall của E, tỷ lệ báo giả trên cửa sổ không-E (tách benign-only và có tấn công); sai số trung vị |log10(α·TR) − log10(FPR)|. α chính 0.1%, báo thêm 0.05%, 0.5%, 1%.

**Luật "hữu ích" cho D** (gộp DEV + HO; HO báo riêng; nhãn sửa là chính, nhãn gốc báo kèm), α = 0.1%:
- ρ(TR, FPR) ≥ 0.5 và cận dưới CI 95% > 0; **và**
- TR báo động bắt ≥ 80% cửa sổ E với tỷ lệ báo giả ≤ 20% trên cửa sổ không-E.
- Nếu số cửa sổ E < 5: phần recall là **INCONCLUSIVE**.

Monitor luôn được đưa lên UI như **chỉ báo** (không đổi quyết định). Nếu không đạt luật trên, UI chỉ được ghi "chỉ báo thay đổi phân phối", **không** được ghi là ước lượng FPR.

## 5. Luật cho RQ-M (bằng chứng cho D1)
Khuyến nghị pilot `pilot_cns/s0` làm model cuối nếu trên H5–H9 (gộp benign, α = 0.1%, nhãn sửa nếu có): FPR thực của pilot ≤ A0 v2; **và** source incident báo nhầm/giờ của pilot ≤ 1.5 × A0 v2; **và** recall flow HOIC (H5) của pilot ≥ A0 v2 − 0.05. Ngược lại giữ A0 v2. Báo cáo cả hai model ở mọi mức α.

## 6. Bất biến phải có test
1. Correlation và monitor không đổi `a0_candidate`, `incident_id`, `active_decisions_sha1`.
2. Gán campaign là causal: kết quả trên một prefix của stream bằng kết quả của toàn stream cắt tại prefix đó.
3. Monitor và UI không đọc nhãn.
4. Cùng một hàm hàng xem xét cho source incident và campaign.
5. Incident uncertain không bao giờ nhận severity của XSS hay SQLi.

## 7. Thứ tự thực hiện
1. Commit tài liệu này + config (`ops` trong `configs/demo.yaml`, `configs/ops_holdout.yaml`).
2. Code + test → commit.
3. Dev: replay pilot trên các segment dev (không phải holdout), chạy study trên DEV và EXP. Sửa lỗi nếu có; mọi thay đổi thiết kế sau bước này được ghi ở mục "Sai lệch so với pre-registration" của báo cáo kết quả.
4. Tag `ops-v1-frozen` → prepare holdout mới → replay hai model **một lần** → study trên HO.
5. Báo cáo `docs/OPS_STUDY_RESULTS.md`, cập nhật kiến trúc, giới hạn, README, registry.
