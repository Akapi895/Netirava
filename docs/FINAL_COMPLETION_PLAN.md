# Netirava: kế hoạch hoàn thiện (2026-11-08 → hạn slide 10/11/2026)

**Mục tiêu:** chốt **một** giải pháp datathon gồm 3 thành phần ([`FINAL_SOLUTION_ARCHITECTURE.md`](FINAL_SOLUTION_ARCHITECTURE.md)) để có thể triển khai, đánh giá minh bạch và trình bày. Giới hạn nêu ở [`CURRENT_LIMITATIONS.md`](CURRENT_LIMITATIONS.md).

**Ràng buộc chung:**
- **Không** train model mới;
- **không** chạy lại holdout H1/H2;
- **không** sửa số liệu lịch sử hay xóa bằng chứng;
- **không** push khi chưa được yêu cầu.

Replay hoặc evaluation trên các segment **không phải holdout** bằng model đã có thì được phép.

## Trạng thái (cập nhật 2026-11-08, ops study)
- **D1 chốt:** pilot `pilot_cns/s0` theo luật RQ-M khai báo trước (`OPS_STUDY_PREREG.md` §5), áp trên holdout mới H5–H9 (`OPS_STUDY_RESULTS.md` §6). `final_system.model_dir` trong `configs/demo.yaml`; `replay` mặc định dùng model này.
- **D2:** báo cả hai bộ nhãn (mọi bảng ops study). **D3:** α = 0.1%. **D4:** giữ severity (nay family-aware). **D5:** shadow tắt trong demo (`replay --mode a0`).
- **Xong:** P1.1 (severity family-aware), P1.2 (`notified` và `queue_rank_*`), P1.3 (`severity_source`), P3.1 (AppTest UI + smoke e2e), P3.3 (ghi chú provenance của feedback trên UI).
- **Mới:** campaign correlation (experimental view, NO-GO) và drift monitor (chỉ báo). Ràng buộc "không gom theo chiến dịch" ở cuối tài liệu này đã được người dùng mở lại cho ops study.

## P0: Quyết định cần người dùng chốt (chặn P1–P2)
| # | Quyết định | Phương án | Đề xuất | Lý do và cái giá |
|---|---|---|---|---|
| **D1** | **Model detection cuối** | (a) A0 v2 `f32899bde8b4` (nhãn gốc) · (b) Pilot `pilot_cns/s0` `f964bde1ef5c` (nhãn đã sửa) | **(b) Pilot**; A0 v2 giữ làm baseline để so sánh | **Lý do:** thành phần 1 gồm "kiểm soát chất lượng nhãn". A0 v2 có XSS F1 = 0 và FPR trong phạm vi web 47.7% trên nhãn đã sửa (L-1.3); pilot giảm FPR theo flow trên R1 7–8 lần. **Cái giá phải ghi rõ:** incident báo nhầm/giờ tăng khoảng 2 lần trên R1 và known (L-3.5); portscan recall giảm (L-2.6); **không có holdout độc lập** và K5 trùng với dữ liệu train của pilot (L-7.4) |
| **D2** | **Label policy cho báo cáo** | Chỉ nhãn gốc · chỉ nhãn đã sửa · cả hai | **Cả hai.** Nhãn đã sửa là chính cho lớp web và FP; nhãn gốc để so sánh với literature | Mọi bảng ghi rõ bộ nhãn. Nhãn gốc không bao giờ bị sửa |
| **D3** | **Alert threshold** | α = 0.1% (đã khóa trên C1) · mức khác | **α = 0.1%** là operating point chính; báo thêm 0.05%, 0.5% và 1% | Đã khai báo trước. Threshold của pilot s0 là 0.00924; của A0 v2 là 0.8679 |
| **D4** | **Thứ tự hàng triage** | severity (đã khai báo trong `final_system`) · volume · FIFO | **Giữ severity** (đã khai báo trước, chạy trên H2), báo kèm volume và FIFO | Severity ≈ volume (L-6.2): giữ để không đổi luật sau khi đã xem kết quả |
| **D5** | **Anomaly shadow trong demo** | Bật · tắt | **Tắt mặc định** trong demo cuối; giữ code và các run cũ | Không thuộc 3 thành phần; V4b đã bị bác bỏ |

**Hoàn thành khi:**
- `configs/demo.yaml → final_system` cập nhật theo D1–D5;
- `replay` mặc định trỏ tới model đã chọn;
- có commit và tag `final-v1`.

## Danh sách công việc theo thứ tự ưu tiên
| Ưu tiên | Việc | Tiêu chí hoàn thành | Ước tính |
|---|---|---|---|
| **P1.1** | **Severity theo nhãn family-aware** (sửa L-4.4): incident có `fine_label_status = uncertain` lấy severity của **họ** (thêm `family.severity: {Web: 4}`), không lấy của lớp mịn đã bị giấu | Test mới: incident uncertain không bao giờ nhận severity của SQLi hay XSS. `active_decisions_sha1` và số incident không đổi trên run `20261108T143728` | 1 h |
| P1.2 | **Phân biệt "notified (FIFO budget)" và "trong hàng xem xét (severity/volume)"** trên UI và export (L-6.5) | UI có 2 cột hoặc nhãn riêng kèm chú thích; export có `queue_rank` và `notified` | 1 h |
| P1.3 | Export và UI ghi rõ **nguồn** của severity và nhãn (family/fine, τ) | `incidents.csv` có `severity_source` | 0.5 h |
| **P2.1** | **Run đánh giá cho model cuối** trên mọi segment không phải holdout (K1–K5, S1, R1; replay, không train) | Run mới có `EVALUATION.json`, `DECISIONS_dev.json` (gồm triage), `FAMILY_REPORT*.json` trên **cả hai bộ nhãn**. Nếu D1 = pilot thì chỉ đo lớp web trên các row eval của pilot (theo split `pilot.py`), và ghi rằng K5 không sạch | 1–2 h |
| P2.2 | **Bảng minority-class trung thực:** support credible, Wilson CI, cờ INCONCLUSIVE khi n < 30; tách "tái tạo nhãn NF-v3" khỏi "phát hiện trên nhãn đã sửa" | Một bảng trong `FINAL_RESULTS.md`, mỗi ô có bộ nhãn và loại bằng chứng (DEV / EXP / HO) | 1 h |
| P2.3 | **Bảng FP và incident burden:** theo scenario, FPR theo flow kèm Wilson CI, incident báo nhầm/giờ, tỷ lệ tập trung theo nguồn, độ dao động qua 3 seed | Có cả A0 v2 và model cuối, cả hai bộ nhãn | 1 h |
| P2.4 | **Bảng unknown-attack:** gom số đã có (Bot dev, H1, H2, portscan), **không chạy mới** | Ghi rõ "không claim zero-day"; HO được đánh dấu riêng | 0.5 h |
| P2.5 | **Accuracy–coverage của family-aware** cho model cuối (τ ∈ {0.5…0.95}, τ = 0.8 cố định) trên nhãn đã sửa | Có bảng risk–coverage và tỷ lệ uncertain theo flow và theo incident | 0.5 h |
| **P3.1** | Smoke test cho UI (Streamlit `AppTest`) trên run tổng hợp, và smoke test CLI (`export`, `family-report`, `registry`, `incidents`, `feedback`) | `pytest` xanh (18 + test mới) | 1.5 h |
| P3.2 | **Kịch bản demo 5 phút** (`docs/DEMO_SCRIPT.md`): replay → UI → mở incident uncertain → ghi feedback → export; kèm ảnh chụp dự phòng | Chạy được từ máy sạch theo README trong ≤ 10 phút | 1 h |
| P3.3 | Feedback hiển thị provenance (ai, khi nào, nguồn) và ghi rõ là không có vòng học lại | Có trên UI | 0.5 h |
| **P4.1** | **`FINAL_RESULTS.md`**: một nguồn số liệu duy nhất cho slide. Mỗi số kèm loại bằng chứng, bộ nhãn, run_id hoặc file | Mọi số trên slide truy được về artifact | 1.5 h |
| P4.2 | Model card cho model cuối (nếu D1 = pilot); cập nhật README, ARCHITECTURE và EXPERIMENT_REGISTRY (thêm run cuối và RQ-PCAP); chạy lại `registry` | Link không gãy; registry có run cuối | 1 h |
| P4.3 | **Errata** (thêm vào, không sửa số cũ): L-3.6 (pilot "giảm nhất quán" chỉ đúng một phần), L-4.7 (97% so với 85%) | Thêm mục errata trong `RESULTS_FINAL_ADDENDUM.md` | 0.5 h |
| **P5** | **Slide** theo năm bước: baseline bỏ sót gì → xử lý → cải thiện bao nhiêu → trả giá gì → giới hạn | Số chỉ lấy từ `FINAL_RESULTS.md`; có slide giới hạn (5 điểm ở đầu `CURRENT_LIMITATIONS.md`) | 10/11 |

**Thứ tự gợi ý:**
- **08–09/11:** P0 → P1 → P2.
- **09/11:** P3 → P4.
- **10/11:** P5.

Nếu thiếu thời gian, bỏ P3.3 và P2.5 trước, rồi đến P1.3. **Không bỏ** P1.1, P2.1–P2.3, P4.1.

## Tiêu chí hoàn thành toàn bộ
1. Một model, một bộ cấu hình và một threshold được ghi trong `final_system` và tag `final-v1`. Mọi số liệu của model cuối đến từ run ở tag đó.
2. Family-aware nhất quán trong prediction, incident (severity), UI và export. Có test chứng minh **không** đổi alert binary hay incident.
3. Mỗi claim trên slide có: số liệu, bộ nhãn, loại bằng chứng (DEV / EXP / HO) và nguồn.
4. `pytest` pass; demo chạy theo README.
5. Giới hạn được trình bày ngang hàng với kết quả.

## Phạm vi loại trừ (không làm trong giai đoạn này)
- **Dừng hẳn:** PCAP/HTTP feature expansion; GNN/GraphIDS; HICID, DIDS-MFL; kiến trúc SOTA mới; full hyperparameter search. Báo cáo và kết quả âm được giữ nguyên.
- **Không train:** không train model mới; không thêm seed hay biến thể; không tune τ hay α theo kết quả.
- **Không chạy lại holdout:** H1 và H2 không chạy lại, cũng không dùng để đánh giá model mới.
- **Không mở thêm phương pháp:** không mở decision layer V5 hay "A0-score theo entity"; không gom theo chiến dịch (chỉ ghi là hướng tương lai).
- **Không đổi dữ liệu:** không thêm dataset, không sửa nhãn gốc.
- **Không mở rộng sản phẩm:** không triển khai streaming hay production, không có vòng học lại từ feedback.

Muốn mở lại hướng nào ở trên cần có quyết định mới của người dùng.
