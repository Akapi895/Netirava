# Tài liệu Netirava

Đọc theo thứ tự: `08` là báo cáo tổng, `10` là ledger số liệu; `01`–`07` và `11`–`13` là chi tiết; `09` là hạn chế.

| File | Nội dung |
|---|---|
| [`01_problem_framing.md`](01_problem_framing.md) | Đề bài, câu hỏi nghiên cứu, protocol, danh sách holdout, luật kết luận |
| [`02_data_eda_labels.md`](02_data_eda_labels.md) | Nguồn dữ liệu, subset, EDA, forensics FP, nhãn web, nhãn sửa CNS2022 |
| [`03_preprocessing_features.md`](03_preprocessing_features.md) | Input của model, preprocessing và nhóm feature đã thử, holdout H3/H4 |
| [`04_modeling.md`](04_modeling.md) | Model card, MVP và decision layer, lớp hiếm và mất cân bằng, pilot nhãn sửa, so sánh model trên H5–H9, chi phí, review SOTA |
| [`05_family_aware.md`](05_family_aware.md) | Nhãn family-aware: luật, bất biến, risk–coverage |
| [`06_triage_correlation.md`](06_triage_correlation.md) | Triage theo incident, UI, correlation theo campaign (NO-GO) |
| [`07_drift_monitoring.md`](07_drift_monitoring.md) | Drift monitor không nhãn (INCONCLUSIVE) |
| [`08_final_report.md`](08_final_report.md) | **Báo cáo tổng:** mọi cách đã thử theo giai đoạn, kết quả, quyết định, số cho slide |
| [`09_limitations.md`](09_limitations.md) | Hạn chế và kết quả âm |
| [`10_evidence_ledger.md`](10_evidence_ledger.md) | **Nguồn số duy nhất cho headline:** model và run cuối, bảng bằng chứng theo cohort (raw và dedup), đánh đổi, split thật, sửa đo lường |
| [`11_ablation_and_cohorts.md`](11_ablation_and_cohorts.md) | Ablation imbalance sạch; kiểm kê cohort thiểu số trên toàn dataset |
| [`12_triage_trial.md`](12_triage_trial.md) | Thử nghiệm triage nhỏ có đáp án tham chiếu (reviewer LLM, formative) |
| [`13_external_evaluation.md`](13_external_evaluation.md) | Đánh giá ngoài trên NF-UNSW-NB15-v3 (model frozen), drift monitor trên môi trường mới, cổng cho lượt train cuối |
| [`architecture.md`](architecture.md) | Pipeline, module, contract dữ liệu, bất biến |
| [`experiment_registry.md`](experiment_registry.md) | Thí nghiệm, artifact, lệnh, commit; bảng sinh tự động ở [`experiment_registry_generated.md`](experiment_registry_generated.md) |
| [`ops_change_audit.md`](ops_change_audit.md) | Audit training và inference invariance của ops study |
| [`protocols/ops_study_prereg.md`](protocols/ops_study_prereg.md) | Pre-registration của ops study, giữ nguyên văn (commit `e1b473a`) |
| [`protocols/evidence_round2_prereg.md`](protocols/evidence_round2_prereg.md) | Pre-registration của ablation sạch, kiểm kê cohort, thử nghiệm triage (commit `d368fdc`) |
| [`protocols/external_round3_prereg.md`](protocols/external_round3_prereg.md) | Pre-registration của đánh giá ngoài và cổng train (commit `6ad5206`) |

Pre-registration của feature study nằm trong `configs/fe_study.yaml` (commit `e820605`).

## Ánh xạ từ tài liệu cũ
Các tài liệu dưới đây đã được gộp. Bản gốc còn nguyên ở tag `pre-docs-refactor` (`git show pre-docs-refactor:docs/<tên>`).

| Tài liệu cũ | Nay ở |
|---|---|
| `RESEARCH_FRAMING.md` | `01` |
| `DATASET_CARD.md`, `EDA_REPORT.md`, `FP_LABEL_FORENSICS.md`, `CORRECTED_LABEL_AUDIT.md`, `MINORITY_INFORMATION_AUDIT.md`, `DATA_SUFFICIENCY_DECISION.md` | `02` |
| `PREPROCESSING_SPEC.md`, `FEATURE_EVALUATION.md`, `FE_HOLDOUT_RESULTS.md` | `03` |
| `MODEL_CARD_A0_v2.md`, `history/MODEL_CARD_A0_v1.md`, `RESULTS_MVP.md`, `RESULTS_DECISION.md`, `RESULTS_FINAL.md` §2 và §7, `RESULTS_FINAL_ADDENDUM.md`, `CORRECTED_LABEL_PILOT_RESULTS.md`, `SOTA_METHOD_REVIEW.md` | `04` |
| `FAMILY_AWARE_FINAL_REPORT.md`, `history/FAMILY_AWARE_EVALUATION.md` | `05` |
| `RESULTS_FINAL.md` §3, `OPS_STUDY_RESULTS.md` §1 và §4 | `06` |
| `OPS_STUDY_RESULTS.md` §5 | `07` |
| `FINAL_SOLUTION_ARCHITECTURE.md`, `FINAL_COMPLETION_PLAN.md`, `OPS_STUDY_RESULTS.md` §2 và §6 | `08`, `04` §6 |
| `CURRENT_LIMITATIONS.md` | `09` |
| `ARCHITECTURE.md` | `architecture.md` |
| `EXPERIMENT_REGISTRY.md`, `EXPERIMENT_REGISTRY.generated.md` | `experiment_registry.md`, `experiment_registry_generated.md` |
| `OPS_STUDY_PREREG.md` | `protocols/ops_study_prereg.md` (nguyên văn) |
| `OPS_CHANGE_AUDIT.md` | `ops_change_audit.md` |
| `CLEANUP_MANIFEST.md`, `history/NEXT_RESEARCH_DECISION.md` | Lịch sử dọn repo và quyết định đã bị thay thế; chỉ còn ở tag |
