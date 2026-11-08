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

**Kết quả DEV và EXP** (`runs/ops_study/{dev,exp_h2}/`, chi tiết ở mục 3) chỉ dùng để phát hiện lỗi; chúng không được dùng để chọn tham số.
