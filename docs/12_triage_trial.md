# 12. Thử nghiệm triage nhỏ có đáp án tham chiếu

Đây là **đánh giá thử nghiệm nhỏ (formative)** với **một reviewer là LLM (Claude), đã làm mù**, không phải analyst người. Thời gian đo được là thời gian xử lý của reviewer LLM và không suy ra cho người. Protocol khai báo trước: [`protocols/evidence_round2_prereg.md`](protocols/evidence_round2_prereg.md) §C.

## 1. Thiết lập
- **Nguồn:** model cuối `pilot_cns/s0`, run holdout `20261108T211057_a0_fast` (H5–H9, α = 0.1%). H5–H9 đã được dùng để chọn model, nên kết quả là EXP.
- **Ngân sách:** 20 quyết định mỗi điều kiện, 4 cho mỗi segment.
- **C0, hàng flow theo score (không gom):** 4 flow bị alert có score cao nhất mỗi segment. Card là một flow, kèm score và lớp dự đoán của detector.
- **C1, hàng source incident của Netirava:** 4 incident đầu tiên mỗi segment theo giờ review và hạng severity. Card là bằng chứng tại lúc review: số flow, số đích, top port, nhãn family-aware, severity, thống kê byte, 5 flow đầu.
- **Làm mù:** IP thay bằng token, không có ngày, không có nhãn. Đáp án ghi riêng (`answers.json`, sha1 `db260504…` trong `manifest.json`) và chỉ được mở sau khi verdict đã lưu.
- **Đáp án:** mục là attack nếu có ít nhất một flow mang nhãn tấn công. Dùng nhãn CNS2022-adapted ở ngày đã audit, nhãn gốc ở ngày khác.
- **Thứ tự:** C1 trước, C0 sau, để hiệu ứng học nghiêng về baseline.
- **Artifact:** `runs/triage_trial/` (card, verdict, `SCORE.json`). Code: `src/netirava/triage_task.py`.

## 2. Kết quả
| Chỉ tiêu | C0: flow theo score | C1: incident Netirava |
|---|---|---|
| Mục chứa tấn công (theo đáp án) | 4 / 20 | 5 / 20 |
| Episode tấn công riêng biệt trong các mục đó | 1 (một nguồn Infilteration chiếm cả 4 mục) | 5 (4 nguồn HOIC, 1 nguồn Infilteration) |
| Loại tấn công (segment + nhãn) xuất hiện | 1: Infilteration (H6) | 2: HOIC (H5), Infilteration (H6) |
| Attack flow nằm trong các mục đã xem | 4 | 177,957 |
| Mục benign phải mở | 16 | 15 |
| Verdict đúng | 20 / 20 | 18 / 20 |
| Báo nhầm (đánh tấn công khi đáp án là benign) | 0 | 2 |
| Bỏ sót | 0 | 0 |
| Đúng họ tấn công trên mục tấn công | 0 / 4 | 4 / 5 |
| Thời gian reviewer LLM | 17 s | 20 s |

**Đọc kết quả:**
- **Phát biểu sát nhất:** ở 20 lượt xem, workflow incident đưa ra năm source-defined attack episode, so với một của hàng flow. Không nên chuyển thành "phát hiện nhiều tấn công hơn 5 lần" hay "tăng hiệu suất analyst".
- **Không cô lập được thành phần tạo ra khác biệt.** C0 và C1 khác nhau đồng thời ở đơn vị (flow hay incident), cách xếp hạng (score hay severity), lượng ngữ cảnh trên card và cách chọn theo thời điểm review. Kết quả thuộc về cả workflow, không quy riêng cho việc gom incident hay family-aware.
- **Bốn nguồn HOIC thuộc cùng một kịch bản**, không phải bốn chiến dịch độc lập.
- **Hàng flow theo score không đưa HOIC ra.** Flow HOIC chỉ có score khoảng 0.19 (vượt threshold 0.0092 nhưng thấp hơn nhiều flow benign hoặc dò port lẻ), nên không flow HOIC nào lọt vào top-4 của H5. Gom thành incident theo nguồn làm 4 nguồn HOIC, mỗi nguồn khoảng 44,000 flow tới cùng một đích trên port 80, đứng đầu hàng.
- **Hàng flow tốn 4 lượt xem cho một nguồn** (cùng nguồn dò port 1). Hàng incident gộp nguồn đó thành một mục.
- **2 báo nhầm của C1** là hai nguồn quét (một nguồn quét port 3391 trên 72 đích; một nguồn dò 4 port trên một đích), mang nhãn Benign trong NF-v3. Đây có thể là lỗi của reviewer, hoặc là quét nền Internet mà kịch bản CIC gắn Benign (`02` §4). Thử nghiệm không phân xử được.
- **C0 đúng 20/20** vì một flow lẻ hiếm khi đủ bằng chứng; reviewer đánh gần hết là benign và đáp án cũng là benign. Độ đúng cao đi kèm việc gặp ít tấn công hơn.
- **Họ tấn công:** reviewer gọi nguồn Infilteration ở H6 là "Portscan" (hành vi quét port), khác nhãn tham chiếu.

## 3. Giới hạn
- Một reviewer, và đó là LLM; reviewer cũng là người thiết kế pipeline. Không có kiểm định thống kê.
- 20 quyết định mỗi điều kiện, trên một run, một model. Holdout đã dùng.
- Thời gian của LLM không phản ánh thời gian của người.
- Đáp án dựa trên nhãn NF-v3 hoặc CNS2022-adapted, cả hai đều có lỗi đã biết.

## 4. Chạy với người
Kit có chế độ tương tác ghi thời gian từng quyết định:
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava task-make --config configs/ops_holdout.yaml --run 20261108T211057_a0_fast --out runs/triage_trial_human
& $py -m netirava task-run  --task runs/triage_trial_human --cond C1 --reviewer <tên>   # rồi --cond C0
& $py -m netirava task-score --task runs/triage_trial_human --verdicts verdicts_C1_<tên>.csv verdicts_C0_<tên>.csv
```
Với nhiều người tham gia, nên đổi thứ tự C0/C1 giữa các người để cân bằng hiệu ứng học.
