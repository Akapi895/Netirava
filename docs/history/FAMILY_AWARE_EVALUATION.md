# Family-aware output — đánh giá (2026-11-08)

**Code:** `src/netirava/family.py`; tích hợp ở `src/netirava/app.py` (UI) và `pilot.evaluate_pilot`.

**Test:** `test_family_aware_keeps_probabilities_and_binary_alerts`.

**Luật:**
- Xác suất **không bị sửa**: p(Benign), tổng khối của họ Web và mọi p_c giữ nguyên.
- Chỉ những flow có argmax thuộc họ Web (Brute_Force_-Web, XSS, SQLi) mới được hiển thị lại: giữ nhãn mịn nếu tỷ trọng của nó trong khối họ ≥ τ, ngược lại hiển thị **"Web attack - fine class uncertain"**.
- τ = 0.8 (cố định trong UI); các mức 0.6, 0.7, 0.9 chỉ được báo để phân tích độ nhạy.
- **Alert binary không đổi theo cấu trúc** (attack_score = 1 − p(Benign) không bị chạm tới). Unit test xác nhận xác suất, alert và nhãn ngoài họ đều không đổi.

## Kết quả (eval trong phạm vi web; mỗi ô là seed 0 / 1 / 2)
| Model · nhãn | τ | Precision họ Web | Recall họ Web | Tỷ lệ từ chối nhãn mịn | Độ chính xác nhãn mịn khi phát (family-aware) | Độ chính xác argmax trên cùng các flow | Nhãn mịn sai: argmax → family-aware |
|---|---|---|---|---|---|---|---|
| A0 v2 · nhãn gốc | 0.8 | 0.967 / 0.967 / 0.968 | 0.903 / 0.899 / 0.907 | 0.42 / 0.44 / 0.43 | **0.93 / 0.93 / 0.94** | 0.71 / 0.70 / 0.72 | **300 → 9; 308 → 9; 297 → 2** |
| A0 v2 · nhãn gốc | 0.6 / 0.9 | không đổi | không đổi | 0.38–0.40 / 0.44–0.45 | 0.90–0.91 / 0.93–0.94 | | 26–33 / 1–6 |
| A0 v2 · nhãn đã sửa | 0.8 | 0.06–0.09 | 0.63–0.90 | 0.84–0.86 | 0.13–0.15 | 0.02 | 23–39 → 13–18 |
| Pilot · nhãn đã sửa | 0.8 | 1.00 | 0.983 | 0 | 1.00 | 1.00 | 0 → 0 |

**Triage** (run dev `20261108T122848`, A0 v2): 238 incident (**không đổi**, vì alert binary không đổi). 9 incident chuyển nhãn hiển thị sang "Web attack - fine class uncertain"; 1,049/166,636 flow bị alert được gắn nhãn uncertain (`runs/family_aware_triage_impact.json`).

## Kết luận
- **Family-aware output: GO.**
  - Không ảnh hưởng FP (có chứng minh bằng test).
  - Với model còn mơ hồ (A0 v2), số nhãn mịn sai giảm khoảng **97%**, đổi lại 43% dự đoán trong họ Web được trả về dạng "uncertain"; precision họ Web giữ ở 0.97.
- **Giới hạn:**
  - Metric trên nhãn gốc phản ánh nhãn nhiễu.
  - Trên nhãn đã sửa, A0 v2 có precision họ Web rất thấp. Đây là vấn đề của nhãn train, không phải của luật hiển thị.
  - Với pilot, luật này không có tác dụng gì đo được (n quá nhỏ).
