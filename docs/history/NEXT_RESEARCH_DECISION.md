# Next research decision (2026-11-08)

Căn cứ: [`FP_LABEL_FORENSICS.md`](FP_LABEL_FORENSICS.md), [`MINORITY_INFORMATION_AUDIT.md`](MINORITY_INFORMATION_AUDIT.md), [`SOTA_METHOD_REVIEW.md`](SOTA_METHOD_REVIEW.md). Không có lần train hay HPO nào trong nhiệm vụ này.

## 1. Nguyên nhân chính của từng hạn chế
| Hạn chế | Nguyên nhân chính (bằng chứng) | Phụ |
|---|---|---|
| FPR 0.60% trên ngày 28/02 | **Nhãn**: 84% FP là portscan của .24 mà NF-v3 gắn Benign; nếu sửa nhãn thì FPR còn 0.097% | Nhiễu quét Internet (111 flow) |
| FP trên ngày Bot | **Nhãn train sai**: mẫu nền UDP/500 bị gắn nhãn web attack ngày 22/02 | Duyệt web bình thường (175 flow) |
| F1 thấp và không ổn định của XSS/SQLi | **Nhãn**: train không có flow credible; 100% XSS nằm trong nhóm fingerprint nhiều nhãn | Thiếu payload HTTP (giả thuyết) |
| "Web F1 0.769" | Đo trên **flow không credible** (0/715 credible) | — |
| Nhầm SQLi thành XSS | Cùng traffic nền mang hai nhãn | — |

**Kết luận:** chưa nên thay model. Nguyên nhân chính nằm ở dữ liệu (nhãn), sau đó mới đến thông tin còn thiếu.

## 2. Hướng ưu tiên duy nhất
**Corrected-label evaluation theo CNS2022 cho NF-v3**, kèm một family-aware output bảo toàn khối xác suất làm cải tiến đi kèm, có ràng buộc FP.

## 3. Điều kiện chuyển hướng
- Nếu với nhãn đã sửa mà A0 vẫn không tách được XSS và SQLi credible (F1 mỗi lớp < 0.5 ở FPR ≤ 0.1%), thì giới hạn nằm ở **input**. Khi đó chuyển sang thu thập payload HTTP từ PCAP gốc (cần người dùng duyệt mở rộng dữ liệu).
- Nếu family-aware output không giảm lỗi multiclass, hoặc làm giảm family-level recall quá 0.02, thì bỏ và giữ argmax.
- Không chuyển sang graph, DIDS-MFL hay deep model khi chưa có nhãn sạch.

## 4. Pilot tối giản (đề xuất, chưa chạy)
1. **Nhãn đã sửa** (file riêng `truth_cns2022.parquet`; không ghi đè `truth.parquet`):
   - 22/02: flow web credible giữ nhãn lớp; các flow mang nhãn web còn lại chuyển sang **"Benign (CNS2022-corrected)"** hoặc "Attempted" theo luật cửa sổ khởi động;
   - 28/02: .24 → host nội bộ trong cửa sổ NMAP chuyển sang **"Portscan (CNS2022)"** (lớp unknown với A0).
2. **Chia lại web theo thời gian bên trong từng cửa sổ credible.** Support rất nhỏ (XSS 41, SQLi 20, BF 115), nên mọi kết quả chỉ là **chỉ báo**.
3. **Retrain A0** (công thức cố định, 3 seed) trên train đã sửa nhãn. Đánh giá trên known_replay đã sửa, cộng FP trên S1 và R1 (nhãn đã sửa và nhãn gốc, báo cả hai).
4. **Family-aware output** chạy post-hoc trên xác suất của A0.
5. **Tiêu chí chấp nhận** (khai báo trước):
   - benign FPR ≤ 0.1% trên C1, S1, R1 (với nhãn đã sửa), báo cả FPR với nhãn gốc;
   - false incident/giờ không tăng;
   - known macro-F1 không giảm quá 0.01.
6. **Tiêu chí loại bỏ:** vi phạm ngân sách FPR thì loại, không nới ngân sách sau khi xem kết quả.

## 5. Dữ liệu độc lập còn cần
- **Một episode web thứ hai:** CNS2022 ghi có tấn công ngày 23/02, nhưng NF-v3 **không có** flow 18.218.115.60 ↔ 172.31.69.28 trong ngày đó. Cần trích lại từ PCAP (nProbe) hoặc dùng flow CICFlowMeter đã sửa nhãn của CNS2022 (khác representation).
- Mọi claim về lớp hiếm hiện chỉ là **development evidence trên một episode**. Hai holdout LOIC-HTTP và DoS-Hulk đã dùng hết; không dùng lại.
