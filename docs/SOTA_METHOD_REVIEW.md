# SOTA method review — minority classes và họ tấn công liên quan (2026-11-08)

Tiêu chí:
- giải đúng vấn đề đã đo (nhãn sai, XSS/SQLi, FP);
- có code chính thức;
- có kết quả theo class và FPR;
- không tạo shortcut hay leakage;
- chi phí phù hợp.

Nguồn chưa đọc được toàn văn được ghi rõ.

## 1. Ba paper được yêu cầu audit
| | **HCE-Boost** (Sci. Rep. 2026) | **HICID** (Computer Networks 2026, PII S138912862600544X) | **DIDS-MFL** (IEEE TPAMI 2025, 47(11):10528–10545) |
|---|---|---|---|
| Đã đọc được gì | README chính thức ([repo](https://github.com/pengslin6/HCE-Boost)) và tóm tắt abstract. Trang Nature yêu cầu đăng nhập | **Không đọc được** (ScienceDirect trả 403; tìm theo tên/PII không ra) | Abstract arXiv 2307.11079 và README ([repo](https://github.com/qcydm/DIDS-MFL)) |
| Novelty | Expert toàn cục (XGBoost + LightGBM cân bằng trọng số), cộng **local expert kích hoạt theo lỗi trên validation** cho một họ hay nhóm lớp hiếm, cộng **luật chỉnh xác suất trong nhóm mà không tăng tổng khối xác suất của nhóm** | Coarse-to-fine cho lớp hiếm (theo tên gọi; chưa kiểm chứng được nội dung) | Disentangle feature hai bước, graph diffusion động (TGN memory), module few-shot đa thang đo |
| Code | Có | Không rõ | Có (input `.pt` đã tiền xử lý; bản NF-v2 `_3d`) |
| Input bắt buộc | Feature dạng bảng | ? | Event theo thời gian `src, dst, t, msg`, tức graph theo IP |
| Kết quả theo lớp hiếm và FPR | Chỉ có macro-F1 (NSL-KDD 64.99, subset CIC-IDS2017 93.73, Edge-IIoT 92.39). Không có per-class XSS/SQLi, không có benign FPR. Tác giả tự ghi: expert **giúp ổn định trên NSL-KDD, lợi ích không rõ trên CIC-IDS2017, không bao giờ kích hoạt trên Edge-IIoT** | ? | Báo cáo mức tăng F1 trung bình rất lớn so với baseline (73–140%) trong thiết lập few-shot. Không có FPR vận hành |
| Có giải đúng vấn đề của Netirava? | Một phần: nhắm vào **nhầm lẫn bên trong một họ**. Luật bảo toàn khối xác suất **giữ nguyên p(Benign)**, nên binary FP không đổi. Nhưng **không sửa được nhãn sai** và **không thêm thông tin** | Không đánh giá được | **Không.** Không thêm thông tin payload; graph theo IP lặp lại rủi ro của GraphIDS (shortcut theo host, ngữ cảnh transductive). Chi phí xây graph cao |
| Rủi ro leakage | Thấp nếu validation tách theo thời gian hay episode | ? | Cao (ngữ cảnh graph và memory; README không nói cách xử lý test edge) |
| Chi phí tích hợp | Thấp (chạy post-hoc trên xác suất A0 hoặc một vài model con) | ? | Cao (pipeline mới, GPU, định dạng dữ liệu riêng) |

**Họ hierarchical khác** (tham khảo, không có code hay per-class FPR đủ để ưu tiên): HFPD-IDS (IEEE Access 2023), CANET (Comput. Commun. 2023), hierarchical IDS nhiều tầng (Verkerken et al., TNSM 2023). Điểm chung là coarse-to-fine giảm nhầm "attack thành benign", nhưng **lỗi lan truyền** từ tầng thô sang tầng mịn, và chúng không thêm thông tin.

## 2. Hướng data-centric (không phải model)
**Engelen et al., IEEE CNS 2022, *Error Prevalence in NIDS Datasets*** ([doc](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html), [code](https://github.com/GintsEngelen/CNS2022_Code)). Cùng hướng có Liu et al. 2022 (sửa logic gắn nhãn của CIC).
- Có code; bằng chứng ở mức PCAP; trực tiếp giải **nguyên nhân chính** đã đo được (`FP_LABEL_FORENSICS.md`).
- Đánh đổi: luật được viết cho flow CICFlowMeter. Với NF-v3 chỉ áp được phần luật theo **cặp IP + cửa sổ thời gian + giao thức/cổng**; phần dựa payload hay số packet cần kiểm chứng lại.

## 3. Đề xuất (tối đa 2)
1. **Ứng viên 1, data-centric: đánh giá lại bằng nhãn đã sửa theo CNS2022** cho các ngày 22/02 (web) và 28/02 (portscan, Infiltration).
   - Không đổi model; là điều kiện tiên quyết để mọi so sánh model về lớp hiếm có nghĩa.
   - Đóng góp riêng của Netirava: quy trình **chuyển luật sửa nhãn từ CICFlowMeter sang NetFlow v3**, cùng báo cáo độ nhạy giữa nhãn gốc và nhãn sửa.
2. **Ứng viên 2, family-aware output bảo toàn khối xác suất** (lấy cảm hứng từ luật group-mass của HCE-Boost).
   - Gộp Web/XSS/SQLi thành **họ Web** ở tầng quyết định. Chỉ phát nhãn mịn khi xác suất trong họ đủ tách; ngược lại báo "Web attack (fine class uncertain)".
   - Tùy chọn: một local expert trong họ Web, **chỉ kích hoạt** nếu validation (nhãn đã sửa) cho thấy có lợi.
   - Tính chất quan trọng: p(Benign) không đổi, nên **binary FP không đổi theo cấu trúc**; chỉ giảm lỗi multiclass.

**Không đề xuất** DIDS-MFL (graph theo IP, chi phí lớn, không thêm thông tin, rủi ro giống GraphIDS) và HICID (không kiểm chứng được nội dung). Hyperparameter tuning là lựa chọn sau cùng.

## 4. Trả lời câu hỏi: học các họ tấn công liên quan nhau có giúp không?
- **Có phương pháp:**
  - hierarchical hoặc coarse-to-fine classification (HFPD-IDS, CANET, hierarchical multi-stage);
  - family-local expert kèm luật bảo toàn khối xác suất (HCE-Boost);
  - học biểu diễn disentangle hoặc contrastive (DIDS-MFL, SupCon).
- **Trên dữ liệu hiện tại thì lợi ích sẽ hạn chế:**
  - (i) 93% nhãn web không credible, và train không có XSS hay SQLi credible, nên mọi phương pháp chỉ học lại nhiễu nhãn;
  - (ii) mức họ Web đã đạt F1 0.85 (trên nhãn gốc), nên dư địa cải thiện của "học theo họ" chủ yếu nằm ở **cách báo cáo trung thực** (họ thay vì lớp mịn khi mơ hồ), không nằm ở metric;
  - (iii) tách XSS với SQLi thật có lẽ cần payload HTTP mà NetFlow không có.
- **Cái học theo họ làm được:** giảm lỗi multiclass mà không tăng FP (nhờ bảo toàn khối xác suất), và làm triage nhất quán hơn.
- **Cái nó không làm được:** tạo ra thông tin hay sửa nhãn sai.
