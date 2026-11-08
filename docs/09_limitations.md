# 09. Hạn chế

Trạng thái bằng chứng: **CM** đã đo và tái lập được; **TĐ** có đo nhưng support nhỏ, within-episode hoặc exploratory; **GT** giả thuyết, chưa đo.

## 1. Năm hạn chế phải nói trên slide
1. **Nhãn lớp hiếm của NF-v3 phần lớn sai.** Chỉ 6.9% flow web là credible; XSS và SQLi thật chỉ có một episode (80 và 17 flow). F1 lớp hiếm trên nhãn gốc đo khả năng tái tạo nhãn, không đo khả năng phát hiện.
2. **Họ tấn công lạ chỉ lộ ra ở FPR cao hơn.** Ở α = 0.1%: Bot 0/8 episode, LOIC-HTTP recall 0, LOIC-UDP gần 0. HOIC được pilot bắt 81% nhưng A0 v2 chỉ 4%.
3. **FPR thay đổi theo ngày ở cùng threshold:** A0 v2 từ 0.037% tới 0.598% (nhãn gốc). Trên 6 cửa sổ chưa chạm (H3, H5–H9), FPR luôn ≤ 0.127%, nhưng mức dao động theo seed và theo ngày vẫn lớn.
4. **Đơn vị gom incident còn thô.** Gom theo source IP không hợp với tấn công nhiều nguồn; gom theo campaign giúp nhưng gộp nhầm 5–7% incident benign (NO-GO).
5. **Một testbed, mỗi lớp một episode, holdout đã dùng hết** (H1–H9). Không còn dữ liệu sạch trong dataset này để kiểm chứng phương pháp mới.

## 2. Theo nhóm
| Nhóm | Hạn chế | Bằng chứng | Trạng thái |
|---|---|---|---|
| Lớp hiếm | Support credible quá nhỏ (Web 70, XSS 80, SQLi 17; eval SQLi n = 2) | `02` §6 | CM |
| | Pilot gần như hoàn hảo trên nhãn sửa nhưng chỉ within-episode; K5 trùng phần train của pilot | `04` §5 | TĐ |
| | A0 v2 có XSS F1 = 0 và FPR 47.7% trong phạm vi máy chủ web khi đánh giá bằng nhãn sửa | `04` §5 | CM |
| | Lợi ích của SMOTE: cùng dấu ở 3 seed nhưng CI seed 0 chưa loại trừ 0; chưa hơn class weight | `04` §3 | TĐ |
| | XSS và SQLi khó tách bằng NetFlow vì khác biệt nằm ở payload HTTP | `02` §7 | GT |
| Họ lạ | V4b (anomaly gom theo host) bị bác bỏ trên H1 | `04` §2 | CM (HO) |
| | Hulk (gần họ DoS) được phát hiện, chỉ 1 episode | `04` §4 | TĐ |
| | Pilot bỏ sót Infilteration (0.012 trên H6) và portscan (0.5–0.7%) | `04` §5–6 | CM |
| False positive | FPR phụ thuộc seed (S1, A0 v2: 0.598 / 0.350 / 0.158%) | `04` §5 | CM |
| | Pilot giảm FP theo flow nhưng incident báo nhầm/giờ tăng trên R1 và known | `04` §5 | CM |
| | Pilot có FPR cao hơn A0 v2 ở α = 0.5% trên ngày benign | `04` §6 | CM (HO) |
| | Phần lớn FP của 28/02 là portscan bị gắn Benign (0.598% → 0.097% nếu sửa); chưa kiểm chứng packet tại chỗ | `02` §4 | CM có điều kiện |
| Family-aware | Chỉ là abstention; không sửa Benign → Web; chỉ định nghĩa họ mơ hồ cho Web; τ chỉ kiểm tra trên K5 | `05` | CM |
| Triage | Luật ưu tiên theo volume được đặt sau khi thấy FIFO thất bại (H1 là EXP) | `06` §2 | TĐ |
| | Budget 10 và 30 mục/giờ là giả định; chưa có đánh giá với analyst thật; feedback không có vòng học lại (cố ý) | `06` | GT |
| | Campaign: chỉ một holdout nhiều nguồn (HOIC) | `06` §4 | CM |
| Drift | Quá ít cửa sổ FPR > 2α để đánh giá recall của monitor; trên holdout riêng ρ(TR, FPR) = 0.06; α·TR không phải ước lượng FPR | `07` | TĐ |
| Triage | Thử nghiệm triage chỉ có một reviewer LLM, 20 quyết định mỗi điều kiện; chưa có analyst người | `12` | TĐ |
| Chọn model | Luật chọn pilot không có điều kiện bảo toàn lớp thiểu số, portscan hay Infiltration; H5–H9 sau khi dùng để chọn không còn là test chưa chạm | `10` §1 | CM |
| Feature | Port, TTL, DNS id có thể là shortcut, nhưng bỏ chúng làm kết quả holdout kém hơn | `03` §3 | CM (HO) |
| | G_ctx (ngữ cảnh theo host) hứa hẹn cho scan nhưng làm tăng FPR R1; chưa kiểm chứng | `03` §2 | GT |
| Lớp hiếm | Ablation sạch (nhãn sửa, đã loại trùng) không phân biệt được không xử lý, class weighting và SMOTENC | `11` §1 | CM |
| | Không còn cohort thiểu số độc lập, đáng tin, chưa dùng trong dataset | `11` §2 | CM |
| Dữ liệu | 440/480 row XSS là bản sao y hệt của row mang nhãn web khác | `11` §2 | CM |
| | Split là đánh giá theo cửa sổ hồi cứu, không phải train → calibration → tương lai; replay K5 chứa row train của pilot | `10` §4 | CM |
| | Pilot, A0 v2 và ops study chưa loại bản trùng; FE study, ablation sạch và ledger đã loại (ledger báo cả hai) | `10` §5 | CM |
| | NF-v3 xuất phần lớn flow tấn công hai lần; số đếm tấn công trong báo cáo trước khi loại trùng bị thổi phồng khoảng 2 lần | `02` §3 | CM |
| | Nhãn sửa CNS2022 dùng xấp xỉ payload và chỉ có cho 3 ngày; 17,082 nhãn Infilteration thành indeterminate | `02` §6 | TĐ |
| Vận hành | Export delay giả định bằng 0; chỉ replay, không có ingest nProbe hay streaming thật | `01` §4 | GT |
| | Một cửa sổ calibration, không calibrate lại theo ngày | `04` §1 | CM |

## 3. Kết quả âm được giữ làm bằng chứng
- GraphIDS: NO-GO. RQ-PCAP: NO-GO trên IoT-23. NP-v1 A1+B2 không chuyển giao qua đợt.
- V4a không có lợi trên DEV; V4b bị bác bỏ trên H1.
- Severity không tốt hơn volume.
- A0 v2 có XSS F1 = 0 trên nhãn sửa.
- Bỏ cột shortcut làm kết quả H3/H4 kém hơn.
- Campaign correlation NO-GO; bản "open-once" che một SQLi thật trên DEV.
- Drift monitor INCONCLUSIVE.
