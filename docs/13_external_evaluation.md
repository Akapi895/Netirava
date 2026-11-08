# 13. Đánh giá ngoài trên NF-UNSW-NB15-v3 và quyết định về lượt train cuối

Protocol khai báo trước: [`protocols/external_round3_prereg.md`](protocols/external_round3_prereg.md) (commit `6ad5206`). Code: `src/netirava/external.py` (`python -m netirava external`). Kết quả: `runs/external_unsw/EXTERNAL.json`, `MONITOR_EXPLORATORY.json`.

## 1. Nguồn
- **NF-UNSW-NB15-v3:** 2,365,424 flow, 2,350,609 sau khi loại bản trùng toàn phần. Cùng schema 49 feature NetFlow v3 với dữ liệu CIC.
- **Môi trường khác hẳn:** traffic do IXIA PerfectStorm sinh, hai phiên capture (22/01/2015, kéo sang 23/01 theo UTC; và 18/02/2015).
- Mọi tấn công đến từ 4 host 175.45.176.0–3, không host nào trong số đó gửi benign.
- UNSW mới với model CIC, nhưng không mới với recipe: NP-v1 đã chọn công thức A0 trên chính hai phiên này.

## 2. E1: model CIC frozen, threshold khóa trên C1 của CIC
| Model | Phiên | Benign n | FPR @ α = 0.1% | FPR @ α = 1% | AUROC tấn công so với benign (theo lớp) |
|---|---|---|---|---|---|
| pilot `pilot_cns/s0` | 22/01 | 1,074,674 | **25.1%** | 80.3% | 0.06–0.27 |
| | 23/01 (phần đuôi) | 39,775 | 27.0% | 80.5% | — |
| | 18/02 | 1,108,481 | **24.3%** | 80.1% | 0.10–0.25 |
| A0 v2 | 22/01 | 1,074,674 | 2.03% | 61.7% | 0.23–0.44 |
| | 18/02 | 1,108,481 | 2.07% | 62.2% | 0.27–0.42 |

- **Threshold không giữ được** ở bất kỳ phiên hay mức α nào (luật: FPR ≤ 2α). Ở α = 0.1%, FPR thực của pilot gấp khoảng 250 lần mục tiêu, của A0 v2 khoảng 20 lần.
- **AUROC dưới 0.5 ở mọi lớp:** flow tấn công UNSW nhận score *thấp hơn* benign UNSW. Detection ở đây không chỉ kém, mà xếp hạng ngược.
- Gần như mọi flow tấn công UNSW được gán argmax Benign. Vài flow được gán `DoS_attacks-GoldenEye` hoặc `Brute_Force_-Web`.
- **Nguyên nhân quan sát được** (kiểm tra trên 300,000 flow mẫu; không phải lỗi pipeline vì cột khớp theo tên và kiểu số tương đương):
  - TTL benign trung vị 31–32 ở UNSW, so với 100 ở CIC;
  - TCP window trung vị 13,032 so với 258;
  - 21% benign UNSW là FTP (port 21), loại traffic mà model CIC chỉ thấy dưới dạng FTP-BruteForce;
  - score benign UNSW ở phân vị 99% là 0.90 (CIC C1: 0.0002).
- **Kết luận E1:** model CIC không chuyển sang môi trường UNSW. Đây là kết quả âm rõ ràng và nhất quán với rủi ro shortcut theo TTL, port và window đã ghi ở `03` và `09`. Không model nào được tune lại.

## 3. Exploratory (ngoài protocol): drift monitor có nhận ra môi trường mới không?
Đặt câu hỏi này **sau** khi thấy E1, nên kết quả chỉ là exploratory.

- **Cách chạy:** monitor không nhãn với reference C1 của pilot, cửa sổ 15 phút trên UNSW.
- **Kết quả:** **99/99 cửa sổ** có trạng thái "threshold-reliability WARN". Cả bốn tín hiệu đều báo ở 100% cửa sổ. Trung vị: AR 232, TR 62.5, score PSI 6.35, feature PSI 1.81. Feature thay đổi nhiều nhất là `CLIENT_TCP_FLAGS`, `TCP_FLAGS`, `L7_PROTO`.
- **So sánh:** trên các giờ chỉ có benign của CIC (H5–H9), AR, score PSI và feature PSI không báo cửa sổ nào (`07` §3).
- **Đọc đúng:** monitor nhận ra được một dịch chuyển môi trường rất lớn trước khi có nhãn. Dịch chuyển này dễ phát hiện, nên kết quả không cho biết monitor có bắt được những dịch chuyển nhỏ đủ làm hỏng threshold hay không (vẫn INCONCLUSIVE, `07`).

## 4. E2: cổng cho lượt train cuối → **không train**
| Điều kiện | Kết quả | Ghi chú |
|---|---|---|
| G1: ≥ 2 lớp thiểu số có ≥ 30 flow ở cả hai phiên, với host hoặc episode ở mỗi phía | **Không đạt** | Lớp thiểu số (< 1% flow tấn công): Analysis, Worms. Phiên 22/01: Analysis 267 flow nhưng chỉ 1 host nguồn, 1 episode; Worms chỉ 20 flow. Phiên 18/02: Analysis 959 (13 episode), Worms 138 (124 episode) |
| G2: biết ý nghĩa timestamp, host, kịch bản | Đạt theo phiên | Code chia theo ngày UTC nên ra 3 ngày và báo "không đạt". Thực tế 23/01 là đuôi của phiên 22/01; khi chia theo phiên, hai phiên và subnet attacker/victim khớp tài liệu nguồn |
| G3: không có bản trùng xuyên split | Đạt | 0 bản trùng toàn phần giữa các ngày |
| G4: benign calibration và test riêng | Đạt theo phiên | Như G2, "không đạt" là do mảnh 23/01 chỉ có 39,775 benign. Mỗi phiên chính có trên 1 triệu benign |
| G5: trong ngân sách | Đạt | 2.37 triệu row |
| G6: phần test chưa dùng để chọn recipe | **Không đạt** | Cả hai phiên đã dùng trong NP-v1 (phát triển và đánh giá A0); Run 1 và GraphIDS dùng split ngẫu nhiên trên mọi row |

**Quyết định:** G1 và G6 không đạt, nên lượt train cuối **không** được dùng. Lý do:
- Lớp thiểu số của UNSW ở phiên còn lại quá ít (Worms 20 flow; Analysis đúng 1 episode).
- Mọi phần test có thể có đều đã ảnh hưởng tới việc chọn recipe.
- Một fit trên UNSW sẽ chỉ cho thêm một model, không trả lời được "recipe khóa trước đạt gì trên một nguồn mới".

Lượt train được giữ cho một nguồn độc lập thật nếu sau này có.

## 5. E3: thử nghiệm với người
Kit đã sẵn (`12` §4). Bước này cần người tham gia nên chưa chạy được trong repo. Khi chạy:
- mỗi người làm cả C0 và C1, đổi thứ tự giữa các người;
- ghi số người và kinh nghiệm;
- gọi kết quả là formative.

## 6. Ý nghĩa cho bài nộp
- Model cuối giữ nguyên. Kết quả ngoài không dùng để chọn lại model.
- **Claim được thêm:** model CIC không chuyển giao sang một môi trường khác (FPR 24–27% ở mục tiêu 0.1%, AUROC < 0.5). Mọi kết quả của Netirava vì vậy chỉ đúng trong testbed CIC-2018; triển khai ở mạng khác cần train và calibrate lại.
- **Claim exploratory:** drift monitor báo động trên toàn bộ cửa sổ của môi trường mới, nên nó có thể làm lớp cảnh báo "đừng tin threshold này" khi đưa model sang mạng khác.
