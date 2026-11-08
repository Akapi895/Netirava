# Addendum cho RESULTS_FINAL.md: nhãn (2026-11-08)

`RESULTS_FINAL.md` được giữ nguyên; mọi con số trong đó dùng **nhãn gốc của NF-v3**. Kết quả forensics ([`FP_LABEL_FORENSICS.md`](FP_LABEL_FORENSICS.md)) thay đổi cách đọc ba điểm:

1. **FPR 0.598% trên ngày 28/02.** 804/959 flow FP là portscan .24 → .15. NF-v3 gắn Benign cho chúng, nhưng CNS2022 xác định là tấn công dựa trên phân tích PCAP. Phân tích độ nhạy với nhãn đã sửa (exploratory) cho **0.097%**.
2. **Lớp hiếm.** Chỉ 6.9% flow mang nhãn web là credible. Train **không có** XSS hay SQLi credible. Web F1 0.769 được đo trên flow không credible. Các số F1 lớp hiếm trong `RESULTS_FINAL.md` vì thế đo khả năng **tái tạo nhãn NF-v3**, không đo khả năng phát hiện XSS hay SQLi thật.
3. **FP trên ngày Bot** là FP thật so với kịch bản, nhưng nguyên nhân là **nhãn train sai** (traffic nền UDP/500 bị gắn nhãn web).

Hướng tiếp theo: [`history/NEXT_RESEARCH_DECISION.md`](history/NEXT_RESEARCH_DECISION.md) (superseded by [`DATA_SUFFICIENCY_DECISION.md`](DATA_SUFFICIENCY_DECISION.md)).
