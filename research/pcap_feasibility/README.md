# RQ-PCAP feasibility study (độc lập với package Netirava)

**Câu hỏi:** thêm feature packet/protocol có giúp hơn so với chỉ dùng flow không?

**Kết luận: NO-GO trong thiết lập đã thử** (IoT-23, 3 capture). Không suy ra kết luận nào cho NF-CSE-CIC-IDS2018-v3. Lý do chi tiết ở [`PCAP_RESEARCH_DECISION.md`](PCAP_RESEARCH_DECISION.md).

| Tài liệu | Nội dung |
|---|---|
| [`DATA_ACCESS_REPORT.md`](DATA_ACCESS_REPORT.md) | Source A (CIC-2018 S3) và B (IoT-23): truy cập, kích thước, ngân sách, provenance |
| [`FEATURE_EXTRACTION_REPORT.md`](FEATURE_EXTRACTION_REPORT.md) | Join packet ↔ flow, coverage, artefact, shortcut, kiểm tra join NF-v3 |
| [`PCAP_FEASIBILITY_RESULTS.md`](PCAP_FEASIBILITY_RESULTS.md) | So sánh A / B / C, control, ablation, chi phí, giới hạn |
| [`PCAP_RESEARCH_DECISION.md`](PCAP_RESEARCH_DECISION.md) | Quyết định, 6 câu trả lời, deviation log |
| `config.yaml` | Protocol khóa trước (commit `2feaa35`) |
| `results/` | JSON kết quả gốc và `SUMMARY.md` |
| `logs/` | Log tải, trích xuất, đánh giá |

## Tái lập
```powershell
cd research\pcap_feasibility
uv sync                                                          # venv riêng (dpkt, catboost); không đụng .venv của Netirava
$py = ".venv\Scripts\python.exe"
& $py -m pytest -q -p no:cacheprovider tests                     # 9 test
& $py -I scripts\download.py                                     # ≈137 MB IoT-23 → data/ (gitignored); dừng nếu vượt ngân sách
foreach ($c in "CTU-IoT-Malware-Capture-20-1","CTU-IoT-Malware-Capture-8-1","CTU-IoT-Malware-Capture-34-1") { & $py -I scripts\extract_all.py $c }
& $py -I scripts\run_eval.py                                     # khoảng 20 phút CPU
& $py -I scripts\summarize.py
# Source A (tùy chọn): một member 9.6 MB, chỉ kiểm tra join
& $py -I scripts\cic2018_member.py Thursday-22-02-2018 pcap/UCAP172.31.69.28 15
& $py -I scripts\cic2018_join_check.py ..\..                     # đọc artifacts/ của Netirava, chỉ đọc
```
- **Thư mục gitignored:** `data/` (dữ liệu tải về, coi là untrusted) và `work/` (parquet feature).
