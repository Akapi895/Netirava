# Corrected-label audit — CNS2022 rules applied to NF-CSE-CIC-IDS2018-v3 (2026-11-08)

**Script:** `src/netirava/relabel.py` (`python -m netirava relabel`).

**Output:** `artifacts/cic18_causal_demo_v1/truth_cns2022.parquet` (sha1 `ff679256a42c…`), kèm `truth_cns2022.summary.json`. Nhãn gốc `truth.parquet` **không bị đổi**. Mỗi flow có `label_original`, `label_corrected`, `status`, `confidence`, `rule`.

**Test:** `tests/test_pipeline.py::test_relabel_rules_basic` kiểm tra portscan, DHCP, cửa sổ web, UDP/500 background, indeterminate, not_audited, và việc giữ nhãn gốc.

**Nguồn luật:** Engelen et al., IEEE CNS 2022, [tài liệu CSE-CIC-IDS2018](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html).

## Phạm vi và trạng thái
- **Ngày được audit:** 22/02 (web), 28/02 (infiltration/portscan), 02/03 (bot). Luật được áp lên **mọi flow** của subset trong các ngày này, không chỉ các flow bị model cảnh báo.
- **Các ngày khác:** `not_audited`, giữ nhãn gốc.

| Status | Ý nghĩa | Số row |
|---|---|---|
| `not_audited` | Ngày ngoài phạm vi audit | 1,979,378 |
| `unchanged` | Đã audit, không luật nào áp dụng, giữ nhãn gốc | 1,006,929 |
| `confirmed` | Nhãn đặt theo luật tấn công của CNS2022 (cặp IP + cửa sổ thời gian, có thể kèm cổng) | 133,711 |
| `background` | CNS2022 ghi nhận mẫu này không phải tấn công (UDP/500, DHCP tới victim; ARP artefact) → Benign | 1,033 |
| `indeterminate` | NF-v3 gắn nhãn attack nhưng không luật nào xác nhận hay bác bỏ → **loại** khỏi train và eval | 18,336 |
| `attempted` | "Attempted" theo CNS2022 (giai đoạn khởi động, không payload, flow ngắn) → **loại** | 84 |

- Flow không khớp luật **không** bị tự động chuyển sang Benign. Chúng hoặc giữ nhãn gốc (`unchanged`), hoặc thành `indeterminate`.
- **Xấp xỉ có khai báo:** NetFlow không có độ dài payload, nên "zero forward payload" được xấp xỉ bằng `IN_PKTS ≤ 3` và `IN_BYTES ≤ 180`. Ngưỡng BF lấy theo CNS2022 (> 20 forward packet), áp lên `IN_PKTS` của NetFlow. Hai luật này có confidence `medium`.

## Chuyển nhãn (35,730 row thay đổi)
| Gốc → Đã sửa | Số row | Luật |
|---|---|---|
| Benign → **Portscan** | 12,633 | NMAP của .24 → host nội bộ (14:46:22–18:39:00 UTC, không tính src port 68) |
| Infilteration → **Portscan** | 3,585 | Như trên |
| Infilteration → Indeterminate | 17,082 | Không dính tới victim .24 hay attacker 13.58.225.34 |
| Benign → Infilteration | 2 | Giao tiếp C2 .24 ↔ 13.58.225.34 |
| Brute_Force_-Web → Indeterminate / Benign / Attempted | 1,254 / 249 / 61 | Không phải cặp attacker; UDP/500 hoặc DHCP; ngưỡng BF |
| Brute_Force_-XSS → Benign / Attempted / Web | 437 / 3 / 1 | UDP/500; payload; cửa sổ |
| SQL_Injection → Benign / **XSS** / Web / Attempted | 347 / **41** / 15 / 20 | UDP/500; **flow của attacker nằm trong cửa sổ XSS**; cửa sổ BF |
| Bot | 0 | **Toàn bộ 117,324 nhãn Bot khớp luật C2 18.219.211.138**: nhãn Bot của NF-v3 đúng |

## Support sau khi sửa (lớp hiếm, phạm vi máy chủ web)
| Lớp | Tổng (đã sửa) | Episode / attacker | Cửa sổ CNS2022 (UTC) |
|---|---|---|---|
| Brute_Force_-Web | 70 | 1 / 1 (18.218.115.60) | 14:17:51–15:23:59 |
| Brute_Force_-XSS | 80 | 1 / 1 | 17:51:39–18:29:41 |
| SQL_Injection | 17 | 1 / 1 | 20:16:30–20:27:56 |

**Chia train/eval hợp lệ không?** Mỗi lớp chỉ có **một episode, một attacker, một cửa sổ**, nên không thể chia theo episode độc lập.
- Pilot chia theo thời gian **bên trong** từng cửa sổ: 60% đầu dùng để train, 40% sau để eval. Đây là bằng chứng **within-episode**.
- SQLi chỉ có 17 flow (khoảng 10 train, 7 eval), dưới mọi ngưỡng tin cậy thống kê. Kết luận nào về SQLi cũng là **INCONCLUSIVE**.
- 28/02: Portscan có 16,218 flow nhưng không phải known class; nó chỉ đóng vai trò attack trong binary view với nhãn đã sửa.
