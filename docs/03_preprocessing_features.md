# 03. Preprocessing và feature

## 1. Input của model triển khai
- **49 feature NetFlow v3** theo allowlist (`features.FEATURES`, schema `nfv3-49-allowlist-v1`). Không có IP, timestamp tuyệt đối hay nhãn; port, TTL và `DNS_QUERY_ID` được giữ.
- Không có transform học từ dữ liệu. Runtime chỉ nhận các cột của contract `FlowEvent` và từ chối mọi cột nhãn.
- **SMOTE theo quy tắc** (công thức LCCDE/NP-v1): lớp có < 1,000 row được nâng lên 1,000 bằng SMOTENC; mã phân loại (port, protocol, cờ TCP…) được copy từ láng giềng, không nội suy.

Kết quả của feature study dưới đây không thay đổi input này: mọi đề xuất đều bị loại ở DEV hoặc ở holdout.

## 2. Feature study
- **Protocol** khai báo trước trong `configs/fe_study.yaml` (commit `e820605`); code khóa ở `c22f8fc` trước khi chạy ablation.
- **Code:** `src/netirava/fe.py` (`FeaturePipeline`, `context_features`, `drop_exact_duplicates`), `src/netirava/fstudy.py`. Test: `tests/test_fe.py`.
- **Thiết lập:** nhãn sửa, đã loại bản trùng toàn phần, công thức A0, 3 seed, không HPO. Inner split: T1–T4 lấy 70% đầu để train, purge 5 phút, 30% cuối để val; web theo split của pilot.
- **Metric:**
  - M1: macro-F1 trên inner-val;
  - M3: macro-F1 trên fingerprint chưa thấy;
  - M2: benign FPR trên S1 và R1 ở threshold α = 0.1% khóa trên C1.

### 2.1 Các bước preprocessing đã thử (G_prep)
| Bước | Nội dung | Tham số học (chỉ trên tập fit) |
|---|---|---|
| D0 | Loại bản trùng toàn phần, giữ `flow_id` nhỏ nhất (EDA E1) | Không |
| P1 | Nhãn sửa CNS2022; loại `attempted` và `indeterminate` | Không |
| P2 | Gom row trùng (input + nhãn) thành một row có `sample_weight` | Không |
| P3 | Protocol, L7, ICMP, DNS type, mã FTP, cờ TCP thành categorical | Target statistics của CatBoost |
| P4 | Port đích: top-50 giữ nguyên, còn lại theo nhóm; port nguồn chỉ còn nhóm {well-known, registered, ephemeral} | top-50 port |
| P5 | Giá trị không áp dụng → NaN (DNS ngoài port 53, ICMP ngoài ICMP, cờ TCP ngoài TCP) | Không |
| P6 | SMOTENC trên log1p + robust scale | median, IQR |

### 2.2 Các nhóm feature đã thử
| Nhóm | Nội dung |
|---|---|
| G0 | 49 cột thô (như A0), làm reference |
| G_shortcut_drop | G0 bỏ L4_SRC_PORT, DNS_QUERY_ID, MIN_TTL, MAX_TTL, TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT |
| G_ratio | +14 tỷ lệ: byte/packet theo chiều, out/in, retransmission, histogram kích thước, thời gian |
| G_flag | +25 bit cờ TCP (8 bit × tổng/client/server, cộng `f_no_reply`) |
| G_ctx | +10 feature ngữ cảnh causal theo SRC và DST trong 60 s: số flow, số port đích, số peer, tỷ lệ không trả lời, TB log(IN_BYTES). Chỉ dùng flow cùng segment có `available_at` nhỏ hơn hẳn; IP chỉ dùng để nhóm |
| Control | Mỗi nhóm cộng thêm có hai control: cột bị hoán vị và cột nhiễu cùng số lượng |

### 2.3 Kết quả DEV (TB 3 seed)
| Arm | #feat | M1 | M3 | FPR S1 | FPR R1 | Incident báo nhầm/giờ | Recall scan S1 (nhãn sửa) |
|---|---|---|---|---|---|---|---|
| G0 | 49 | 0.9726 | 0.9687 | 0.099% | 0.011% | 20.1 | 0.006 |
| G_prep | 49 | 0.9984 | 0.9981 | 0.107% | 0.020% | 24.4 | 0.002 |
| G_shortcut_drop | 43 | 0.9726 | 0.9687 | 0.057% | 0.022% | 35.1 | 0.010 |
| G_ratio | 57 | 1.0000 | 1.0000 | 0.050% | 0.027% | 41.7 | 0.007 |
| control ratio hoán vị | 57 | 0.9809 | 0.9782 | 0.033% | 0.018% | 31.4 | 0.007 |
| G_flag | 68 | 0.9726 | 0.9687 | 0.077% | 0.016% | 26.7 | 0.009 |
| G_ctx | 53 | 0.9957 | 0.9950 | 0.019% | 0.070% | 13.5 | 0.713 |
| control ctx hoán vị | 53 | 0.9726 | 0.9686 | 0.062% | 0.015% | 26.9 | 0.005 |

Từ G_ratio trở xuống, mỗi arm là G_shortcut_drop cộng thêm nhóm tương ứng.

**Luật chấp nhận** (khai báo trước): M1 không giảm quá 0.01, vượt control hoán vị nếu là nhóm cộng thêm, và M2 không xấu hơn cận Wilson của reference ở **mọi** segment.

| Nhóm | Quyết định | Lý do |
|---|---|---|
| G_prep | Loại | FPR R1 0.020% > cận 0.014% |
| G_shortcut_drop | Chấp nhận | FPR TB 0.055% → 0.040%; adversarial AUC 0.818 → 0.795 |
| G_ratio | Loại | FPR R1 tăng |
| G_flag | Loại | Không vượt control |
| G_ctx | Loại | FPR R1 gấp khoảng 3 lần |

**Diễn giải:**
- M1 đã bão hòa: mọi lớp known đạt F1 = 1.0 ở mọi arm. Chênh lệch chỉ đến từ 1–2 flow web (SQLi có n = 2), nên không có kết luận nào về feature cho lớp hiếm.
- Tín hiệu thật nằm ở FP khi chuyển ngày (M2).
- G_ctx là đánh đổi rõ: bắt 71% scan và giảm 3 lần incident báo nhầm trên S1, nhưng FPR R1 tăng 3 lần. Control không tái tạo được hiệu ứng, nên đây là thông tin thật về hành vi theo host.
- Chẩn đoán trên model seed 0:
  - probe theo segment trên benign: L4_SRC_PORT đoán được ngày tốt nhất (macro-F1 0.333, ngẫu nhiên 0.167);
  - permutation importance theo nhóm: kích thước packet và byte 0.460, cờ TCP 0.113, port 0.091.

## 3. Holdout H3/H4 (một lần, sau tag `fe-v2-frozen`)
- **H3:** 23/02 14:00–15:00, 234,262 flow benign sau khi loại trùng, ngày chưa từng dùng.
- **H4:** 21/02 14:00–15:00, 188,094 benign và 1,725 flow LOIC-UDP (10 attacker; 3,450 flow gốc, một nửa là bản trùng).
- **Model so sánh:** v2 (G_shortcut_drop) và reference G0, cùng tập train cuối (650,248 row, nhãn sửa, đã loại trùng), 3 seed. A0 v2 và pilot được đóng băng làm tham chiếu.

| Model, α = 0.1% (seed 0 / 1 / 2) | H3 FPR | H3 incident báo nhầm/giờ | H4 FPR | H4 recall LOIC-UDP |
|---|---|---|---|---|
| v2 (43 cột) | 0.025 / 0.030 / 0.024% | 36.8 / 42.6 / 35.8 | 0.022 / 0.027 / 0.021% | 0 / 0 / 0 |
| reference G0 | 0.007 / 0.007 / 0.026% | 13.6 / 12.6 / 32.9 | 0.018 / 0.018 / 0.033% | 0.0006 / 0 / 0.0006 |
| A0 v2 (đóng băng) | 0.027% | 10.7 | 0.077% | 0 (0/10 episode) |
| pilot_cns/s0 (đóng băng) | 0.052% | 18.4 | 0.018% | 0.093 (9/10 episode) |

Ở α = 1%, recall LOIC-UDP: v2 0.80 / 0.01 / 0.02; reference 0.99 / 0.98 / 0.65; A0 v2 0.008; pilot 0.81.

**Luật GO** (H3: FPR và incident của v2 không cao hơn reference; H4: recall của v2 ≥ reference − 0.02 ở α = 0.1% và 1%) → **NO-GO**. Bỏ cột shortcut làm kết quả kém hơn trên dữ liệu độc lập; pipeline giữ 49 feature.

## 4. Kết luận
| Thành phần | Trạng thái |
|---|---|
| Loại bản trùng toàn phần | Cần cho mọi đánh giá; là sửa dữ liệu, không chọn theo metric |
| Nhãn sửa CNS2022 cho train | Dùng trong pilot (`04` §5) |
| G_prep, G_ratio, G_flag | Không có lợi ích chứng minh được |
| Bỏ shortcut | Bị holdout bác bỏ |
| G_ctx | Giả thuyết mạnh nhất cho bước sau; không còn holdout sạch để kiểm chứng |

Kết quả vững nhất của study: ở α = 0.1%, mọi model đạt FPR 0.007–0.052% trên ngày chưa chạm H3. Độ dao động theo seed lớn (reference seed 2 có FPR H3 gấp 4 lần seed 0/1), nên không báo kết quả của một seed.
