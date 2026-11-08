# Đặc tả preprocessing và feature engineering (`fe-pipeline-v1`)

- **Code:** `src/netirava/fe.py` (`FeaturePipeline`, `context_features`, `drop_exact_duplicates`, `study_frame`) và `src/netirava/fstudy.py` (`fit_arm`, `_smote`).
- **Test:** `tests/test_fe.py`.
- **Giữ nguyên method:** CatBoost theo công thức A0 (NP-v1: 1000 iteration, GPU, learning rate cpu_auto_probe, SMOTE cho lớp < 1000 → 1000), threshold α = 0.1% trên benign của C1. Không HPO.

## Thứ tự xử lý
| Bước | Áp dụng cho | Nội dung | Tham số học (chỉ trên inner-train hoặc tập train cuối) |
|---|---|---|---|
| D0 Loại bản trùng toàn phần | Mọi row, mọi arm, mọi tập đánh giá, cả runtime | Bỏ flow trùng timestamp, IP, port và 49 feature; giữ `flow_id` nhỏ nhất (EDA E1) | Không |
| P1 Nhãn | Train và đánh giá | `label_corrected` (CNS2022). Row `attempted`/`indeterminate` bị loại khỏi train và chọn feature; báo riêng | Không |
| P2 Gom row trùng | Tập fit (arm có `prep`) | Row giống hệt input + nhãn → 1 row, `sample_weight` = số lần lặp | Không |
| P3 Kiểu dữ liệu | `prep` | PROTOCOL, L7_PROTO, ICMP_TYPE, ICMP_IPV4_TYPE, DNS_QUERY_TYPE, FTP_COMMAND_RET_CODE, TCP_FLAGS, CLIENT_/SERVER_TCP_FLAGS → `cat_features` của CatBoost (chuỗi, `"NA"` khi không áp dụng) | Không (target statistics của CatBoost được học trong lúc fit, chỉ trên tập fit) |
| P4 Port | `prep` | L4_DST_PORT: top-50 port của tập fit giữ nguyên làm category, còn lại thành `other_{wk,reg,eph}`. L4_SRC_PORT → nhóm `{wk, reg, eph}` | **top-50 port**, chỉ từ tập fit |
| P5 Giá trị không áp dụng → NaN | `prep` | DNS_* khi không có port 53; FTP_COMMAND_RET_CODE khi không có port 21; ICMP_* khi không phải ICMP (loại artefact E8); TCP_WIN và cờ TCP khi không phải TCP | Không |
| P6 SMOTE | Mọi arm (chỉ tập fit) | SMOTENC: copy categorical, không nội suy. Với `prep`: k-NN chạy trên log1p + robust scale (median, IQR), rồi biến đổi ngược. NaN được thay bằng sentinel trước, vùng sentinel đổi lại thành NaN sau | **median/IQR**, chỉ từ tập fit. Kế hoạch SMOTE tính trên số row có trọng số |

## Nhóm feature
| Nhóm | Cột | Ghi chú |
|---|---|---|
| G0 | 49 cột NetFlow v3 thô (như A0) | Baseline |
| G_ratio (`r_*`) | byte/packet theo chiều; tỷ lệ byte và packet out/in; tỷ lệ retransmission theo chiều; tỷ lệ histogram kích thước (5 mức); tỷ lệ thời gian in/out; tốc độ packet | Chia cho 0 → NaN |
| G_flag (`f_*`) | 8 bit (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR) × {tổng, client, server}; `f_no_reply` (OUT_PKTS = 0) | |
| G_shortcut_drop | Bỏ L4_SRC_PORT, DNS_QUERY_ID, MIN_TTL, MAX_TTL, TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT | Ứng viên shortcut (EDA E4, E5) |
| G_ctx (`ctx_*`) | Theo SRC và theo DST, cửa sổ 60 s: số flow, số port đích khác nhau, số peer khác nhau, tỷ lệ flow không có trả lời, trung bình log(IN_BYTES) | **Causal:** chỉ dùng flow cùng segment có `available_at` **nhỏ hơn hẳn**; reset ở ranh giới segment; IP chỉ dùng để nhóm, không thành feature |

## Bất biến (có test)
- Không cột nào trong `features.NEVER_INPUT` lọt vào input (assert trong `transform`).
- Tham số học (top-k port, scaler) chỉ đến từ `fit()`; đổi dữ liệu val không đổi state (`test_pipeline_learns_only_from_fit_frame...`).
- `FeaturePipeline({})` cho ma trận **trùng** với `features.matrix` của A0 (`test_g0_pipeline_equals_feature_matrix`).
- Feature ngữ cảnh: đổi dữ liệu tương lai không đổi feature quá khứ; không phụ thuộc thứ tự row; reset ở mỗi segment (`test_context_*`).
- SMOTE chỉ sinh row cho lớp có trong kế hoạch, và chỉ trong tập fit (`test_smote_only_adds_rows_of_planned_classes`).
- Loại bản trùng giữ bản đầu tiên (`test_exact_duplicates_keep_first_copy`).
- Holdout không thể vào study (`study_frame` assert, `load_stream(roles ≠ holdout)`).
