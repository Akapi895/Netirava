# Decision layer — kết quả dev và holdout (2026-11-08)

Luật chứng minh: [`RESEARCH_FRAMING.md`](RESEARCH_FRAMING.md) §6. Code: `src/netirava/decision.py`; tham số nằm trong `configs/demo.yaml → decision`.

**Trình tự (git):**

| Commit | Nội dung |
|---|---|
| `d8a846b` | Dọn repo |
| `e5336a8` | **Khóa phương pháp** (tham số V4 cố định), **trước** khi chạy holdout |
| commit này | Chạy holdout một lần, báo cáo |

**Run:**
- dev `20261108T114809_a0-shadow_fast` (`DECISIONS_dev.json`);
- holdout `20261108T115320_a0-shadow_fast` (`DECISIONS_holdout.json`), cùng model A0 `be8f6d84bf2d` và IsolationForest `2840a4698e7c`.

## Thiết lập
- **Đơn vị:** flow. Mọi biến thể được calibrate trên 278,255 flow benign của C1 ở **cùng FPR tổng** α ∈ {0.05%, 0.1%, 0.5%, 1%}.
- **Operating point chính** (khai báo trước, không đổi sau khi xem dev): **α = 0.1%**. Các mức khác là phụ.
- **Biến thể:**

| Biến thể | Luật alert |
|---|---|
| V1 | A0 |
| V2 | anomaly |
| V3 | A0 OR anomaly, mỗi nhánh được α/2 |
| V4a (thiết kế 1) | A0@α/2 OR [flow bất thường ở mốc top 1% **và** số flow bất thường của entity trong 60 s ≥ k] |
| **V4b (thiết kế 2, phương pháp đề xuất đã khóa)** | A0@α/2 OR [entity có ≥ 50 flow trong 60 s **và** trung bình anomaly score ≥ τ@α/2] |
| Ablation của V4b | cùng luật nhưng dùng A0 score; nhánh entity đứng một mình ở mức α |

- **Entity** là source IP. Thống kê theo cửa sổ được tính causal trong từng segment.
- **Cách chọn tham số:** grid và luật chọn khai báo trước, chỉ trên dev unknown (Bot, Web). Đã có **hai vòng thiết kế**:
  - V4a không cải thiện trên dev. Lỗi quan sát được: flow Bot có score cố định khoảng 0.538, nằm giữa mốc 90% và 95% của benign, nên không bao giờ lọt vào phần đuôi top 1%.
  - Từ lỗi đó, V4b được thiết kế và là vòng cuối cùng.
- **CI:** bootstrap theo episode (proxy: cùng nhãn và source IP, tách khi gap > 30 phút); FPR có Wilson trong file JSON.

## Dev (development unknowns: Bot, Web; stress Infiltration báo riêng)
| Scenario | Biến thể | α = 0.1%: recall · episode · FPR | α = 1%: recall · episode · FPR · Δ so với A0 [CI] |
|---|---|---|---|
| Bot (8 episode) | V1 A0 | 0.000 · 0/8 · 0.018% | 0.000 · 0/8 · 0.545% |
| | V3 OR | 0.000 · 0/8 · 0.053% | 0.000 · 0/8 · 0.729% |
| | **V4b** | 0.000 · 0/8 · 0.050% | **0.958 · 8/8 · 0.601% · +0.958 [+0.872, +0.994]** |
| | abl A0-score theo entity | 0.000 · 0/8 · 0.165% | 0.000 · 0/8 · 0.690% |
| Web (97 episode, support nhỏ) | V1 A0 | 0.006 · 2/97 · 0.007% | 0.366 · 26/97 · 0.542% |
| | **V3 OR** | 0.000 · 0/97 · 0.018% | **0.658 · 29/97 · 0.683% · +0.292 [+0.079, +0.527]** |
| | V4b | 0.000 · 0/97 · 0.064% | 0.355 · 24/97 · 0.542% · −0.011 [−0.024, −0.002] |
| Infiltration (stress, nhãn gắn cờ) | V1 A0 | 0.002 · 3/118 · 0.029% | 0.015 · 24/118 · 0.648% |
| | V4b | 0.001 · 1/118 · 0.115% | 0.031 · 12/118 · 0.731% |
| | abl A0-score theo entity | 0.139 · 1/118 · **3.53%** | 0.153 · 12/118 · **6.03%** |
| Known (within-episode) | V1 A0 | 0.999 · 4/4 · 0.025% | 1.000 · 4/4 · 0.637% |
| | V4b | 0.995 · 4/4 · 0.031% | 1.000 · 4/4 · 0.530% |

- Nhãn class (argmax của A0) không đổi ở mọi biến thể, nên known macro-F1 vẫn là 0.993.
- Ở α ≤ 0.5%, không biến thể nào có nhánh anomaly bắt được Bot.

## Holdout: DDoS LOIC-HTTP (H1, 20/02 14:05–14:35; 101,051 flow attack, 10 episode/attacker IP, 91,812 benign)
| Biến thể | α = 0.05% | **α = 0.1% (chính)** | α = 0.5% | α = 1% |
|---|---|---|---|---|
| V1 A0 | 0.000 · 0.036% | **0.000 · 0.122%** | 0.707 · 0.408% | 0.757 · 0.661% |
| V2 anomaly | 0.000 · 0.003% | 0.000 · 0.008% | 0.000 · 0.417% | 0.000 · 0.939% |
| V3 OR | 0.000 · 0.004% | 0.000 · 0.039% | 0.022 · 0.344% | 0.707 · 0.809% |
| V4a | 0.000 · 0.002% | 0.000 · 0.066% | 0.022 · 0.525% | 0.707 · 0.975% |
| **V4b (đã khóa)** | 0.000 · 0.078% | **0.000 · 0.112%** | **0.022** · 0.510% | **0.707** · 0.733% |
| abl V4b, A0-score theo entity | 0.776 · 0.002% | 0.780 · 0.036% | 0.977 · 0.222% | 0.996 · 0.593% |
| abl V4b, chỉ nhánh entity | 0.000 · 0.076% | 0.000 · 0.076% | 0.000 · 0.325% | 0.890 · 1.478% |

Mỗi ô ghi: recall flow · benign FPR thực tế trên holdout.
- Δ so với A0 ở α = 1%: V4b **−0.050 [−0.055, −0.044]**; V3 cũng −0.050.
- Ở α = 0.5%: V4b −0.685 [−0.700, −0.671].
- FPR thực tế của A0 ở α = 0.1% là 0.122%, hơi vượt mục tiêu (calibration đạt 0.0995%).

## Kết luận theo luật chứng minh
| Câu hỏi | Trả lời |
|---|---|
| Baseline bỏ sót gì? | Ở α = 0.1%, A0 bỏ sót **toàn bộ** Bot (dev), gần hết Web và Infiltration, và **toàn bộ DDoS holdout**. Ở α = 0.5–1%, A0 bắt được 71–76% DDoS, vì DDoS gần với các lớp DoS đã học; vẫn bắt 0% Bot |
| Phương pháp đề xuất (V4b) có cải thiện không? | **Không, trên holdout.** Ở α = 0.1% không có lợi ích. Ở α = 0.5% và 1%, V4b **kém hơn A0** (CI < 0), vì chia đôi ngân sách FPR làm nhánh A0 mất recall, trong khi nhánh anomaly không bắt được DDoS. Claim cải tiến **bị bác bỏ** |
| Lợi ích ở đâu? | Chỉ trên dev: V4b bắt 8/8 episode Bot ở α = 1% (A0 và OR: 0/8), với FPR 0.60%. Đây là development evidence: tham số được chọn trên chính Bot và Web |
| Trả giá gì? | V4b tăng FPR thực tế nhẹ ở một số scenario (ví dụ Infiltration 0.115% so với 0.029% ở α = 0.1%); chi phí shadow 3.7–10.8 µs/flow |
| Giới hạn | Mỗi family chỉ có một episode; cùng một testbed; Bot và Web vừa dùng để chọn tham số vừa dùng để báo cáo; budget theo flow (100 hoặc 1,000/giờ) quá nhỏ so với lưu lượng DDoS (khoảng 200k flow/giờ), nên recall@B gần 0 với mọi biến thể |

**Quan sát exploratory (KHÔNG phải claim):** ablation "A0-score theo entity" (trung bình `attack_score` của A0 theo source IP trong 60 s) bắt 78% DDoS holdout ở α = 0.1% với FPR 0.036%. Nhưng:
1. đây không phải phương pháp đã khóa; nâng nó lên sau khi đã xem holdout là chọn lọc hậu nghiệm;
2. trên dev, nó không bắt được Bot;
3. nó làm FPR của Infiltration vọt lên **3.5–6%**, gấp 35–60 lần mục tiêu, khi chuyển sang ngày 28/02.

Kết quả này chỉ đủ để làm một giả thuyết mới, cần holdout khác để kiểm chứng.

## Bước tiếp theo đề xuất (một bước, chưa thực thi)
Đăng ký trước một giả thuyết mới: "gom A0 score theo entity, kèm cơ chế chặn khi FPR bùng lên do dịch chuyển phân phối" (ví dụ giới hạn số alert mỗi entity, hoặc calibrate lại theo ngày bằng benign trước attack). Giả thuyết này được kiểm chứng trên **một holdout mới chưa từng chạm tới** trong NF-CSE-CIC-IDS2018-v3, ví dụ DoS-Hulk (16/02) hoặc DDoS LOIC-UDP (21/02). Không dùng HOIC, vì nó dùng chung 10 attacker IP với LOIC-HTTP.

Nếu thời gian không cho phép, câu chuyện nộp bài vẫn trung thực:
- **baseline bỏ sót gì:** unknown family ở FPR thấp;
- **xử lý ra sao:** anomaly gom theo host;
- **kết quả:** chỉ giúp cho kiểu C&C đều đặn (Bot), không giúp cho flood (DDoS);
- **cái giá:** chia ngân sách FPR làm giảm recall của A0;
- **giới hạn:** như bảng trên.
