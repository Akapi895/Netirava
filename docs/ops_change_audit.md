# Audit thay đổi của ops study

**Phạm vi:** nhánh `feat/incident-correlation-drift-monitoring` tại `26fab5d`, so với `master` (`b900099`, merge-base). Audit chỉ đọc: không train, không sửa model hay config.

**Bằng chứng:** `runs/ops_study/AUDIT_INVARIANCE.json`, sinh bởi `runs/ops_study/audit_inv.py` (ngoài git).

## Kết luận
| Hạng mục | Kết luận | Căn cứ |
|---|---|---|
| Training invariance | **PASS** | Không có lệnh train, fine-tune, SMOTE hay calibration nào chạy; code training và preprocessing không đổi; file model và dữ liệu train trùng hash đã ghi trước nhánh (§2) |
| Inference invariance (cùng model, cùng input) | **PASS** | Score, xác suất, argmax, alert, source incident và trường family-aware trùng tuyệt đối trên 1,669,430 flow (§3) |
| Hành vi mặc định | **Thay đổi, ngoài phạm vi** | `replay` không có `--model` dùng `pilot_cns/s0` thay vì A0 v2. Đây là thay đổi duy nhất làm đổi output detection (§5) |
| Lớp trình bày | Thay đổi, không chạm detection | Severity family-aware lấy max theo flow; top-B của UI theo hàng xem xét causal (§4) |

## 1. File thay đổi
| Nhóm | File | Chạm detection? |
|---|---|---|
| Module mới | `campaign.py`, `drift.py`, `ops.py` | Không (chỉ đọc output của detector; `drift` chỉ được import bởi `cli.py` và `ops.py`) |
| Sửa | `replay.py`: +17 dòng, ghi cột `campaign_id` sau khi score, alert, policy và family đã xong | Không |
| | `family.py`: thêm `flow_severity`; `annotate`, `settings`, `incident_labels` không đổi | Không |
| | `triage.py`, `app.py`: view, export, UI | Không |
| | `cli.py`: lệnh mới; default của `replay --model` đổi từ `"a0"` sang `final_system.model_dir` | **Có, gián tiếp** (§5) |
| Config | `configs/demo.yaml`: thêm section `ops`, `family.severity`, 2 khóa taxonomy (HOIC, LOIC-UDP → DDoS), `final_system.model_dir` | Chỉ `model_dir` |
| | `configs/ops_holdout.yaml` (mới, H5–H9) | Không |
| Test | `tests/test_ops.py` (11 test mới) | — |

So sánh YAML theo section: `a0`, `anomaly`, `dataset`, `paths`, `windows`, `replay`, `policy`, `triage`, `decision`, `evaluation` không đổi. Hai khóa taxonomy mới không phải known class nên không bao giờ là argmax; `family.severity` không được `annotate` đọc.

Code không đổi (git diff rỗng): `detectors.py`, `features.py`, `dataset.py`, `relabel.py`, `pilot.py`, `fe.py`, `fstudy.py`, `policy.py`, `decision.py`, `evaluation.py`, `storage.py`, `config.py`, test cũ.

## 2. Artifact bất biến
Mốc: commit đầu tiên của nhánh `e1b473a`, 2026-11-08 18:51:48 +0700.

| Artifact | sha1 | Đối chiếu | mtime |
|---|---|---|---|
| `models/a0/a0.cbm` | `f32899bde8b4ade3…` | = `model_hash` trong meta (sha1 lúc train) = run trước nhánh `20261108T143728`; threshold 0.8678725413804724 khớp | 12:24 |
| `models/pilot_cns/s0/a0.cbm` | `f964bde1ef5ced86…` | = meta = run trước nhánh `20261108T143803`; threshold 0.00924223068597019 khớp | 14:07 |
| `models/calibration_scores.parquet` | `6c38b9093b22` | — | 12:28 |
| `cic18_causal_demo_v1/stream.parquet` | `b7e43a671687` | = registry trên `master` | 13:16 |
| `cic18_causal_demo_v1/truth.parquet` | `4bb8de42532d` | = registry trên `master` | 13:16 |
| `cic18_causal_demo_v1/truth_cns2022.parquet` | `ff679256a42c` | = registry trên `master` | 14:05 |

File ghi trong `artifacts/` sau mốc:
- `drift_reference.json` trong `models/a0/` và `models/pilot_cns/s0/`: file mới; `A0.load` chỉ đọc `a0.cbm` và `a0_meta.json`. Threshold trong file được tính lại bằng `threshold_at_fpr` và có assert bằng threshold đã khóa.
- `ops_holdout_v1/*`: derived riêng cho H5–H9, không phải dữ liệu train.

Log (`runs/logs/ops_*.log`) chỉ có `drift-reference`, `replay`, `ops-study`, `prepare`/`relabel` cho `ops_holdout.yaml`, `export`, `registry`.

## 3. Inference invariance
| So sánh | Flow | max \|Δ score\| | Xác suất (8 cột) | `a0_pred`, alert, action | Source incident | Family-aware (6 trường) |
|---|---|---|---|---|---|---|
| A. A0 v2: code `master` (`143728`) và code nhánh (`190136`) | 1,669,430 | 0.0 | trùng | trùng (166,636 alert) | id trùng (238) | trùng |
| B. Pilot: `143803` và `190143`, trên K5 + R1 | 977,200 | 0.0 | trùng | trùng (244 alert) | phân hoạch trùng (68)¹ | trùng |
| C1. A0 v2, code nhánh: bật và xóa hẳn section `ops` | 1,669,430 | 0.0 | trùng | trùng | id trùng (238) | trùng |
| C2. Pilot: bật và tắt `ops` | 1,669,430 | 0.0 | trùng | trùng (164,876 alert) | id trùng (141) | trùng |

¹ Run cũ chỉ có K5 + R1 nên id đánh số lệch; kiểm tra là ánh xạ một-một giữa id cũ và mới.

- `active_decisions_sha1`: A và C1 `1c7b4b31…`, C2 `8eaccddf…`, giống nhau ở hai phía.
- Cột duy nhất khác giữa bật và tắt là `campaign_id`.
- Benign FPR tính lại từ từng run trùng tới 4 chữ số (A0 v2: 0.0366%, 0.5978%, 0.0815%; pilot: 0.0268%, 0.1091%, 0.0115%).
- Monitor không ghi vào output của detector: `detections.parquet` và `alerts.db` của run `190136` giữ mtime lúc replay dù monitor chạy sau; bảng `incidents` có đúng 238 row.

## 4. Thay đổi ở lớp trình bày
| Thay đổi | Định lượng trên DEV |
|---|---|
| Severity incident: từ `severity[lớp argmax phổ biến nhất]` sang max severity family-aware theo flow | A0 v2: 0/238 đổi. Pilot: 6/141 đổi (5 incident 3 → 4 vì có flow argmax Benign; 1 incident 4 → 5 vì có flow SQLi phát nhãn mịn). 9 incident uncertain của A0 v2 đều có severity 4 |
| Top-B mỗi giờ trên UI: từ sắp theo tổng flow (dùng cả flow sau giờ xem) sang hàng xem xét causal | Top-10/giờ khác 18/107 (A0 v2) và 9/90 (pilot) incident |
| `notified` hiển thị tách khỏi queue rank | Giá trị `notified` không đổi (217 notified, 21 bị chặn) |

Số triage lịch sử (`decision.triage_metrics`) không đổi vì `decision.py` không bị sửa.

## 5. Đổi model mặc định
- **Nguồn gốc:** pre-registration của ops study tự thêm RQ-M, một luật chọn model, vì holdout mới là đánh giá độc lập đầu tiên của pilot. Luật đạt, nên `final_system.model_dir` được đặt `pilot_cns/s0` và default của CLI được đổi theo.
- **Phạm vi:** việc chọn model không thuộc yêu cầu "hai tính năng bổ trợ". Đây là thay đổi ngoài phạm vi; quyết định cuối thuộc người dùng.
- **Ảnh hưởng:** đây là thay đổi duy nhất làm đổi output detection. Khi truyền `--model` tường minh, output giống `master`. Lệnh cũ không ghi `--model` giờ chạy pilot.
- **Hoàn tác nếu cần:** xóa `final_system.model_dir`; CLI rơi về `a0`, không cần sửa code.

### 5.1 Đánh đổi khi chuyển từ A0 v2 sang pilot (α = 0.1%)
| Khía cạnh | A0 v2 | Pilot | Loại |
|---|---|---|---|
| Lớp hiếm, nhãn gốc (K5): recall Web / XSS / SQLi | 0.404 / 0.763 / 0.817 | 0.057 / 0.160 / 0.217 | DEV |
| Lớp hiếm, nhãn sửa: F1 Web / XSS / SQLi | 0.52 / 0.00 / 0.12 | 0.98 / 1.00 / 1.00 (n = 2; K5 trùng phần train của pilot) | DEV |
| Benign FPR trong phạm vi máy chủ web (nhãn sửa) | 47.7% | 0 | DEV |
| Known K1–K4 recall (FTP, SSH, GoldenEye, Slowloris) | 1.00 / 1.00 / 1.00 / 0.939 | 1.00 / 1.00 / 1.00 / 0.965 | DEV |
| Bot | 0 | 0 | DEV |
| HOIC (H5) | 0.036 | 0.813 | HO |
| Portscan (S1, nhãn sửa) | 0.061 | 0.005 | DEV |
| Infilteration S1 / H6 | 0.010 / 0.194 | 0.003 / 0.012 | DEV / HO |
| FPR known / S1 gốc / S1 sửa / R1 | 0.037 / 0.598 / 0.105 / 0.081% | 0.027 / 0.109 / 0.093 / 0.012% | DEV |
| FPR gộp H5–H9 | 0.085% | 0.065% | HO |
| FPR α = 0.5%, H7 / H8 | 0.231 / 0.386% | 0.510 / 0.575% | HO |
| Source incident báo nhầm/giờ: known / S1 / R1 | 2.7 / 41.0 / 5.6 | 4.5 / 16.0 / 11.4 | DEV |
| Source incident báo nhầm/giờ, H5–H9 | 24.1 | 15.9 | HO |
| LOIC-UDP H4 | 0/10 episode | 9/10 episode | HO |

H1 và H2 chưa được đánh giá với pilot (holdout đã dùng).

## 6. Thay đổi ngoài phạm vi hai tính năng
| # | Thay đổi | Ảnh hưởng |
|---|---|---|
| O1 | Model mặc định (`final_system.model_dir`, default `--model`) | Detection của `replay` không có `--model` |
| O2 | Tài liệu mô tả pilot là lựa chọn được khuyến nghị | Thông điệp nộp bài |
| O3 | Severity family-aware và top-B causal trên UI (P1.1 của kế hoạch hoàn thiện) | Trình bày |
| O4 | `notified` tách khỏi `queue_rank_*`, thêm `severity_source` | Trình bày |
| O5 | Hai khóa taxonomy mới | Chỉ báo cáo |
| O6 | Tiêu thụ holdout H5–H9 | Không còn dùng được làm holdout độc lập |
| O7 | `drift_reference.json` nằm trong thư mục model | Không ảnh hưởng load model |
| O8 | Push nhánh và tag lên `origin` theo yêu cầu của người dùng | Chỉ nhánh mới, không chạm `master` |

## 7. Tái lập
```powershell
git diff --stat master...26fab5d -- src/netirava/detectors.py src/netirava/features.py src/netirava/dataset.py src/netirava/relabel.py src/netirava/pilot.py src/netirava/fe.py src/netirava/policy.py src/netirava/decision.py src/netirava/evaluation.py
.venv\Scripts\python.exe runs/ops_study/audit_inv.py
```
