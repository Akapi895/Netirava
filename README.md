# Netirava MVP

Một IDS dựa trên **flow đã hoàn tất**, chạy bằng **dataset replay**. Gồm một detector có giám sát (**A0**, CatBoost theo công thức anchor NP-v1, train lại trên CIC-2018) ở chế độ active, và một **IsolationForest** ở chế độ **shadow** (chỉ quan sát). Phản ứng chỉ là mô phỏng (incident/notification); không block, không quarantine, không tự train lại.

- Dataset và subset: [`docs/DATASET_CARD.md`](docs/DATASET_CARD.md)
- Kiến trúc: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Model: [`docs/MODEL_CARD_A0.md`](docs/MODEL_CARD_A0.md)
- Kết quả: [`docs/RESULTS_MVP.md`](docs/RESULTS_MVP.md)
- Test: [`docs/TEST_REPORT.txt`](docs/TEST_REPORT.txt)

## Cài đặt (Windows, PowerShell)
```powershell
cd D:\Downloads\DataNova\Netirava
uv sync                       # Python 3.12; versions pinned in pyproject.toml / uv.lock
.venv\Scripts\python.exe -m pytest -q
```
- Dataset gốc nằm ở `datasets/` (ngoài git, chỉ đọc); đường dẫn khai báo trong `configs/demo.yaml`.
- Dữ liệu dẫn xuất, model và run nằm trong `artifacts/` và `runs/` (ngoài git).
- A0 kế thừa `../experiments/nextphase/configs.yaml` (NP-v1) nếu file đó tồn tại.

## Các lệnh đã chạy thật (2026-11-08)
```powershell
$py = ".venv\Scripts\python.exe"
& $py -m netirava inspect --config configs/demo.yaml          # 77 s: sha1, schema, hourly class counts
& $py -m netirava prepare --config configs/demo.yaml          # 74 s: 2,973,401 flows -> stream/truth/manifest
& $py -m netirava audit   --config configs/demo.yaml          # host overlap, fingerprint overlap, collisions
& $py -m netirava train-a0 --config configs/demo.yaml         # GPU, ~15 s fit; threshold on calibration
& $py -m netirava replay --config configs/demo.yaml --mode a0
& $py -m netirava train-anomaly --config configs/demo.yaml    # IsolationForest on train benign (200k sample)
& $py -m netirava replay --config configs/demo.yaml --mode a0-shadow
& $py -m netirava replay --config configs/demo.yaml --mode a0-shadow --pace paced --speed 60 --segments R1_0302_bot --max-events 30000
& $py -m netirava evaluate --run 20261108T110215_a0-shadow_fast
& $py -m netirava incidents --run 20261108T110255_a0_fast --limit 5
& $py -m netirava feedback --run 20261108T110255_a0_fast --alert-id 1 --status true_positive --source agent --confirmed-by demo-operator --corrects 2 --provenance demo
```
- Mỗi lệnh `replay` tạo một run mới, `runs/<run_id>/`, gồm `run.json`, `detections.parquet` và `alerts.db`. Đây cũng là cách resume duy nhất: chạy lại thành run mới, không skip theo file đã tồn tại.
- `evaluate` ghi `EVALUATION.json` và `episodes.csv` vào thư mục của run.

## Ranh giới
- **Model input:** 49 feature trong allowlist (giữ port, TTL, DNS id). Không bao giờ dùng IP, timestamp tuyệt đối, nhãn, role hay scenario.
- **Nhãn** chỉ nằm trong `truth.parquet` và chỉ được đọc bởi `evaluation`/`audit`.
- **`attack_score = 1 − p(Benign)`** là score để ra quyết định, không phải xác suất đã calibration.
- **Shadow** không ảnh hưởng tới quyết định active (có test). Không có fusion giữa hai nhánh.
