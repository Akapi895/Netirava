# Reproduction and artifact handoff

## 1. Choose the required level

| Level | Requirements | Fitting? |
|---|---|---|
| Code tests | Repository, Python 3.12, locked dependencies | Small synthetic fixtures only |
| Read submission results | Markdown and `ton_iot_evidence.json` | No |
| UI / reporting from saved scores | Checkpoint, derived stream/truth, run outputs, manifests | No |
| Replay a checkpoint | Checkpoint and matching derived stream/config, fresh run ids | No fit; inference occurs |
| Repeat from raw | Raw CSV, recipe, preparation, suitable GPU | **New fitting experiment** |

No new fit is needed to verify reported numbers. Reusing consumed holdouts does not create independent evidence.

## 2. Environment

```powershell
uv sync --locked
$py = ".venv\Scripts\python.exe"
& $py -m pytest -q
& $py -m netirava --help
```

`uv.lock` pins packages. ToN's recipe uses GPU; inspect original model metadata for hardware and resolved parameters. GPU fits may not produce bit-identical checkpoints across repetitions. The approximately 84-second ToN fit was measured on an RTX 4060 Laptop, not guaranteed elsewhere.

## 3. External artifact bundle

Preserve relative paths expected by configs:

| Purpose | Required files |
|---|---|
| CIC DEV UI | `artifacts/cic18_causal_demo_v1/{manifest.json,stream.parquet}`, `artifacts/models/pilot_cns/s0/{a0.cbm,a0_meta.json}`, `runs/20261108T190143_a0_fast/` |
| CIC evaluation | Add original/adapted truth, baseline `artifacts/models/a0/`, `artifacts/ops_holdout_v1/`, and ledger-listed baseline/final runs |
| ToN UI | `artifacts/ton_iot_v1/{manifest.json,stream.parquet}`, `artifacts/ton_iot_v1/models/a0/`, `runs/ton_iot/ton_X09_mitm/` |
| `ton-report` | Checkpoint/meta, manifest, stream/truth, and detections/run metadata for all nine `ton_X*` runs |
| Historical evidence | `SPLIT_AUDIT.json`, `FROZEN_PLAN.json`, raw before/after manifests, original evaluation/sensitivity/ledger/UI reports; these are not all runtime inputs to `ton-report` |
| Original documents | `artifacts/documentation_originals/`, mapped by [originals manifest](protocols/originals_manifest.json); needed for byte-level frozen-protocol comparison |

Runs contain `run.json`, `detections.parquet`, and `alerts.db`; monitor display needs `DRIFT_MONITOR.parquet`. Keep the `ui-smoke-test` feedback provenance rather than rewriting append-only history.

### Packaged bundle

`scripts/artifact_bundle.py` packs and installs the rows of the table above that the README flow needs: CIC DEV UI, ToN UI, `ton-report`, the ToN historical manifests, and the original-document archive. Run `build --output <zip>` in the checkout that holds the artifacts; run `install <zip>` in a fresh clone, then `check`.

- `BUNDLE_MANIFEST.json` inside the zip lists every file with size and SHA-256 and the repository commit it was built from. `install` verifies each file while extracting and aborts on a mismatch or an unsafe path.
- `install` never overwrites a file that differs from the bundle unless `--force` is given. `alerts.db` files hold append-only UI feedback: they are kept as they are and ignored by `check`.
- Not included: raw CSVs, `artifacts/ton_iot_v1/audit/` (about 380 MB of audit fingerprints), `*.log` (local paths), `catboost_info/`, and the local agent notes copy `artifacts/documentation_originals/CLAUDE.md`. CIC evaluation inputs (original/adapted truth, `artifacts/models/a0/`, `artifacts/ops_holdout_v1/`, ledger-listed runs) are also not included; add them for the CIC evaluation level.
- Verified on a clean clone of `master` plus the installed bundle: 56 tests pass with the ToN contract check running, `ui-check` passes for CIC and ToN, and `ton-report` reproduces `docs/ton_iot_evidence.json` except `config_sha1`, which records the hash of the currently opened `configs/ton_iot.yaml`.
- The bundle holds derived NetFlow records. Check the source terms before sharing it outside the intended audience.

Download/provenance: [UQ catalog](https://staff.itee.uq.edu.au/marius/NIDS_datasets/), [ToN record](https://researchdata.edu.au/nf-ton-iot-v3/3485175). Verify distribution rights before publicly bundling raw or derived data. Repository documentation does not grant a new dataset license.

## 4. Existing UI and non-writing headless check

```powershell
& $py -m netirava ui --config configs/demo.yaml --run 20261108T190143_a0_fast
& $py -m netirava ui --config configs/ton_iot.yaml --run ton_X09_mitm
& $py -m netirava ui-check --config configs/ton_iot.yaml --run ton_X09_mitm
```

`ui-check` runs Streamlit AppTest without saving feedback or reading truth for analyst decisions. It does not assess actual browser layout/usability. Use the matching config: stream provenance is checked, and runs under another config's directory are rejected.

Notification budget 30/hour is distinct from review budget ten/hour. “Configured rare-class incidents” refers to `a0.rare_classes`, not ground-truth support. The ToN historical placeholder contains ransomware/mitm, while the pre-sampling report definition also includes Backdoor.

## 5. Recompute ToN reports without fitting or inference

```powershell
& $py -m netirava ton-report
& $py -m netirava ton-report --output docs/ton_iot_evidence.json
```

Default run ids are `ton_<declared-test-window-id>`. The command checks checkpoint/schema, stream/truth checksums, run model/stream/threshold, stored gate, test role, and exactly-once full-test coverage. It computes threshold+argmax metrics **before family abstention**, plus novelty against all training hosts including benign/other classes. This additive report preserves original evaluator files.

To recompute originally declared metrics/bootstrap from saved scores, overwriting their corresponding report files:

```powershell
& $py -m netirava ton-evaluate
& $py -m netirava ton-sensitivity
```

Supply `--runs <id1> ... <id9>` for a fresh prefix. `ton-report` rejects partial-test results as a final pooled report.

## 6. Replay into fresh runs

```powershell
& $py -m netirava ton-replay --prefix verify
```

This uses the existing checkpoint and locked calibration rule, creates a reference only if missing, then replays/monitors each test window. It refuses existing run ids. Results are `verify_X01_scan` through `verify_X09_mitm`; provide all ids to evaluation. This is reproduction, not new independent testing.

For CIC development-only replay:

```powershell
& $py -m netirava replay --config configs/demo.yaml --mode a0 --run-id verify_cic_dev
& $py -m netirava ui --config configs/demo.yaml --run verify_cic_dev
```

Do not reopen historical holdouts for new method selection.

## 7. Starting a new experiment from raw

These commands write derived data and fit a model; they are **not** required for submission verification:

Before **any** audit/prepare command, create a separate configuration such as `configs/ton_iot_fresh.yaml` with fresh `paths.derived`, `paths.models`, and `paths.runs`. The filename below is illustrative and is not supplied by the repository. Preserve the existing config and artifacts; do not run preparation against their occupied namespaces. A newly designed experiment also needs its own protocol.

```powershell
$c = "configs/ton_iot_fresh.yaml"  # prepare this separate config and fresh paths first
& $py -m netirava ton-audit --config $c
& $py -m netirava ton-prepare --config $c
& $py -m netirava ton-split-audit --config $c
# Only for a separately authorized new fitting experiment:
& $py -m netirava ton-train --config $c
```

The current namespace has `FIT_STARTED.json` and refuses another fit. Preserve that marker/checkpoint. A genuinely new study needs a separate namespace/protocol. Historical CIC trainer fields are available in `configs/a0_reference.yaml` if the external NP-v1 file is missing; ToN uses its self-contained fixed recipe without a CPU probe.

## 8. Documentation migration and packaging

English documentation is a later consolidation/translation. [Protocol originals](protocols/README.md) explain which bytes were frozen at experimental time. Current English comment/path changes can alter config/source file hashes without altering parsed parameters, data, scores, or checkpoint bytes. Historical manifests remain untouched; reporting records the currently opened config rather than pretending its hash is the original fit hash.

Keep code/config/docs/small evidence in Git; keep large artifacts outside Git. Preserve original manifests, model metadata, hashes, logs, and protocols in the evidence bundle. Generate run inventories with `registry`: Markdown/JSON outputs go to the configured `runs/` directory, not into the curated docs. Perform tests, headless checks, and a browser walkthrough before presenting. Commit/push only on explicit request.
