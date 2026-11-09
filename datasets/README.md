# Datasets

This folder holds the raw, read-only source data for Netirava. It is excluded from Git (`datasets/` in `.gitignore`). Do not edit or add derived files here; derived outputs go to `artifacts/` and `runs/`.

## 1. Where to download

| Dataset | Used for | Download / record | Size |
|---|---|---|---|
| **NF-CSE-CIC-IDS2018-v3** | Primary CIC model, demo, all CIC holdouts | UQ eSpace record: https://espace.library.uq.edu.au/view/UQ:ece9b83 (RAiD https://hdl.handle.net/102.100.100/602564) | CSV 4,222,783,755 bytes |
| **NF-ToN-IoT-v3** | Supplementary ToN-IoT model | UQ eSpace record: https://espace.library.uq.edu.au/view/UQ:44d7c5e · dataset record: https://researchdata.edu.au/nf-ton-iot-v3/3485175 | CSV 5,302,886,266 bytes (zip 417 MB) |
| **NF-UNSW-NB15-v3** | External transfer evaluation (frozen CIC checkpoints) | UQ NIDS catalog: https://staff.itee.uq.edu.au/marius/NIDS_datasets/ | CSV 577,360,958 bytes |

Catalog and background: [UQ NetFlow datasets](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) and the NetFlow v3 paper, Luay et al., https://arxiv.org/abs/2503.04404.

Source terms and licensing are stated on each UQ record. Check them before redistributing any raw or derived data.

## 2. Where to place them

Paths below are the ones the configs and code read. Keep the BagIt folder names exactly as they are.

```
datasets/
├── README.md
├── NF-CSE-CIC-IDS2018-v3/
│   └── f78acbaa2afe1595_NFV3DATA-A11964_A11964/      # BagIt bag, unzipped as downloaded
│       ├── bag-info.txt, bagit.txt, manifest-sha1.txt, tagmanifest-sha1.txt, FurtherInformation.txt
│       └── data/
│           ├── NF-CICIDS2018-v3.csv                  # used by configs/demo.yaml, ops_holdout.yaml, fe_study.yaml
│           └── NetFlow_v3_Features.csv
├── NF-ToN-IoT-v3/
│   ├── NF-ToN-IoT-v3.csv                             # used by configs/ton_iot.yaml
│   ├── NetFlow_v3_Features.csv
│   └── bag-info.txt, bagit.txt, manifest-sha1.txt, tagmanifest-sha1.txt, FurtherInformation.txt
└── NF-ToN-IoT-v3.zip                                 # original download archive (optional; keep for provenance)
```

**UNSW is not inside this folder.** `src/netirava/external.py` reads it from a path outside the repository:

```
D:\Downloads\DataNova\GraphIDS\data\NF-UNSW-NB15-v3\NF-UNSW-NB15-v3.csv
```

That is `../GraphIDS/data/NF-UNSW-NB15-v3/NF-UNSW-NB15-v3.csv` relative to the Netirava root. If you keep UNSW elsewhere, change `CSV` in `src/netirava/external.py`.

Keep `NetFlow_v3_Features.csv` next to each CSV. It is the feature schema shipped with each bag.

## 3. Verify the files

Compute each CSV's SHA-1 and compare it with the value in the `manifest-sha1.txt` that ships in its bag. On Windows:

```powershell
certutil -hashfile "datasets\NF-ToN-IoT-v3\NF-ToN-IoT-v3.csv" SHA1
```

| File | Rows / flows |
|---|---|
| `NF-CICIDS2018-v3.csv` | 20,115,529 flows, 55 columns |
| `NF-ToN-IoT-v3.csv` | 27,520,260 flows |
| `NF-UNSW-NB15-v3.csv` | 2,365,424 flows; 2,350,609 after exact deduplication |

A mismatch means the file differs from the one used in the experiments, and results will not reproduce.

## 4. Notes

- Raw files are read-only inputs. Do not sort, re-save, or edit them in place.
- The CIC bag is extracted; the matching zip is not stored here.
- Download size is about 4 GB for CIC and about 5.3 GB for ToN, so allow disk space for both extracted CSVs.
- Reproduction steps and the artifacts needed beyond these raw files: [docs/reproduction.md](../docs/reproduction.md). Data quality notes: [docs/data_quality.md](../docs/data_quality.md).
