# Data quality and cohort eligibility

## 1. Sources and identifiers

| Source | Role | Size and provenance |
|---|---|---|
| NF-CSE-CIC-IDS2018-v3 | Primary CIC model/demo | 20,115,529 flows, 55 columns, 4,222,783,755 bytes; SHA-1 `ddcad6d826b73a128a447a0189137efd6c8f70c9`; BagIt match |
| NF-UNSW-NB15-v3 | Frozen-checkpoint transfer test | 2,365,424 flows; 2,350,609 after exact deduplication; two IXIA capture sessions |
| NF-ToN-IoT-v3 | Supplementary separately fitted model | 27,520,260 flows; SHA-1 `24854ca3072ab7c2ade9ebfb202345a666a94cfe`; BagIt match |

Original files are read-only. The 49 numeric model features exclude two IP columns, two absolute timestamps, `Label`, and `Attack`. Original class spellings, including `Infilteration`, remain unchanged in data and machine-readable outputs. Human-readable discussion may use the standard spelling Infiltration.

The [UQ catalog](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) and [NetFlow v3 paper](https://arxiv.org/abs/2503.04404) describe extraction. Re-extraction does not create recent real-world traffic or independently validate the inherited ground truth. Source terms govern redistribution.

## 2. CIC window selection

`dataset.prepare` selects all flows with FLOW_START in declared half-open windows. Original CIC subsets do not sample individual rows or balance classes. `flow_id` is the original CSV row index and remains stable across subsets. The timestamps span 2018-02-14 12:28:07 to 2018-03-02 20:06:24 UTC. Initial inspection finds no null/negative features, END<START, or binary/fine-label disagreement.

| Subset | Configuration | Rows | Purpose |
|---|---|---:|---|
| `CIC18-Causal-Demo-v1` | `configs/demo.yaml` | 3,139,471 | Train/calibration, known tails, Bot development, Infiltration stress, historical H1/H2 |
| `CIC18-FE-Study-v1` | `configs/fe_study.yaml` | 3,181,717 | Feature-study development plus H3/H4 |
| `CIC18-Ops-Holdout-v1` | `configs/ops_holdout.yaml` | 1,489,831 | H5–H9 ops evaluation |

T1–T4 are FTP/SSH/GoldenEye/Slowloris training heads on February 14–15; K1–K4 are the same-day tails. C1 is February 20, 12:00–14:05, with 278,255 benign flows. T5/K5 are February 22, 12:00–17:00/17:00–22:00, scoped to web servers `172.31.69.28` and `.1`. S1 is February 28, 15:00–15:40; R1 is March 2, 13:30–17:30. The complete window definitions live in the configs, not duplicated here.

These are retrospective windows, not a global train→calibration→future-test sequence. Each class is concentrated on one date; source sharing and repeated features make known-class evaluation optimistic. The pilot further assigns the first 60% of each credible web window to training, including part of K5. Its ledger therefore filters evaluation rows explicitly.

## 3. Duplicates and feature artifacts

Feature-study EDA uses corrected labels, exact deduplication, and inner-training data; it excludes untouched holdouts. Main findings:

| Finding | Evidence | Consequence |
|---|---|---|
| Exact duplicates | 310,892 duplicate rows outside feature-study holdouts; roughly half of sampled FTP/SSH/GoldenEye attack rows | FE and clean ablation deduplicate; historical A0/pilot/ops training does not |
| Repeated model inputs | FTP inner-validation fingerprints are 100% seen in train; Slowloris 34%, benign 5% | Report unseen-fingerprint sensitivity and within-episode limits |
| Host dependence | Each known attack class in training has one source and one destination; benign has 9,652 sources | Row count overstates independent situations |
| Day/service shortcuts | Source-port PSI 0.165 versus C1; mixed-traffic destination-port/L7 PSI about 1.72/1.44 | Cross-day behavior needs explicit evaluation |
| Structural zeros | TCP windows/flags are zero outside TCP; FTP return code is constant in the inspected CIC scope | Zero need not mean missing data |
| Exporter artifacts | 202,066 TCP flows have nonzero `ICMP_TYPE`; packet histogram counts can exceed packet totals | Candidate preprocessing tested rather than silently imposed |
| Redundancy | LONGEST_FLOW_PKT equals MAX_IP_PKT_LEN; TTL fields are nearly redundant | Retained in the final 49-column contract |

Historical counts before deduplication are not silently substituted with later unique-flow counts. The [CIC ledger](cic_evidence.md) distinguishes raw and deduplicated evaluation.

## 4. CIC label forensics

Reference: [CNS2022 analysis](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html). Its host/time/protocol rules are adapted to NetFlow; they are not a fresh payload audit of every row. Some packet evidence exists in the separate [PCAP feasibility study](../research/pcap_feasibility/README.md), but does not validate the entire label set.

At α=0.1%, A0 v2 on S1 has 959 original-label false positives. Of these, 804 flows match the documented NMAP `.24 → .15` window, 580 destination ports and one packet per direction. Treating those as attacks reduces S1 FPR from 0.598% to 0.097% in an exploratory label-sensitivity analysis. Other Internet scans remain unverified. R1 false positives include 524 UDP/500 or 5060 flows matching noisy web-training patterns and 175 outbound browsing flows.

Web-attack reference pair: `18.218.115.60 → 172.31.69.28`; BF 14:13–15:23, XSS 17:51–18:29, SQLi 20:14–20:27 UTC on February 22.

| Original class | Published rows | Credible: pair/window/TCP-80 | Credible in original T5 | Credible in original K5 |
|---|---:|---:|---:|---:|
| Brute_Force_-Web | 1,618 | 115 | 115/903 | 0/715 |
| Brute_Force_-XSS | 480 | 41 | 0/223 | 41/257 |
| SQL_Injection | 440 | 20 | 0/150 | 20/290 |

Only **176/2,538 (6.9%)** published web rows match the credible rule. This does not prove all remaining rows are benign. The original A0 v2 split contains no credible XSS or SQLi training flows. A large share of nominal web traffic is UDP/500, not HTTP. February 23 contains no flows between the reference attacker–victim pair.

### Adapted labels

`relabel.py` writes `truth_cns2022.parquet` next to original truth. Fields include original/corrected label, status, confidence, and rule. Audited days are February 22, February 28, and March 2; other days retain original labels as `not_audited`.

| Status | Meaning | Rows in the recorded audit |
|---|---|---:|
| confirmed | Matches the adapted attack rule | 133,711 |
| background | Documented background, e.g. UDP/500 or DHCP | 1,033 |
| indeterminate | Neither confirmed nor rejected; excluded from training/evaluation | 18,336 |
| attempted | Startup/no-payload approximation; excluded | 84 |
| unchanged / not_audited | Original label retained | 1,006,929 / 1,979,378 |

The audit changes 35,730 labels, including Benign→Portscan 12,633; Infilteration→Portscan 3,585; Infilteration→indeterminate 17,082; and 41 SQLi→XSS. Adapted web support is Web 70, XSS 80, SQLi 17 before final deduplication. The payload approximation `IN_PKTS≤3` and `IN_BYTES≤180` has medium confidence; it does not directly inspect HTTP payloads.

## 5. Whole-dataset minority inventory

Code: `inventory.py`; output: `runs/minority_inventory/INVENTORY.json` and `episodes.csv`. All 20,115,529 rows are scanned without model scores. An episode is label+source+destination split after a 30-minute gap. Eligibility requires unused, credible, ≥30 deduplicated flows, and an episode different from training.

| Class | Raw rows | Within-label unique exact fingerprints | Shared with another label | Exclusive fingerprints | Rows retained by global keep-first |
|---|---:|---:|---:|---:|---:|
| Brute_Force_-Web | 1,618 | 1,618 | 168 | 1,450 | 1,618 |
| Brute_Force_-XSS | 480 | **460** | **440** | **20** | **20** |
| SQL_Injection | 440 | 440 | 272 | 168 | 440 |

The XSS count 20 is not the number of distinct XSS-labeled flows in the file: it is the exclusive-fingerprint count and the result of a file-order-dependent keep-first policy. Credible XSS count 41 is computed separately within its credible set. Fingerprints include timestamps, IPs, and all 49 features, excluding the label.

**No eligible unused minority cohort remains under the declared rules.** Web/XSS/SQLi episodes are all already used. Unused Infiltration episodes have no validated rules; one remaining Bot flow is insufficient; SlowHTTPTest shares model-input patterns with FTP; the remaining LOIC-HTTP tail shares attackers with the consumed H1 scenario. Seed repetition and oversampling cannot create independent attacks.

## 6. Other sources and interpretation

UNSW has different traffic generation, services, and host characteristics; its two capture sessions span more than two UTC calendar dates. Calendar-day fragments are not independent captures. ToN has 1,816,137 exact duplicate rows but no exact-fingerprint label conflicts; after derived deduplication, training sampling and retrospective windows are explicit. See [monitoring/transfer](monitoring_and_transfer.md) and [ToN evaluation](ton_iot_evaluation.md).

Data quality limits cannot be repaired simply by choosing a more complex model. Conversely, absent HTTP payload is a plausible limitation, not a theorem that every credible web subtype is impossible to distinguish using flow features. Conclusions remain tied to the audited labels, cohort definitions, and effective number of episodes.
