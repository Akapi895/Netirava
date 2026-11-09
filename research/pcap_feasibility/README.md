# Discontinued PCAP feasibility study

This historical study asks whether packet/protocol features add information beyond flow features. **NO-GO in the tested IoT-23 setting.** It is not part of Netirava runtime and does not establish either benefit or futility of PCAP enrichment on NF-CSE-CIC-IDS2018-v3.

The former access, extraction, results, and decision narratives are consolidated here. Original result JSON, [generated result tables](results/SUMMARY.md), scripts, tests, and protocol remain. Pre-translation reports are archived outside Git in `artifacts/documentation_originals/`; Git history retains earlier versions.

## 1. Protocol and data access

Protocol `config.yaml` was locked before download at `2feaa35`; corrected extraction code at `973b4c8` preceded evaluation. Budget: at most three captures and 200 MB. Models use CatBoost CPU, 500 trees, depth6, learning rate0.1, seeds0/1/2, no HPO.

Source A is the public CSE-CIC-IDS2018 S3 archive. Whole-day PCAP objects are 38–59 GB, initially judged too large. A later HTTP Range inspection of the February22 ZIP central directory found 447 per-host members. Web server `UCAP172.31.69.28` is only 9.49 MB compressed/25.7 MB uncompressed. A 9.61 MB selective download was used only for join feasibility, not model evaluation.

Source B is IoT-23. Capture selection uses listing sizes, labeled-log availability, different malware families, and inclusion of 20-1, not measured model results. Chosen captures: 34-1 Mirai, 8-1 Hakai, 20-1 Torii. Nine files total137.3 MB; total source/download traffic about147.2 MB, within200 MB. Exact hashes remain in `data/DOWNLOAD_MANIFEST.json` and member manifests outside Git. Some source README terms require authorization; no raw data is distributed here.

| Capture | Benign | Malicious | Benign calibration in LOCO | Independent malicious destinations |
|---|---:|---:|---:|---|
| 34-1 Mirai | 1,923 | 21,222 | 1,608 | DDoS3, C&C1, PortScan2 |
| 8-1 Hakai | 2,181 | 8,222 | 1,133 | C&C2 |
| 20-1 Torii | 3,193 | 16 | 815 | Torii1 |

Each capture has one infected device; benign traffic comes from that device. Effective independent support is much smaller than flow count. The 0.1% FPR target has insufficient support in every LOCO fold; the predeclared fallback uses1% plus PR-AUC.

## 2. Packet-to-flow extraction

Input labeled Zeek logs supply `uid`; `dpkt` parses PCAP. No local Zeek/Tshark installation is used. Join by bidirectional protocol/5-tuple and `[ts−1s,ts+duration+1s]`; prefer containing intervals, then nearest start, and count ambiguity. Non-first fragments attach via `(src,dst,protocol,IP-ID)`. Keep unmatched flows with missing packet features; join-status flags are excluded from model inputs.

| Check | 20-1 | 8-1 | 34-1 |
|---|---:|---:|---:|
| PCAP packets | 50,156 | 23,623 | 233,865 |
| Flows with at least one matched packet | 3,209/3,209 | 10,403/10,403 | 23,145/23,145 |
| IPv4 packets matched | 100% | 100% | 96.7% |
| Ambiguous matched packets | 0 | 0 | 52,052 |
| Parse/features time | 0.85s | 1.19s | 5.0s |
| Peak RSS | 120MB | 175MB | 300MB |

An initial lookup matched only46% of34-1 flows because it considered too few preceding candidates; it was fixed before evaluation and covered by regression tests. 34-1 has14,260 Zeek DDoS rows with zero recorded packets, creating ambiguous packet-level evidence. A sensitivity analysis removes them; no demonstrated incremental benefit appears.

### Feature sets and shortcuts

- **A, 11 features:** Zeek duration, directional byte/packet counts, missed bytes, protocol/state, destination port. This is poorer than Netirava's49-feature NetFlow contract.
- **B, 64 features:** directional packet-size distributions, IAT/response delay, TCP flags, first-five signed packet sizes, DNS/HTTP metadata, payload length/entropy, and Zeek service.
- **C, 75 features:** A+B. Controls add equal-dimensional noise or independently permuted B.
- Exclude IP, absolute time, uid/capture id, source port, labels, join flags, TTL/IP-ID/windows, and raw strings/payload. Missingness is structural; CatBoost handles it without fitted imputation.

Benign is98.4% UDP, mostly NTP/DNS; malicious is99.99% TCP. Protocol and destination port nearly saturate binary ranking. Encrypted traffic is absent; malicious application metadata is almost absent. Packet sizes have full coverage, timing0.323, TCP flags0.805, DNS0.021, HTTP0.0003, TLS/SSH0, service0.066. This is primarily a packet-feature test, not a meaningful test of rich protocol/encrypted-traffic metadata.

## 3. Evaluation and NO-GO

LOCO binary: train the first70% of the two non-test captures, choose threshold on their final30% benign, test the held-out capture/malware family. Same flows/labels/splits across sets. Results below are means over three seeds; full variability and controls remain in [SUMMARY](results/SUMMARY.md) and JSON.

| Test capture | Set | PR-AUC | Recall at locked calibration1% | Realized test FPR | False incidents |
|---|---|---:|---:|---:|---:|
| 34-1 | A | 0.989 | 1.000 | 0.075 | 4.0 |
| 34-1 | C | 0.988 | 1.000 | 0.073 | 2.7 |
| 8-1 | A | 1.000 | 0.667 | 0.001 | 2.0 |
| 8-1 | C | 0.999 | 0.750 | 0.001 | 2.0 |
| 20-1 | A | 1.000 | 1.000 | 0.158 | 23.0 |
| 20-1 | C | 1.000 | 1.000 | 0.160 | 15.0 |

FPR numbers are ratios:0.075 means7.5%. C−A recall deltas are0/0/0 on34-1 and20-1, and0/0/+0.25 on8-1; the latter is smaller than seed variability and an A+noise control reaches recall1.0. C does not beat permuted-B controls. All feature sets violate nominal1% test FPR on two of three captures. An oracle test-benign threshold is analysis-only, not deployable calibration.

Capture identifiability on benign data has macro-F1 A0.712/B0.769/C0.768 against chance0.333: added features carry environment fingerprints. Group ablations have |ΔPR-AUC|≤0.007 with mostly unchanged recall. Exploratory within-capture multiclass A/B/C results are identical (macro-F1≈0.987); minority classes below20 train/test rows are unscored.

The declared GO condition requires improvement in at least two of three folds beyond seed/control effects, without higher benign FPR or a single capture-identifying shortcut. **It fails.** This decision does not show PCAP is intrinsically useless, and does not answer the question against Netirava's richer49-feature baseline.

## 4. CIC join feasibility, not model evidence

On February22 web-server windows,2,752/3,212 NetFlow rows match PCAP packets (**85.7%**) at zero timestamp offset; matched packet counts equal `IN_PKTS+OUT_PKTS`. Benign/Web/SQLi labels match at100%; nominal XSS matches20/480 (4.2%), those20 being DHCP. Many unmatched nominal XSS flows are AWS IKE/500 rather than HTTP traffic in the server capture. The separate zero-offset scan reports86.6% before the final join handling; it is not substituted for the final85.7% result.

This establishes a technical route for selective NetFlow enrichment, not classification improvement or complete label validation. Direct CIC model testing would need a new protocol and credible labels; it was not integrated.

## 5. Cost and deviations

Measured extraction is approximately95k packets/s in one Python thread. Average fit time A11.2s versus C13.7s; vectorized inference0.92 versus1.94µs/flow, about2.1×. Full evaluation took1,179s. PCAP acquisition/parsing adds costs without the required demonstrated benefit.

Recorded deviations: join lookup/fragment handling fixed before evaluation; selective Source A join check added after the IoT-23 plan without model fitting;1% used because0.1% lacked support under the declared fallback; zero-packet-record sensitivity added after discovering the artifact. Original logs and result JSON retain their experimental paths and values.

## 6. Historical reproduction

Run in this directory with its separate environment. These commands download data and fit historical research models; they are **not** needed for the submission demo or intended to be run during final verification.

```powershell
uv sync
$py = ".venv\Scripts\python.exe"
& $py -m pytest -q -p no:cacheprovider tests
& $py -I scripts/download.py
foreach ($c in "CTU-IoT-Malware-Capture-20-1","CTU-IoT-Malware-Capture-8-1","CTU-IoT-Malware-Capture-34-1") { & $py -I scripts/extract_all.py $c }
& $py -I scripts/run_eval.py
& $py -I scripts/summarize.py
```

`data/` and `work/` remain ignored and unchanged. This study is stopped; reopening packet/HTTP expansion requires a separate user decision.
