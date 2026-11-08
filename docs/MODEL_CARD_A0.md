# Model card — A0-CIC (be8f6d84bf2d)

CatBoost MultiClass, công thức anchor NP-v1, **fit mới trên CIC-2018**; không dùng trọng số UNSW.

- Known classes (5): Benign, FTP-BruteForce, SSH-Bruteforce, DoS_attacks-GoldenEye, DoS_attacks-Slowloris
- Train rows: 804,439 — Benign 507,113, FTP-BruteForce 125,700, SSH-Bruteforce 100,140, DoS_attacks-GoldenEye 50,134, DoS_attacks-Slowloris 21,352
- SMOTE: no class below the threshold: no synthetic rows
- Recipe source: D:\Downloads\DataNova\Netirava\..\experiments\nextphase\configs.yaml (sha1 d56f1c3e56d8d5d68b6a9443a5e312bac6bd9df7)
- Device: GPU; learning rate 0.1113020032644272 (cpu_auto_probe); iterations 1000, depth 6, l2 3, border 254, seed 0
- Features: 49 (nfv3-49-allowlist-v1); ports, TTL and DNS_QUERY_ID kept; IPs, absolute timestamps and labels excluded
- Output: predicted known class, full probability vector, attack_score = 1 − p(Benign) (decision score, not calibrated)
- Threshold: 0.00393777 at target benign FPR 0.001 on 278,255 calibration benign flows; realised 0.00100 (Wilson 95% [0.0008850019224134631, 0.0011197559382618257]); uncertain=False
- Cannot name classes it was not trained on: unknown attacks can only surface as high attack_score.
- Deviations from NP-v1: dataset/taxonomy: CIC-2018 known classes instead of UNSW 10 classes (new fit, new class map); single seed (a0.seed) instead of 3-seed evaluation; train rows = configured train windows (chronological), not the NP-v1 grouped CV; threshold on attack_score chosen on a calibration window (NP-v1 used argmax only)
