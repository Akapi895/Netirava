# Protocol translations and original evidence

These files are **English translations prepared after the experiments**. They retain the original questions, parameters, rules, and sequence, with explicitly marked notes for later corrections. They are not newly preregistered plans and must not be compared against historical hashes as if they were the original bytes.

| English document | Original source | Status at execution |
|---|---|---|
| [Ops study](ops_study.md) | `docs/OPS_STUDY_PREREG.md` at commit `e1b473a`, later renamed `docs/protocols/ops_study_prereg.md` | Committed before implementation/evaluation |
| [Clean ablation, inventory, task](clean_ablation.md) | `docs/protocols/evidence_round2_prereg.md`, commit `d368fdc` | Committed before those activities |
| [External UNSW](external_evaluation.md) | `docs/protocols/external_round3_prereg.md`, commit `6ad5206` | Committed before the Netirava external evaluation |
| [Supplementary ToN](ton_iot.md) | `docs/protocols/ton_iot_protocol.md`, hash in `FROZEN_PLAN.json` | Local timestamp/checksum before fit; not committed at execution |

Exact pre-translation copies are stored under `artifacts/documentation_originals/docs/protocols/`. The [originals manifest](originals_manifest.json) records original paths, SHA-1 values, and archive paths; the ToN original is checked against the pre-fit frozen plan. Earlier committed versions can be retrieved from their historical Git paths. No original manifest or model metadata is edited to match the translations.

Original code/config snapshots needed for hash comparison are `artifacts/documentation_originals/ton.py` and `ton_iot.yaml`. Current source/config documentation references may change without altering executable training logic or parsed configuration. Raw data, checkpoint bytes, thresholds, and saved scores retain their original identities.

For current conclusions, use the linked result reports, not prospective wording inside a protocol. In particular: ToN host novelty is corrected to distinguish same-class from global training; historical incident/hour denominators are corrected outside the original plans; XSS deduplicated support differs from the clean-ablation plan's initial expectation.
