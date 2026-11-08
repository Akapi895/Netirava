"""Command line interface: python -m netirava <command> --config configs/demo.yaml"""

import argparse
import json
import sys

from netirava import config as K


def _print(obj):
    print(json.dumps(obj, indent=2, default=str))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="netirava")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("inspect", "prepare", "train-a0", "train-anomaly", "audit", "score-calibration"):
        p = sub.add_parser(name)
        p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("replay")
    p.add_argument("--config", default="configs/demo.yaml")
    p.add_argument("--mode", choices=["a0", "a0-shadow"], default="a0")
    p.add_argument("--pace", choices=["fast", "paced"], default="fast")
    p.add_argument("--speed", type=float, default=None)
    p.add_argument("--segments", nargs="*", default=None)
    p.add_argument("--max-events", type=int, default=None)
    p.add_argument("--unlock-holdout", action="store_true", help="include the final holdout (only after the method is frozen)")
    p = sub.add_parser("decide")
    p.add_argument("--run", required=True)
    p.add_argument("--select", action="store_true", help="choose V4 (W, rho) on development scenarios")
    p.add_argument("--unlock-holdout", action="store_true")
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("evaluate")
    p.add_argument("--run", required=True)
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("feedback")
    p.add_argument("--run", required=True)
    p.add_argument("--alert-id", required=True, type=int)
    p.add_argument("--status", required=True, choices=["true_positive", "false_positive", "uncertain"])
    p.add_argument("--source", default="analyst")
    p.add_argument("--confirmed-by", default="unknown")
    p.add_argument("--attack-label", default=None)
    p.add_argument("--corrects", type=int, default=None, help="feedback_id this entry corrects")
    p.add_argument("--provenance", default="analyst", choices=["analyst", "demo", "simulated_ground_truth"])
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("incidents")
    p.add_argument("--run", required=True)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--config", default="configs/demo.yaml")
    a = ap.parse_args(argv)
    cfg = K.load(a.config)

    if a.cmd == "inspect":
        from netirava.dataset import inspect
        _print({k: v for k, v in inspect(cfg).items() if k != "schema"})
    elif a.cmd == "prepare":
        from netirava.dataset import prepare
        m, _ = prepare(cfg)
        _print({k: m[k] for k in ("rows", "rows_by_role", "unknown_to_model_rows", "flagged_label_rows")})
    elif a.cmd == "audit":
        from netirava.dataset import audit
        _print(audit(cfg))
    elif a.cmd == "train-a0":
        from netirava.detectors import train_a0
        _print(train_a0(cfg))
    elif a.cmd == "train-anomaly":
        from netirava.detectors import train_anomaly
        _print(train_anomaly(cfg))
    elif a.cmd == "replay":
        from netirava.replay import run
        _print(run(cfg, mode=a.mode, pace=a.pace, speed=a.speed, segments=a.segments, max_events=a.max_events,
                   unlock_holdout=a.unlock_holdout))
    elif a.cmd == "score-calibration":
        from netirava.decision import score_calibration
        _print({"rows": len(score_calibration(cfg))})
    elif a.cmd == "decide":
        from netirava import decision as D
        if a.select:
            _print(D.select_v4(cfg, a.run))
        else:
            name = "DECISIONS_holdout.json" if a.unlock_holdout else "DECISIONS_dev.json"
            r = D.evaluate_run(cfg, a.run, unlock_holdout=a.unlock_holdout, out_name=name)
            _print({k: {s: {v: (m.get("attack_recall"), m["benign_fpr"]) for v, m in x.items()}
                        for s, x in lv["scenarios"].items()} for k, lv in r["levels"].items()})
    elif a.cmd == "evaluate":
        from netirava.evaluation import evaluate
        _print(evaluate(cfg, a.run))
    elif a.cmd == "feedback":
        from netirava.storage import RunStore
        st = RunStore(cfg, a.run)
        _print(st.add_feedback(a.alert_id, a.status, a.source, a.confirmed_by, a.attack_label, a.corrects, a.provenance))
    elif a.cmd == "incidents":
        from netirava.storage import RunStore
        st = RunStore(cfg, a.run)
        for r in st.list_incidents(a.limit):
            print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
