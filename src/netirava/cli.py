"""Command line interface: python -m netirava <command> --config configs/demo.yaml"""

import argparse
import json
import sys

from netirava import config as K


def _print(obj):
    print(json.dumps(obj, indent=2, default=str))


def build_parser():
    """Build the command interface without loading data or running an experiment."""
    ap = argparse.ArgumentParser(prog="netirava")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("inspect", "prepare", "train-a0", "train-anomaly", "audit", "score-calibration", "ablate-imbalance", "minority-report", "relabel", "pilot-train", "pilot-eval", "registry", "eda", "fe-study", "fe-final", "ablate-clean", "inventory", "ledger", "external"):
        p = sub.add_parser(name)
        p.add_argument("--config", default="configs/demo.yaml")
        if name == "train-a0":
            p.add_argument("--variant", default="a0", choices=["a0", "a1", "a2"])
            p.add_argument("--seed", type=int, default=None)
    p = sub.add_parser("replay")
    p.add_argument("--config", default="configs/demo.yaml")
    p.add_argument("--mode", choices=["a0", "a0-shadow"], default="a0")
    p.add_argument("--pace", choices=["fast", "paced"], default="fast")
    p.add_argument("--speed", type=float, default=None)
    p.add_argument("--segments", nargs="*", default=None)
    p.add_argument("--max-events", type=int, default=None)
    p.add_argument("--unlock-holdout", action="store_true", help="include the final holdout (only after the method is frozen)")
    p.add_argument("--model", default=None, help="model dir under artifacts/models (default: final_system.model_dir, else a0)")
    p.add_argument("--run-id", default=None, help="explicit new run id (existing runs are never overwritten)")
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
    for name in ("export", "family-report"):
        p = sub.add_parser(name)
        p.add_argument("--run", required=True)
        p.add_argument("--segments", nargs="*", default=None)
        p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("drift-reference", help="build the label-free drift-monitor reference of a model (C1)")
    p.add_argument("--model", default="a0")
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("drift-monitor", help="label-free monitor table of a run (DRIFT_MONITOR.parquet)")
    p.add_argument("--run", required=True)
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("ops-study", help="evaluator: incident correlation + drift monitoring on runs")
    p.add_argument("--runs", nargs="+", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("ops-go", help="pre-registered GO rules on an ops-study result")
    p.add_argument("--tag", required=True)
    p.add_argument("--benefit-scenario", default="holdout-ddos-hoic")
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("ops-summary", help="Markdown tables of an ops-study result")
    p.add_argument("--tag", required=True)
    p.add_argument("--labels", default="original", choices=["original", "corrected"])
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("ops-pool", help="RQ-D on the pooled monitor windows of several ops-study tags")
    p.add_argument("--tags", nargs="+", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("task-make", help="blinded triage trial task from a run")
    p.add_argument("--run", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--k", type=int, default=4)
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("task-run", help="interactive, timed human session for one condition")
    p.add_argument("--task", required=True)
    p.add_argument("--cond", required=True, choices=["C0", "C1"])
    p.add_argument("--reviewer", required=True)
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("task-score", help="score verdict files against the reference answers")
    p.add_argument("--task", required=True)
    p.add_argument("--verdicts", nargs="+", required=True)
    p.add_argument("--config", default="configs/demo.yaml")
    for name, help_text in (
        ("ton-audit", "streaming audit of the raw ToN-IoT CSV"),
        ("ton-prepare", "prepare the frozen ToN-IoT splits"),
        ("ton-split-audit", "inspect split support and independence"),
        ("ton-train", "single fit; refuses when FIT_STARTED.json exists"),
        ("ton-replay", "replay all declared test windows, without training"),
        ("ton-evaluate", "original ToN-IoT evaluator over saved runs"),
        ("ton-sensitivity", "pre-declared sensitivity and bootstrap over saved runs"),
        ("ton-report", "post-gate metrics and global host novelty from saved runs"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--config", default="configs/ton_iot.yaml")
        if name in {"ton-evaluate", "ton-sensitivity", "ton-report"}:
            p.add_argument("--runs", nargs="+", default=None, help="default: ton_<test window id>")
        if name == "ton-replay":
            p.add_argument("--prefix", default="ton", help="use a fresh prefix to preserve existing runs")
        if name == "ton-report":
            p.add_argument("--output", default=None, help="default: configured runs/SUBMISSION_TON.json")
    p = sub.add_parser("ui-check", help="headless check of a saved run; does not submit feedback")
    p.add_argument("--run", required=True)
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("ui")
    p.add_argument("--run", required=True)
    p.add_argument("--port", default="8501")
    p.add_argument("--config", default="configs/demo.yaml")
    p = sub.add_parser("incidents")
    p.add_argument("--run", required=True)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--config", default="configs/demo.yaml")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
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
        _print(train_a0(cfg, a.variant, a.seed))
    elif a.cmd == "train-anomaly":
        from netirava.detectors import train_anomaly
        _print(train_anomaly(cfg))
    elif a.cmd == "replay":
        from netirava.replay import run
        _print(run(cfg, mode=a.mode, pace=a.pace, speed=a.speed, segments=a.segments, max_events=a.max_events,
                   unlock_holdout=a.unlock_holdout, model=a.model, run_id=a.run_id))
    elif a.cmd == "ablate-imbalance":
        from netirava.evaluation import ablate_imbalance
        r = ablate_imbalance(cfg)
        _print({v: {"macro_f1_known": x["macro_f1_known"], "macro_f1_rare": x["macro_f1_rare"],
                    "rare": {c: (round(m["precision"], 3), round(m["recall"], 3), round(m["f1"], 3), m["support"])
                             for c, m in x["per_class"].items() if c in cfg["a0"]["rare_classes"]},
                    "delta_rare_vs_a0": x.get("delta_macro_f1_rare_vs_a0")} for v, x in r["variants"].items()})
    elif a.cmd == "registry":
        from netirava.registry import build
        _print(build(cfg))
    elif a.cmd == "pilot-train":
        from netirava.pilot import train_pilot
        _print(train_pilot(cfg))
    elif a.cmd == "pilot-eval":
        from netirava.pilot import evaluate_pilot
        r = evaluate_pilot(cfg)
        _print({"eval_rows": r["eval_rows"], "support": r["support"]})
    elif a.cmd == "eda":
        from netirava.eda import run
        r = run(cfg)
        _print({k: r[k] for k in ("rows_non_holdout", "study_role_counts", "near_constant_features", "consistency")})
    elif a.cmd == "fe-study":
        from netirava.fstudy import run_study
        _print(run_study(cfg))
    elif a.cmd == "ton-split-audit":
        from netirava.ton import split_audit
        r = split_audit(cfg)
        _print({k: r[k] for k in r if k != "classes"} | {"minority": [c for c, v in r["classes"].items() if v["minority"]]})
    elif a.cmd == "ton-train":
        from netirava.ton import train_once
        r = train_once(cfg)
        _print({k: r[k] for k in ("model_hash", "n_train", "tree_count", "threshold", "timing", "resources")})
    elif a.cmd == "ton-prepare":
        from netirava.ton import prepare as ton_prepare
        r = ton_prepare(cfg)
        _print({k: r[k] for k in ("rows", "rows_by_role", "p_keep_train", "elapsed_s")})
    elif a.cmd == "ton-audit":
        from netirava.ton import audit as ton_audit
        r = ton_audit(cfg)
        _print({k: r[k] for k in ("rows", "missing_contract_columns", "exact_duplicate_rows", "ts_min_utc", "ts_max_utc", "seconds")})
    elif a.cmd == "ton-replay":
        from netirava.ton_reporting import replay_test
        _print(replay_test(cfg, a.prefix))
    elif a.cmd == "ton-sensitivity":
        from netirava.ton import sensitivity_and_uncertainty
        from netirava.ton_reporting import test_run_ids
        r = sensitivity_and_uncertainty(cfg, a.runs or test_run_ids(cfg))
        _print({"episode_bootstrap": r["episode_bootstrap"]})
    elif a.cmd == "ton-report":
        from netirava.ton_reporting import build_report
        r = build_report(cfg, a.runs, a.output)
        _print({"model_hash": r["model_hash"], "pooled": r["pooled"],
                "test_coverage_exactly_once": r["test_coverage_exactly_once"]})
    elif a.cmd == "external":
        from netirava.external import run as ext
        r = ext(cfg)
        _print({"gate": {k: v["ok"] for k, v in r["gate"].items() if k.startswith("G")} | {"train": r["gate"]["train"]}})
    elif a.cmd == "ledger":
        from netirava.ledger import build, markdown
        led = build()
        flows, cls = markdown(led)
        out = K.path(cfg, "runs") / "final_evidence"
        out.mkdir(parents=True, exist_ok=True)
        (out / "LEDGER_flows.md").write_text(flows, encoding="utf-8")
        (out / "LEDGER_classes.md").write_text(cls, encoding="utf-8")
        _print({n: s["model"] for n, s in led["systems"].items()})
    elif a.cmd == "inventory":
        from netirava.inventory import run as inv
        r = inv(cfg)
        _print({k: r[k] for k in ("attack_rows", "attack_rows_exact_duplicates", "by_label", "web_attacker_victim_pair_by_day_label_all_rows")}
               | {"eligible_cohorts": len(r["eligible"])})
    elif a.cmd == "ablate-clean":
        from netirava.ablation import run as ablate
        r = ablate(cfg)
        _print({f"{x['arm']}_s{x['seed']}": x["rare_macro_f1_web_eval"] for x in r["runs"]})
    elif a.cmd == "fe-final":
        from netirava.fstudy import run_final
        _print(run_final(cfg))
    elif a.cmd == "relabel":
        from netirava.relabel import build
        _print(build(cfg))
    elif a.cmd == "minority-report":
        from netirava.evaluation import minority_report
        r = minority_report(cfg)
        _print({k: r[k] for k in ("stability", "a0_rare_pr", "web_family_view", "data_ceiling")})
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
    elif a.cmd == "export":
        from netirava.triage import export
        _print(export(cfg, a.run))
    elif a.cmd == "family-report":
        from netirava.evaluation import family_report
        r = family_report(cfg, a.run, segments=a.segments)
        _print({"invariance": r["invariance"],
                **{lv: {"family": v["family"],
                        "risk_coverage@0.8": {k: x for k, x in v["risk_coverage"].items() if k.endswith("@0.8")}}
                   for lv, v in r["labels"].items()}})
    elif a.cmd == "drift-reference":
        from netirava.drift import build_reference
        r = build_reference(cfg, a.model)
        _print({k: r[k] for k in ("model_dir", "model_hash", "model_threshold", "n", "n_benign", "levels")})
    elif a.cmd == "drift-monitor":
        from netirava.drift import monitor_run
        t = monitor_run(cfg, a.run)
        _print({"windows": len(t), "status": t.status.value_counts().to_dict()})
    elif a.cmd == "ops-study":
        from netirava.ops import study
        _, summ, win = study(cfg, a.runs, a.tag)
        _print({"windows": len(win), "drift": {m: {k: {"windows": v["windows"], "E": v["E_windows"],
                                                         "TR": v["signals"]["TR"], "go": v["go"]}
                                                     for k, v in x.items() if k.endswith("@%s" % cfg["ops"]["drift"]["primary_alpha"])}
                                                 for m, x in summ["drift"].items()}})
    elif a.cmd == "ops-go":
        from netirava.ops import go_report
        _print(go_report(cfg, a.tag, a.benefit_scenario))
    elif a.cmd == "ops-summary":
        from netirava.ops import summarize
        txt = summarize(cfg, a.tag, a.labels)
        out = K.path(cfg, "runs") / "ops_study" / a.tag / f"SUMMARY_{a.labels}.md"
        out.write_text(txt, encoding="utf-8")
        sys.stdout.buffer.write((txt + chr(10)).encode("utf-8"))
    elif a.cmd == "ops-pool":
        from netirava.ops import pooled_drift
        r = pooled_drift(cfg, a.tags, a.out)
        _print({m: {k: v["go"] for k, v in x.items()} for m, x in r["drift"].items()})
    elif a.cmd == "task-make":
        from netirava.triage_task import make
        _print(make(cfg, a.run, a.out, a.k))
    elif a.cmd == "task-run":
        from netirava.triage_task import run_interactive
        _print({"decisions": run_interactive(a.task, a.cond, a.reviewer)})
    elif a.cmd == "task-score":
        from netirava.triage_task import score
        _print(score(a.task, a.verdicts))
    elif a.cmd == "ton-evaluate":
        from netirava.ton import evaluate as ton_eval
        from netirava.ton_reporting import test_run_ids
        r = ton_eval(cfg, a.runs or test_run_ids(cfg))
        _print({"pooled_macro_f1": r["pooled"]["macro_f1_present"], "pooled_fpr": {k: v["benign_fpr"] for k, v in r["pooled"]["alphas"].items()}})
    elif a.cmd == "ui-check":
        from netirava.ui_check import check
        _print(check(a.config, a.run))
    elif a.cmd == "ui":
        import subprocess
        from pathlib import Path
        app = Path(__file__).with_name("app.py")
        return subprocess.call([sys.executable, "-m", "streamlit", "run", str(app), "--server.port", a.port,
                                "--server.headless", "true", "--", "--config", a.config, "--run", a.run])
    elif a.cmd == "incidents":
        from netirava.storage import RunStore
        st = RunStore(cfg, a.run)
        for r in st.list_incidents(a.limit):
            print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
