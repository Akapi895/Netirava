"""Headless UI verification of a saved run, without adding analyst feedback."""

import sys

from netirava import app


def check(config_path, run_id, timeout=120):
    """Exercise the default source view and campaign view; fail on app errors.

    AppTest validates rendering/interaction logic, not browser layout or human
    usability. The check never clicks Save feedback or reads evaluator truth.
    """
    from streamlit.testing.v1 import AppTest

    original = sys.argv
    try:
        sys.argv = ["app", "--config", str(config_path), "--run", run_id]
        test = AppTest.from_file(app.__file__, default_timeout=timeout)
        test.run()
        errors = [str(e.value) for e in test.error] + [str(e.value) for e in test.exception]
        if errors:
            raise RuntimeError("UI check failed: " + "; ".join(errors))
        captions = [c.value for c in test.caption if "threshold" in c.value and "run " in c.value]
        if not captions or not test.sidebar.radio:
            raise RuntimeError("UI did not render the run metadata and review controls")
        metrics = {m.label: m.value for m in test.metric}
        test.sidebar.radio[0].set_value("campaign").run()
        if test.exception or test.error:
            raise RuntimeError("Campaign view failed to render")
        return {"run_id": run_id, "opened_ok": True, "caption": captions[0],
                "metrics": metrics, "campaign_view_ok": True, "feedback_submitted": False,
                "scope": "Streamlit AppTest; browser layout and analyst usability not assessed"}
    finally:
        sys.argv = original
