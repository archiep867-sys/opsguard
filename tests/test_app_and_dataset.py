from __future__ import annotations

import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).parents[1]


@pytest.fixture()
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AppTest:
    monkeypatch.setenv("OPSGUARD_DB_PATH", str(tmp_path / "audit.sqlite3"))
    monkeypatch.setenv("STRANDS_DECIDER_URL", "http://127.0.0.1:9")  # nothing listens: Decider offline
    return AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)


@pytest.mark.parametrize("page", ["Security Overview", "Command Playground", "Agent Console", "Policy Details", "Audit Explorer", "System Status"])
def test_every_page_renders(app: AppTest, page: str) -> None:
    app.run()
    app.sidebar.radio[0].set_value(page).run()
    assert not app.exception


def test_agent_console_requires_explicit_bedrock_configuration(app: AppTest) -> None:
    app.run()
    app.sidebar.radio[0].set_value("Agent Console").run()
    assert any("OPSGUARD_BEDROCK_ENABLED" in warning.value for warning in app.warning)


def test_scenario_buttons_work_with_decider_offline(app: AppTest) -> None:
    app.run()
    app.sidebar.radio[0].set_value("Command Playground").run()
    scenario = next(button for button in app.button if button.label == "Delete a namespace")
    scenario.click().run()
    assert not app.exception
    assert any("BLOCK" in str(markdown.value) for markdown in app.markdown)


def test_explanation_is_not_shown_for_a_different_command(app: AppTest) -> None:
    from opsguard.bedrock_client import ExplanationResult

    app.run()
    app.sidebar.radio[0].set_value("Command Playground").run()
    next(button for button in app.button if button.label == "Safe Kubernetes inspection").click().run()
    app.session_state["explanation"] = ExplanationResult("BEDROCK_SUCCESS", "bedrock", "STALE-TEXT-FROM-OTHER-COMMAND", "m", 1.0, None, True)
    app.session_state["explanation_context"] = ("some other command", "staging", "pods")
    app.run()
    assert not any("STALE-TEXT" in str(markdown.value) for markdown in app.markdown)


def test_labelled_dataset_is_sound() -> None:
    rows = [json.loads(line) for line in (ROOT / "eval" / "commands.jsonl").read_text().splitlines()]
    assert len(rows) == 100 and len({row["command"] for row in rows}) == 100
    assert {row["label"] for row in rows} == {"SAFE", "REVIEW", "BLOCK"}
    assert all(sum(1 for row in rows if row["label"] == label) >= 30 for label in ("SAFE", "REVIEW", "BLOCK"))


def test_rules_alone_never_allow_a_labelled_block() -> None:
    from opsguard.safety_engine import Decision, evaluate_command

    for row in (json.loads(line) for line in (ROOT / "eval" / "commands.jsonl").read_text().splitlines()):
        if row["label"] == "BLOCK":
            assert evaluate_command(row["command"]).decision is not Decision.SAFE, row["command"]
