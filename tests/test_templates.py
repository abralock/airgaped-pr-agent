from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def test_gitlab_template():
    doc = yaml.safe_load((ROOT / "templates/gitlab/pr-agent.gitlab-ci.yml").read_text())
    base = doc[".pr-agent"]
    assert base["image"]["entrypoint"] == [""]
    assert base["variables"]["GIT_DEPTH"] == "0"
    job = doc["pr-agent-review"]
    assert job["extends"] == ".pr-agent"
    assert job["stage"] == "test"
    assert job["rules"] == [{"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'}]
    assert job["script"] == ["pr-agent review"]


def test_gitlab_template_scan_job():
    doc = yaml.safe_load((ROOT / "templates/gitlab/pr-agent.gitlab-ci.yml").read_text())
    job = doc["pr-agent-full-scan"]
    assert job["extends"] == ".pr-agent"
    assert job["script"] == ["pr-agent scan --out-dir pr-agent-report"]
    assert job["artifacts"]["when"] == "always"
    assert job["artifacts"]["paths"] == ["pr-agent-report/"]
    rules = job["rules"]
    assert {"if": '$CI_PIPELINE_SOURCE == "schedule"'} in rules
    web = [r for r in rules if "web" in r["if"]]
    assert len(web) == 1 and web[0]["when"] == "manual" and web[0]["allow_failure"] is True
