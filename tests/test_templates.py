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
