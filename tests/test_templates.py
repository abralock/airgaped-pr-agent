import os
import subprocess
from pathlib import Path

import pytest
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


def _flatten(steps):
    """Expand `${{ if ... }}:` template-expression keys into their step lists."""
    out = []
    for s in steps:
        if isinstance(s, dict) and len(s) == 1 and str(next(iter(s))).startswith("${{"):
            out.extend(_flatten(next(iter(s.values()))))
        else:
            out.append(s)
    return out


def _azure_steps():
    doc = yaml.safe_load((ROOT / "templates/azure/pr-agent.yml").read_text())
    return doc, _flatten(doc["jobs"][0]["steps"])


def test_azure_template():
    doc, steps = _azure_steps()
    params = {p["name"]: p for p in doc["parameters"]}
    assert set(params) == {"image", "pool", "mode", "history"}
    assert params["mode"]["values"] == ["review", "scan"]
    assert params["history"]["type"] == "boolean" and params["history"]["default"] is False
    assert any(s.get("checkout") == "self" and s.get("fetchDepth") == 0 for s in steps)
    scripts = [s for s in steps if "script" in s]
    assert {s["script"] for s in scripts} == {
        "pr-agent review",
        "pr-agent scan --out-dir pr-agent-report",
        "pr-agent scan --out-dir pr-agent-report --history",
    }
    for s in scripts:
        assert s["env"]["LLM_API_KEY"] == "$(LLM_API_KEY)"
    (review,) = [s for s in scripts if s["script"] == "pr-agent review"]
    assert review["env"]["SYSTEM_ACCESSTOKEN"] == "$(System.AccessToken)"


def test_azure_template_scan_publishes_report_always():
    doc, steps = _azure_steps()
    pubs = [s for s in steps if "publish" in s]
    assert pubs == [
        {"publish": "pr-agent-report", "artifact": "pr-agent-report", "condition": "always()"}
    ]
    scan_block = doc["jobs"][0]["steps"][-1]
    assert next(iter(scan_block)) == "${{ if eq(parameters.mode, 'scan') }}"
    assert not any("publish" in s for s in _flatten(doc["jobs"][0]["steps"][1:2]))


def test_azure_template_runs_container_as_root_for_agent_setup():
    # The image's USER is non-root; Azure's container-job setup needs root
    # (it runs groupadd/useradd), then runs steps as the agent's own uid.
    doc, _ = _azure_steps()
    assert doc["jobs"][0]["container"] == {
        "image": "${{ parameters.image }}",
        "options": "--user 0:0",
    }


def test_azure_template_scan_steps_get_no_access_token():
    _, steps = _azure_steps()
    for s in steps:
        if "script" in s and s["script"].startswith("pr-agent scan"):
            assert s["env"] == {"LLM_API_KEY": "$(LLM_API_KEY)"}


def _workflow(name):
    doc = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    # PyYAML (YAML 1.1) reads the bare key `on` as boolean True.
    return doc, doc.get("on", doc.get(True))


def _run_steps(job):
    return [s["run"] for s in job["steps"] if "run" in s]


def _uses(job):
    return [s["uses"] for s in job["steps"] if "uses" in s]


def test_ci_workflow():
    doc, on = _workflow("ci.yml")
    assert set(on) == {"push", "pull_request"}
    (job,) = doc["jobs"].values()
    runs = _run_steps(job)
    assert runs.index("scripts/fetch-gitleaks.sh") < runs.index(
        "docker build --platform linux/amd64 --target test ."
    )


def test_release_workflow():
    doc, on = _workflow("release.yml")
    assert on == {"push": {"tags": ["v*"]}}
    assert doc["permissions"] == {"contents": "write", "packages": "write"}
    (job,) = doc["jobs"].values()
    runs = _run_steps(job)
    assert runs[0] == "scripts/fetch-gitleaks.sh"
    assert "docker build --platform linux/amd64 --target test ." in runs
    assert any(r.endswith("scripts/build-bundle.sh") for r in runs)
    uses = _uses(job)
    for action in (
        "docker/setup-qemu-action@v3",
        "docker/setup-buildx-action@v3",
        "docker/login-action@v3",
        "docker/build-push-action@v6",
        "softprops/action-gh-release@v2",
    ):
        assert action in uses
    steps = {s.get("uses"): s for s in job["steps"]}
    login = steps["docker/login-action@v3"]["with"]
    assert login == {
        "registry": "ghcr.io",
        "username": "${{ github.actor }}",
        "password": "${{ secrets.GITHUB_TOKEN }}",
    }
    push = steps["docker/build-push-action@v6"]["with"]
    assert push["platforms"] == "linux/amd64,linux/arm64"
    assert push["push"] is True
    assert push["context"] == "."
    assert push["tags"] == "${{ steps.image.outputs.tags }}"  # see the test below
    assert "dist/pr-agent-bundle-*.tar.gz" in steps["softprops/action-gh-release@v2"]["with"]["files"]


@pytest.mark.parametrize("ref,latest", [("v0.2.0", True), ("v0.2.0-rc1", False)])
def test_release_moves_latest_only_for_final_tags(tmp_path, ref, latest):
    doc, _ = _workflow("release.yml")
    (job,) = doc["jobs"].values()
    [step] = [s for s in job["steps"] if s.get("id") == "image"]
    out = tmp_path / "out"
    env = {"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(out),
           "GITHUB_REPOSITORY_OWNER": "Acme", "GITHUB_REF_NAME": ref}
    subprocess.run(["bash", "-e", "-c", step["run"]], env=env, check=True)
    values = dict(line.split("=", 1) for line in out.read_text().splitlines())
    image = "ghcr.io/acme/airgaped-pr-agent"
    assert values["name"] == image
    expected = [f"{image}:{ref}"] + ([f"{image}:latest"] if latest else [])
    assert values["tags"].split(",") == expected
