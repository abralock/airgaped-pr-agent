import json

import httpx
import pytest

from airgap_pr_agent.cli import main
from airgap_pr_agent.gitops import DiffRefs
from airgap_pr_agent.platforms.base import LogOnlyPlatform, PlatformError, Thread
from airgap_pr_agent.platforms.gitlab import GitLabPlatform, refs_from_env

TOKEN = "glpat-secret-token-value"
VERSIONS = [
    {"base_commit_sha": "B", "start_commit_sha": "S", "head_commit_sha": "H"},
    {"base_commit_sha": "b0", "start_commit_sha": "s0", "head_commit_sha": "h0"},
]


def make(handler, head="H"):
    calls = []

    def wrapped(request):
        calls.append(request)
        return handler(request)

    p = GitLabPlatform(
        "https://gl.example/api/v4", "7", "3", TOKEN, DiffRefs("B", head),
        transport=httpx.MockTransport(wrapped),
    )
    return p, calls


def versions_handler(request):
    if request.url.path.endswith("/versions"):
        return httpx.Response(200, json=VERSIONS)
    return httpx.Response(201, json={})


def test_refs_prefers_source_branch_sha():
    env = {"CI_MERGE_REQUEST_DIFF_BASE_SHA": "b", "CI_COMMIT_SHA": "c"}
    assert refs_from_env(env) == DiffRefs("b", "c")
    env["CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"] = "s"
    assert refs_from_env(env) == DiffRefs("b", "s")


def test_list_threads_paginates_and_maps_first_note():
    def handler(request):
        assert request.headers["PRIVATE-TOKEN"] == TOKEN
        assert request.url.params["per_page"] == "100"
        if request.url.params.get("page") == "1":
            return httpx.Response(
                200,
                json=[{"id": "d1", "notes": [{"id": 11, "body": "one", "resolved": True},
                                             {"id": 12, "body": "reply", "resolved": False}]}],
                headers={"X-Next-Page": "2"},
            )
        return httpx.Response(
            200,
            json=[{"id": "d2", "notes": [{"id": 21, "body": "two", "resolved": False}]},
                  {"id": "d3", "notes": [{"id": 31, "body": "plain"}]}],
            headers={"X-Next-Page": ""},
        )

    p, calls = make(handler)
    assert p.list_threads() == [
        Thread("d1", "one", True, "11"),
        Thread("d2", "two", False, "21"),
        Thread("d3", "plain", False, "31"),
    ]
    assert len(calls) == 2


def test_post_inline_uses_versions_shas():
    p, calls = make(versions_handler)
    p.post_inline("a/b.py", 12, "hello")
    post = calls[-1]
    assert post.method == "POST" and post.url.path.endswith("/projects/7/merge_requests/3/discussions")
    assert json.loads(post.content) == {
        "body": "hello",
        "position": {
            "position_type": "text", "base_sha": "B", "start_sha": "S", "head_sha": "H",
            "new_path": "a/b.py", "new_line": 12,
        },
    }


def test_can_post_inline_false_when_head_moved():
    p, _ = make(versions_handler, head="OTHER")
    assert p.can_post_inline() is False
    p, _ = make(versions_handler, head="H")
    assert p.can_post_inline() is True


def test_set_resolved_puts_flag():
    p, calls = make(versions_handler)
    p.set_resolved("d1", True)
    p.set_resolved("d1", False)
    assert [c.method for c in calls] == ["PUT", "PUT"]
    assert calls[0].url.path.endswith("/discussions/d1")
    assert calls[0].url.params["resolved"] == "true"
    assert calls[1].url.params["resolved"] == "false"


def test_summary_post_then_put():
    p, calls = make(versions_handler)
    p.upsert_summary("s1", None)
    p.upsert_summary("s2", Thread("d", "old", False, note_id="9"))
    assert (calls[0].method, calls[0].url.path.rsplit("/", 1)[-1]) == ("POST", "notes")
    assert json.loads(calls[0].content) == {"body": "s1"}
    assert (calls[1].method, calls[1].url.path.endswith("/notes/9")) == ("PUT", True)
    assert json.loads(calls[1].content) == {"body": "s2"}


def test_errors_raise_platform_error_without_token():
    p, _ = make(lambda r: httpx.Response(403, text="nope"))
    with pytest.raises(PlatformError) as ei:
        p.list_threads()
    assert "403" in str(ei.value) and TOKEN not in str(ei.value)


def test_from_env_none_without_token():
    assert GitLabPlatform.from_env({"CI_API_V4_URL": "u"}) is None


def test_from_env_builds_platform():
    env = {
        "PR_AGENT_GITLAB_TOKEN": TOKEN, "CI_API_V4_URL": "https://gl/api/v4",
        "CI_PROJECT_ID": "7", "CI_MERGE_REQUEST_IID": "3",
        "CI_MERGE_REQUEST_DIFF_BASE_SHA": "b", "CI_COMMIT_SHA": "c",
    }
    assert GitLabPlatform.from_env(env).diff_refs() == DiffRefs("b", "c")


def test_cli_auto_detects_gitlab_and_falls_back_to_log_only(monkeypatch, capsys):
    import airgap_pr_agent.cli as cli

    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.delenv("PR_AGENT_GITLAB_TOKEN", raising=False)
    monkeypatch.setenv("CI_MERGE_REQUEST_DIFF_BASE_SHA", "b")
    monkeypatch.setenv("CI_COMMIT_SHA", "c")
    monkeypatch.delenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", raising=False)
    args = cli._build_parser().parse_args(["review"])
    platform = cli._platform(args)
    assert isinstance(platform, LogOnlyPlatform)
    assert platform.diff_refs() == DiffRefs("b", "c")
    assert "PR_AGENT_GITLAB_TOKEN" in capsys.readouterr().err


def test_cli_auto_azure_and_unknown(monkeypatch, capsys):
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.setenv("TF_BUILD", "True")
    assert main(["review"]) == 3
    assert "azure" in capsys.readouterr().err
    monkeypatch.delenv("TF_BUILD")
    assert main(["review"]) == 3
    assert "--platform" in capsys.readouterr().err
