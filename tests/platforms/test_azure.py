import json

import httpx
import pytest

from airgap_pr_agent.cli import main
from airgap_pr_agent.config import ConfigError
from airgap_pr_agent.gitops import DiffRefs
from airgap_pr_agent.platforms.azure import AzurePlatform, refs_from_repo
from airgap_pr_agent.platforms.base import LogOnlyPlatform, PlatformError, Thread

TOKEN = "ado-system-token-secret"
URI = "https://dev.azure.com/org/"


def make(handler, head="H", uri=URI, project="proj-id", repo="repo-id", pr="5"):
    calls = []

    def wrapped(request):
        calls.append(request)
        return handler(request)

    p = AzurePlatform(
        uri, project, repo, pr, TOKEN, DiffRefs("B", head),
        transport=httpx.MockTransport(wrapped),
    )
    return p, calls


def ok(request):
    return httpx.Response(200, json={})


def test_refs_from_merge_commit(git_repo):
    git_repo.commit({"a": "1"}, "root")
    git_repo.branch("feature")
    tip = git_repo.commit({"f": "x"}, "feat")
    git_repo.git("checkout", "-q", "main")
    mb_expected = git_repo.commit({"m": "y"}, "main work")
    git_repo.git("checkout", "-q", "feature")
    base_of_feature = git_repo.git("merge-base", "main", "feature")
    git_repo.git("checkout", "-q", "main")
    git_repo.git("merge", "--no-ff", "-q", "-m", "merge", "feature")
    refs = refs_from_repo(git_repo.path)
    assert refs.head == tip
    assert refs.base == base_of_feature
    assert mb_expected != base_of_feature


def test_refs_from_repo_fails_closed_without_merge_commit(git_repo):
    git_repo.commit({"a": "1"}, "root")
    git_repo.commit({"b": "2"}, "second")
    with pytest.raises(ConfigError, match="merge commit"):
        refs_from_repo(git_repo.path)


def test_list_threads_maps_status():
    def handler(request):
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        return httpx.Response(200, json={"value": [
            {"id": 1, "status": "fixed", "comments": [{"id": 1, "content": "a"}]},
            {"id": 2, "status": "active", "comments": [{"id": 4, "content": "b"}, {"id": 5, "content": "r"}]},
            {"id": 3, "status": "wontFix", "comments": [{"id": 1, "content": "c"}]},
            {"id": 6, "status": "closed", "comments": [{"id": 1, "content": "d"}]},
            {"id": 7, "status": "byDesign", "comments": [{"id": 1, "content": "e"}]},
            {"id": 8, "comments": [{"id": 1, "content": "f"}]},
            {"id": 9, "status": "active", "comments": []},
        ]})

    p, calls = make(handler)
    assert p.list_threads() == [
        Thread("1", "a", True, "1"),
        Thread("2", "b", False, "4"),
        Thread("3", "c", True, "1"),
        Thread("6", "d", True, "1"),
        Thread("7", "e", True, "1"),
        Thread("8", "f", False, "1"),
    ]
    assert calls[0].url.path == "/org/proj-id/_apis/git/repositories/repo-id/pullRequests/5/threads"


def test_post_inline_thread_context():
    p, calls = make(ok)
    p.post_inline("src/a b.py", 12, "hello")
    post = calls[-1]
    assert post.method == "POST" and post.url.path.endswith("/pullRequests/5/threads")
    assert json.loads(post.content) == {
        "comments": [{"parentCommentId": 0, "content": "hello", "commentType": 1}],
        "status": "active",
        "threadContext": {
            "filePath": "/src/a b.py",
            "rightFileStart": {"line": 12, "offset": 1},
            "rightFileEnd": {"line": 12, "offset": 1},
        },
    }


def head_handler(sha):
    def handler(request):
        return httpx.Response(200, json={"lastMergeSourceCommit": {"commitId": sha}})
    return handler


def test_can_post_inline_false_when_head_moved():
    p, calls = make(head_handler("OTHER"), head="H")
    assert p.can_post_inline() is False
    p, calls = make(head_handler("H"), head="H")
    assert p.can_post_inline() is True
    assert calls[0].method == "GET" and calls[0].url.path.endswith("/pullRequests/5")


def test_set_resolved_patch():
    p, calls = make(ok)
    p.set_resolved("3", True)
    p.set_resolved("3", False)
    assert [c.method for c in calls] == ["PATCH", "PATCH"]
    assert calls[0].url.path.endswith("/pullRequests/5/threads/3")
    assert json.loads(calls[0].content) == {"status": "fixed"}
    assert json.loads(calls[1].content) == {"status": "active"}


def test_summary_post_closed_then_patch_comment():
    p, calls = make(ok)
    p.upsert_summary("s1", None)
    p.upsert_summary("s2", Thread("8", "old", False, note_id="4"))
    assert calls[0].method == "POST" and calls[0].url.path.endswith("/pullRequests/5/threads")
    assert json.loads(calls[0].content) == {
        "comments": [{"parentCommentId": 0, "content": "s1", "commentType": 1}],
        "status": "closed",
    }
    assert calls[1].method == "PATCH"
    assert calls[1].url.path.endswith("/pullRequests/5/threads/8/comments/4")
    assert json.loads(calls[1].content) == {"content": "s2"}


def test_summary_without_note_id_posts_new_thread():
    p, calls = make(ok)
    p.upsert_summary("s", Thread("8", "old", False, note_id=None))
    assert calls[0].method == "POST"


def test_collection_uri_normalised_and_ids_quoted():
    for uri in ("https://dev.azure.com/org", "https://dev.azure.com/org/"):
        p, calls = make(ok, uri=uri, project="My Proj", repo="r/../x", pr="5")
        p.set_resolved("3", True)
        assert calls[0].url.raw_path.decode().startswith(
            "/org/My%20Proj/_apis/git/repositories/r%2F..%2Fx/pullRequests/5/threads/3"
        )


def test_api_version_default_and_env_override(monkeypatch):
    monkeypatch.delenv("PR_AGENT_ADO_API_VERSION", raising=False)
    p, calls = make(ok)
    p.set_resolved("1", True)
    assert calls[0].url.params["api-version"] == "6.0"
    monkeypatch.setenv("PR_AGENT_ADO_API_VERSION", "5.0")
    p, calls = make(head_handler("H"))
    p.can_post_inline()
    p.post_inline("a", 1, "x")
    p.set_resolved("1", False)
    p.upsert_summary("s", None)
    p.upsert_summary("s", Thread("1", "o", False, "2"))
    assert len(calls) == 5
    assert all(c.url.params["api-version"] == "5.0" for c in calls)


def test_errors_raise_platform_error_without_token():
    p, _ = make(lambda r: httpx.Response(401, text=TOKEN))
    with pytest.raises(PlatformError) as ei:
        p.list_threads()
    assert "401" in str(ei.value) and TOKEN not in str(ei.value)

    def boom(request):
        raise httpx.ConnectError(f"cannot connect {TOKEN}")

    p, _ = make(boom)
    with pytest.raises(PlatformError) as ei:
        p.list_threads()
    assert TOKEN not in str(ei.value) and ei.value.__cause__ is None


def test_from_env_none_without_token(git_repo):
    assert AzurePlatform.from_env({"SYSTEM_COLLECTIONURI": URI}, git_repo.path) is None


def test_from_env_missing_variable(git_repo):
    with pytest.raises(ConfigError, match="SYSTEM_TEAMPROJECTID"):
        AzurePlatform.from_env(
            {"SYSTEM_ACCESSTOKEN": TOKEN, "SYSTEM_COLLECTIONURI": URI,
             "BUILD_REPOSITORY_ID": "r", "SYSTEM_PULLREQUEST_PULLREQUESTID": "5"},
            git_repo.path,
        )


def _merge_repo(git_repo):
    git_repo.commit({"a": "1"}, "root")
    git_repo.branch("feature")
    tip = git_repo.commit({"f": "x"}, "feat")
    git_repo.git("checkout", "-q", "main")
    git_repo.commit({"m": "y"}, "main work")
    git_repo.git("merge", "--no-ff", "-q", "-m", "merge", "feature")
    return tip


def test_from_env_builds_platform(git_repo):
    tip = _merge_repo(git_repo)
    env = {
        "SYSTEM_ACCESSTOKEN": TOKEN, "SYSTEM_COLLECTIONURI": URI,
        "SYSTEM_TEAMPROJECTID": "p", "BUILD_REPOSITORY_ID": "r",
        "SYSTEM_PULLREQUEST_PULLREQUESTID": "5",
    }
    p = AzurePlatform.from_env(env, git_repo.path)
    assert p.diff_refs().head == tip


def test_cli_auto_detects_azure(monkeypatch, capsys, git_repo):
    import airgap_pr_agent.cli as cli

    tip = _merge_repo(git_repo)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.delenv("SYSTEM_ACCESSTOKEN", raising=False)
    args = cli._build_parser().parse_args(["review", "--repo", str(git_repo.path)])
    platform = cli._platform(args)
    assert isinstance(platform, LogOnlyPlatform)
    assert platform.diff_refs().head == tip
    assert "SYSTEM_ACCESSTOKEN" in capsys.readouterr().err

    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", TOKEN)
    for k, v in {
        "SYSTEM_COLLECTIONURI": URI, "SYSTEM_TEAMPROJECTID": "p",
        "BUILD_REPOSITORY_ID": "r", "SYSTEM_PULLREQUEST_PULLREQUESTID": "5",
    }.items():
        monkeypatch.setenv(k, v)
    assert isinstance(cli._platform(args), AzurePlatform)


def test_cli_azure_outside_pr_build_exits_3(monkeypatch, capsys, git_repo):
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.delenv("SYSTEM_ACCESSTOKEN", raising=False)
    git_repo.commit({"a": "1"}, "root")
    assert main(["review", "--repo", str(git_repo.path)]) == 3
    assert "merge commit" in capsys.readouterr().err
