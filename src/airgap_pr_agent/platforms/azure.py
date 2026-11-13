from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from airgap_pr_agent.config import ConfigError
from airgap_pr_agent.gitops import DiffRefs, GitError, _git, merge_base

from .base import PlatformError, Thread

_RESOLVED = {"fixed", "closed", "wontFix", "byDesign"}
_DEFAULT_API_VERSION = "6.0"


def refs_from_repo(repo: Path) -> DiffRefs:
    """ADO PR builds check out a merge commit: HEAD^1 is the target, HEAD^2 the source."""
    try:
        head = _git(repo, "rev-parse", "--verify", "HEAD^2").decode().strip()
        target = _git(repo, "rev-parse", "--verify", "HEAD^1").decode().strip()
        return DiffRefs(merge_base(repo, target, head), head)
    except GitError:
        raise ConfigError(
            "Azure DevOps PR refs unavailable: HEAD is not a pull request merge commit "
            "(run in a pull request validation build with full history)"
        ) from None


def _q(value: str) -> str:
    return quote(value, safe="")


class AzurePlatform:
    def __init__(
        self,
        collection_uri: str,
        project: str,
        repo_id: str,
        pr_id: str,
        token: str,
        refs: DiffRefs,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._refs = refs
        self._pr = f"{_q(project)}/_apis/git/repositories/{_q(repo_id)}/pullRequests/{_q(pr_id)}"
        self._api_version = os.environ.get("PR_AGENT_ADO_API_VERSION") or _DEFAULT_API_VERSION
        self._client = httpx.Client(
            base_url=collection_uri.rstrip("/") + "/",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
            transport=transport,
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str], repo: Path) -> AzurePlatform | None:
        token = env.get("SYSTEM_ACCESSTOKEN")
        if not token:
            return None
        try:
            uri, project, repo_id, pr_id = (
                env["SYSTEM_COLLECTIONURI"],
                env["SYSTEM_TEAMPROJECTID"],
                env["BUILD_REPOSITORY_ID"],
                env["SYSTEM_PULLREQUEST_PULLREQUESTID"],
            )
        except KeyError as exc:
            raise ConfigError(
                f"missing Azure DevOps variable {exc.args[0]} (run in a pull request build)"
            ) from None
        return cls(uri, project, repo_id, pr_id, token, refs_from_repo(repo))

    def _request(self, method: str, suffix: str = "", **kw: Any) -> httpx.Response:
        path = self._pr + suffix
        try:
            resp = self._client.request(
                method, path, params={"api-version": self._api_version}, **kw
            )
        except httpx.HTTPError as exc:
            raise PlatformError(f"Azure DevOps {method} {path} failed: {type(exc).__name__}") from None
        if not resp.is_success:
            raise PlatformError(f"Azure DevOps {method} {path} returned HTTP {resp.status_code}")
        return resp

    def diff_refs(self) -> DiffRefs:
        return self._refs

    def can_post_inline(self) -> bool:
        pr = self._request("GET").json()
        return (pr.get("lastMergeSourceCommit") or {}).get("commitId") == self._refs.head

    def list_threads(self) -> list[Thread]:
        threads: list[Thread] = []
        for t in self._request("GET", "/threads").json().get("value", []):
            comments = t.get("comments") or []
            if not comments:
                continue
            first = comments[0]
            threads.append(
                Thread(
                    id=str(t["id"]),
                    body=first.get("content", ""),
                    resolved=t.get("status") in _RESOLVED,
                    note_id=str(first["id"]) if "id" in first else None,
                )
            )
        return threads

    @staticmethod
    def _comment(body: str) -> list[dict[str, Any]]:
        return [{"parentCommentId": 0, "content": body, "commentType": 1}]

    def post_inline(self, path: str, line: int, body: str) -> None:
        pos = {"line": line, "offset": 1}
        self._request(
            "POST",
            "/threads",
            json={
                "comments": self._comment(body),
                "status": "active",
                "threadContext": {
                    "filePath": "/" + path,
                    "rightFileStart": pos,
                    "rightFileEnd": dict(pos),
                },
            },
        )

    def set_resolved(self, thread_id: str, resolved: bool) -> None:
        self._request(
            "PATCH",
            f"/threads/{_q(thread_id)}",
            json={"status": "fixed" if resolved else "active"},
        )

    def upsert_summary(self, body: str, existing: Thread | None) -> None:
        if existing is None or existing.note_id is None:
            # "closed" so the summary never blocks a comment-resolution policy.
            self._request(
                "POST", "/threads", json={"comments": self._comment(body), "status": "closed"}
            )
        else:
            self._request(
                "PATCH",
                f"/threads/{_q(existing.id)}/comments/{_q(existing.note_id)}",
                json={"content": body},
            )
