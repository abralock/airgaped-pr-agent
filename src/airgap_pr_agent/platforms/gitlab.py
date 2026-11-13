from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from airgap_pr_agent.config import ConfigError
from airgap_pr_agent.gitops import DiffRefs

from .base import PlatformError, Thread


def refs_from_env(env: Mapping[str, str]) -> DiffRefs:
    base = env.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    head = env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA") or env.get("CI_COMMIT_SHA")
    if not base or not head:
        raise ConfigError(
            "GitLab MR refs unavailable: need CI_MERGE_REQUEST_DIFF_BASE_SHA and "
            "CI_COMMIT_SHA (run in a merge request pipeline)"
        )
    return DiffRefs(base, head)


class GitLabPlatform:
    def __init__(
        self,
        api_url: str,
        project_id: str,
        mr_iid: str,
        token: str,
        refs: DiffRefs,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._refs = refs
        self._mr = f"/projects/{project_id}/merge_requests/{mr_iid}"
        self._client = httpx.Client(
            base_url=api_url.rstrip("/"),
            headers={"PRIVATE-TOKEN": token},
            timeout=30,
            transport=transport,
        )
        self._version: dict[str, Any] | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> GitLabPlatform | None:
        token = env.get("PR_AGENT_GITLAB_TOKEN")
        if not token:
            return None
        try:
            api, project, iid = (
                env["CI_API_V4_URL"],
                env["CI_PROJECT_ID"],
                env["CI_MERGE_REQUEST_IID"],
            )
        except KeyError as exc:
            raise ConfigError(f"missing GitLab CI variable {exc.args[0]}") from None
        return cls(api, project, iid, token, refs_from_env(env))

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            resp = self._client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise PlatformError(f"GitLab {method} {path} failed: {type(exc).__name__}") from None
        if not resp.is_success:
            raise PlatformError(f"GitLab {method} {path} returned HTTP {resp.status_code}")
        return resp

    def _latest_version(self) -> dict[str, Any]:
        if self._version is None:
            versions = self._request("GET", f"{self._mr}/versions").json()
            if not versions:
                raise PlatformError("GitLab MR has no diff versions")
            self._version = versions[0]
        return self._version

    def diff_refs(self) -> DiffRefs:
        return self._refs

    def can_post_inline(self) -> bool:
        return self._latest_version()["head_commit_sha"] == self._refs.head

    def list_threads(self) -> list[Thread]:
        threads: list[Thread] = []
        page = "1"
        while page:
            resp = self._request(
                "GET", f"{self._mr}/discussions", params={"per_page": 100, "page": page}
            )
            for d in resp.json():
                notes = d.get("notes") or []
                if not notes:
                    continue
                first = notes[0]
                threads.append(
                    Thread(
                        id=str(d["id"]),
                        body=first.get("body", ""),
                        resolved=bool(first.get("resolved", False)),
                        note_id=str(first["id"]) if "id" in first else None,
                    )
                )
            page = resp.headers.get("X-Next-Page", "")
        return threads

    def post_inline(self, path: str, line: int, body: str) -> None:
        v = self._latest_version()
        position = {
            "position_type": "text",
            "base_sha": v["base_commit_sha"],
            "start_sha": v["start_commit_sha"],
            "head_sha": v["head_commit_sha"],
            "new_path": path,
            "new_line": line,
        }
        self._request(
            "POST", f"{self._mr}/discussions", json={"body": body, "position": position}
        )

    def set_resolved(self, thread_id: str, resolved: bool) -> None:
        self._request(
            "PUT",
            f"{self._mr}/discussions/{thread_id}",
            params={"resolved": "true" if resolved else "false"},
        )

    def upsert_summary(self, body: str, existing: Thread | None) -> None:
        if existing is None or existing.note_id is None:
            self._request("POST", f"{self._mr}/notes", json={"body": body})
        else:
            self._request("PUT", f"{self._mr}/notes/{existing.note_id}", json={"body": body})
