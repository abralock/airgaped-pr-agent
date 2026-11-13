from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from airgap_pr_agent.gitops import DiffRefs


class PlatformError(Exception):
    """Raised by adapters on any non-2xx API response."""


@dataclass
class Thread:
    id: str
    body: str  # the first note
    resolved: bool
    note_id: str | None = None


class Platform(Protocol):
    def diff_refs(self) -> DiffRefs: ...

    def can_post_inline(self) -> bool: ...

    def list_threads(self) -> list[Thread]: ...

    def post_inline(self, path: str, line: int, body: str) -> None: ...

    def set_resolved(self, thread_id: str, resolved: bool) -> None: ...

    def upsert_summary(self, body: str, existing: Thread | None) -> None: ...


class LogOnlyPlatform:
    """Prints comments to stdout; has no threads. Used for local runs."""

    def __init__(self, refs: DiffRefs) -> None:
        self._refs = refs

    def diff_refs(self) -> DiffRefs:
        return self._refs

    def can_post_inline(self) -> bool:
        return True

    def list_threads(self) -> list[Thread]:
        return []

    def post_inline(self, path: str, line: int, body: str) -> None:
        print(f"--- {path}:{line}\n{body}\n")

    def set_resolved(self, thread_id: str, resolved: bool) -> None:
        pass

    def upsert_summary(self, body: str, existing: Thread | None) -> None:
        print(body)
