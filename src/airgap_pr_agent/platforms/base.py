from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any, Protocol

from airgap_pr_agent.gitops import DiffRefs


class PlatformError(Exception):
    """Raised by adapters on any non-2xx API response."""


_TLS_HINT = (
    " (TLS verification failed: set SSL_CERT_FILE to a CA bundle file that "
    "includes your internal CA)"
)


def _clean(text: str, secret: str) -> str:
    text = " ".join(text.split())
    if secret:
        text = text.replace(secret, "****")
    return text[:300]


def transport_detail(exc: Exception, secret: str) -> str:
    """Why a request never got an answer. The token is scrubbed from the text."""
    text = _clean(str(exc), secret)
    detail = f"{type(exc).__name__}: {text}" if text else type(exc).__name__
    if "CERTIFICATE_VERIFY_FAILED" in text:
        detail += _TLS_HINT
    return detail


def response_detail(resp: Any, secret: str, hints: Mapping[int, str]) -> str:
    """Status, the server's own error message, and what to check for that status."""
    detail = f"HTTP {resp.status_code}"
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        msg = body.get("message") or body.get("error")
        if msg:
            detail += f": {_clean(str(msg), secret)}"
    hint = hints.get(resp.status_code)
    if hint:
        detail += f" ({hint})"
    return detail


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
