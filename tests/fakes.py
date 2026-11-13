from airgap_pr_agent.platforms.base import PlatformError, Thread


class FakePlatform:
    def __init__(self, refs, threads=None, inline_ok=True, fail_posts=False):
        self.refs = refs
        self.threads = list(threads or [])
        self.inline_ok = inline_ok
        self.fail_posts = fail_posts
        self.posted: list[tuple[str, int, str]] = []
        self.resolved: list[tuple[str, bool]] = []
        self.summaries: list[str] = []
        self.summary_existing: list[Thread | None] = []

    def diff_refs(self):
        return self.refs

    def can_post_inline(self):
        return self.inline_ok

    def list_threads(self):
        return self.threads

    def _maybe_fail(self):
        if self.fail_posts:
            raise PlatformError("boom")

    def post_inline(self, path, line, body):
        self._maybe_fail()
        self.posted.append((path, line, body))

    def set_resolved(self, thread_id, resolved):
        self._maybe_fail()
        self.resolved.append((thread_id, resolved))

    def upsert_summary(self, body, existing):
        self._maybe_fail()
        self.summaries.append(body)
        self.summary_existing.append(existing)
