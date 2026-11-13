from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from .checks.language import non_english_findings
from .checks.secrets import Redactor, redact_findings, run_gitleaks, secret_findings
from .checks.security import security_findings
from .config import Config
from .gitops import ChangedFile, DiffRefs, changed_files
from .markers import SUMMARY_MARKER, parse_fp
from .models import Check, CheckResult, Finding
from .paths import PathFilter
from .platforms.base import Platform, PlatformError, Thread
from .summary import render_inline, render_summary


def run_checks(
    repo: Path,
    changed: list[ChangedFile],
    refs: DiffRefs | None,
    cfg: Config,
    llm: Any,
    gitleaks_bin: str,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    redactor = Redactor([])
    if cfg.checks.secrets:
        if refs is not None:
            leaks = run_gitleaks(repo, "range", refs, bin=gitleaks_bin)
        else:
            leaks = run_gitleaks(repo, "dir", bin=gitleaks_bin)
        result, redactor = secret_findings(
            leaks, changed if refs is not None else None, cfg.secrets.allowlist
        )
        results.append(result)
    if cfg.checks.non_english:
        flt = PathFilter.from_globs(cfg.paths.include, cfg.paths.exclude, cfg.non_english.exclude)
        results.append(non_english_findings(changed, cfg.non_english, flt, redactor))
    if cfg.checks.security:
        flt = PathFilter.from_globs(cfg.paths.include, cfg.paths.exclude)
        results.append(
            security_findings(changed, llm, cfg.security, cfg.llm, redactor, flt)
        )
    redact_findings(results, redactor)
    return results


def reconcile(findings: list[Finding], threads: list[Thread], platform: Platform) -> None:
    current = {f.fingerprint for f in findings if f.line is not None}
    existing: set[str] = set()
    for t in threads:
        if SUMMARY_MARKER in t.body:
            continue
        fp = parse_fp(t.body)
        if fp is None:
            continue
        existing.add(fp)
        if t.resolved and fp in current:
            platform.set_resolved(t.id, False)
        elif not t.resolved and fp not in current:
            platform.set_resolved(t.id, True)
    posted: set[str] = set()
    for f in findings:
        if f.line is None or f.fingerprint in existing or f.fingerprint in posted:
            continue
        posted.add(f.fingerprint)
        platform.post_inline(f.path, f.line, render_inline(f))


def run_review(
    repo: Path, platform: Platform, cfg: Config, llm: Any, gitleaks_bin: str
) -> int:
    refs = platform.diff_refs()
    changed = changed_files(repo, refs)
    results = run_checks(repo, changed, refs, cfg, llm, gitleaks_bin)
    findings = [f for r in results for f in r.findings]
    blocked = any(f.check is Check.SECRETS for f in findings)
    try:
        threads = platform.list_threads()
        if platform.can_post_inline():
            reconcile(findings, threads, platform)
        existing = next((t for t in threads if SUMMARY_MARKER in t.body), None)
        platform.upsert_summary(render_summary(results, blocked), existing)
    except (httpx.HTTPError, PlatformError) as exc:
        print(f"pr-agent: could not post review comments: {type(exc).__name__}")
        for f in findings:
            print(f"{f.path}:{f.line if f.line is not None else '-'}: {f.title}")
    return 1 if blocked else 0
