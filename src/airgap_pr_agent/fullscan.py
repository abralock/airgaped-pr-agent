"""Full-repository scan: every tracked file, not just an MR diff."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .checks.language import non_english_findings
from .checks.secrets import Redactor, redact_findings, run_gitleaks, secret_findings
from .checks.security import security_findings
from .config import Config
from .gitops import tracked_files, whole_files
from .models import Check, CheckResult
from .paths import PathFilter
from .report import write_html, write_json, write_sarif
from .summary import TITLES


def _readable(repo: Path, path: str) -> bool:
    p = repo / path
    return p.is_file() and not p.is_symlink()


def run_full_scan(
    repo: Path, cfg: Config, llm: Any, gitleaks_bin: str, out_dir: Path, history: bool
) -> int:
    results: list[CheckResult] = []
    redactor = Redactor([])
    if cfg.checks.secrets:
        leaks = run_gitleaks(repo, "dir", bin=gitleaks_bin)
        if history:
            leaks += run_gitleaks(repo, "history", bin=gitleaks_bin)
        result, redactor = secret_findings(leaks, None, cfg.secrets.allowlist)
        seen: set[str] = set()
        unique = []
        for f in result.findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique.append(f)
        result.findings = unique
        results.append(result)

    ne_filter = PathFilter.from_globs(cfg.paths.include, cfg.paths.exclude, cfg.non_english.exclude)
    sec_filter = PathFilter.from_globs(cfg.paths.include, cfg.paths.exclude)
    candidates = [
        p for p in tracked_files(repo)
        if (ne_filter.allows(p) or sec_filter.allows(p)) and _readable(repo, p)
    ]
    files = whole_files(repo, candidates)
    if cfg.checks.non_english:
        results.append(non_english_findings(files, cfg.non_english, ne_filter, redactor))
    if cfg.checks.security:
        results.append(
            security_findings(files, llm, cfg.security, cfg.llm, redactor, sec_filter)
        )
    redact_findings(results, redactor)

    out_dir.mkdir(parents=True, exist_ok=True)
    name = repo.resolve().name
    write_json(results, out_dir / "report.json", name)
    write_html(results, out_dir / "report.html", name)
    if cfg.full_scan.sarif:
        write_sarif(results, out_dir / "report.sarif")
    for r in results:
        extra = f" ({r.status}: {r.note})" if r.status != "ok" else ""
        print(f"{TITLES[r.check]}: {len(r.findings)} finding(s){extra}")
    has_secrets = any(r.check is Check.SECRETS and r.findings for r in results)
    return 1 if has_secrets and cfg.full_scan.fail_on_secrets else 0
