"""Deterministic secrets check backed by gitleaks.

Raw secret values live only in the in-memory leak dicts and the Redactor; they
are never placed in findings, log lines or exception messages.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

import pathspec

from airgap_pr_agent.config import AllowEntry
from airgap_pr_agent.gitops import ChangedFile, DiffRefs
from airgap_pr_agent.models import Check, CheckResult, Finding, Severity, fingerprint

_KEPT_FIELDS = ("RuleID", "Description", "File", "StartLine", "Secret", "Commit")
_STDERR_LIMIT = 500
_TIMEOUT_SECONDS = 600
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ERR_LINE = re.compile(r"(^|\s)ERR(\s|$)")
_BUNDLED_CONFIG = Path(__file__).with_name("gitleaks.toml")
_MIN_LINE_REDACT = 8


class SecretScanError(Exception):
    pass


def mask(secret: str) -> str:
    return "****" if len(secret) < 8 else secret[:4] + "****"


class Redactor:
    def __init__(self, secrets: Iterable[str]) -> None:
        # Longest first so a secret that contains another is replaced whole.
        targets: dict[str, str] = {}
        for s in secrets:
            if not s:
                continue
            targets[s] = mask(s)
            # Multi-line secrets (private keys) appear line by line in diffs/CRLF text.
            lines = s.splitlines()
            if len(lines) > 1:
                for line in lines:
                    line = line.strip("\r")
                    if len(line) >= _MIN_LINE_REDACT:
                        targets.setdefault(line, mask(line))
        self._targets = sorted(targets.items(), key=lambda kv: len(kv[0]), reverse=True)

    def redact(self, text: str) -> str:
        for raw, masked in self._targets:
            text = text.replace(raw, masked)
        return text


def _relative_posix(file: str, repo: Path) -> str:
    candidates = [str(repo), str(repo.resolve())]
    norm = file
    for base in candidates:
        if norm == base:
            break
        prefix = base.rstrip(os.sep) + os.sep
        if norm.startswith(prefix):
            norm = norm[len(prefix):]
            break
    return Path(norm).as_posix()


def _git_ok(repo: Path, *args: str) -> bool:
    try:
        r = subprocess.run(["git", *args], cwd=repo, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _git_dir(repo: Path) -> Path:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--absolute-git-dir"], cwd=repo, capture_output=True, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SecretScanError("could not run git") from None
    if r.returncode != 0:
        raise SecretScanError("not a git repository; cannot scan")
    return Path(r.stdout.decode("utf-8", "replace").strip())


def _verify_git_inputs(repo: Path, mode: str, refs: DiffRefs | None) -> None:
    # gitleaks logs git failures but still exits 0 with an empty report; fail closed.
    if mode in ("range", "history"):
        _git_dir(repo)
    if mode == "range" and refs is not None:
        for ref in (refs.base, refs.head):
            if ref.startswith("-") or not _git_ok(
                repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"
            ):
                raise SecretScanError(f"git ref is not available in this checkout: {ref[:40]}")


def _clean_stderr(raw: bytes) -> str:
    return _ANSI.sub("", raw.decode("utf-8", "replace"))


def run_gitleaks(
    repo: Path,
    mode: Literal["range", "dir", "history"],
    refs: DiffRefs | None = None,
    bin: str = "gitleaks",
) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        if mode == "range" and refs is None:
            raise SecretScanError("range mode requires refs")
        if mode in ("range", "dir", "history"):
            _verify_git_inputs(repo, mode, refs)
        empty_ignore = Path(tmp) / "ignore"
        empty_ignore.mkdir()
        base = [bin]
        # In git modes gitleaks reads <source>/.gitleaksignore from the working tree
        # even with --gitleaks-ignore-path; scanning the git dir itself avoids that.
        source = _git_dir(repo) if mode in ("range", "history") else repo
        if mode == "range":
            assert refs is not None
            base += ["git", f"--log-opts={refs.base}..{refs.head}"]
        elif mode == "dir":
            base += ["dir"]
        elif mode == "history":
            base += ["git"]
        else:
            raise SecretScanError(f"unknown scan mode: {mode}")
        cmd = base + [
            "--no-banner", "--exit-code", "0",
            "--report-format", "json", "--report-path", str(report),
            # Only the .pr-agent.yml allowlist may suppress findings: ignore any
            # repo-controlled config, .gitleaksignore and inline gitleaks:allow.
            "--config", str(_BUNDLED_CONFIG),
            "--gitleaks-ignore-path", str(empty_ignore),
            "--ignore-gitleaks-allow",
            str(source),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=_TIMEOUT_SECONDS)
        except OSError as e:
            raise SecretScanError(f"could not run gitleaks: {e.strerror or type(e).__name__}") from None
        except subprocess.TimeoutExpired:
            raise SecretScanError(f"gitleaks timed out after {_TIMEOUT_SECONDS}s") from None
        stderr = _clean_stderr(proc.stderr)
        if proc.returncode != 0:
            raise SecretScanError(f"gitleaks exited with {proc.returncode}: {stderr[-_STDERR_LIMIT:]}")
        if any(_ERR_LINE.search(line) for line in stderr.splitlines()):
            raise SecretScanError(f"gitleaks reported errors: {stderr[-_STDERR_LIMIT:]}")
        try:
            raw = report.read_bytes()
        except OSError:
            raise SecretScanError("gitleaks produced no report") from None
        finally:
            report.unlink(missing_ok=True)
    try:
        if not raw.strip():
            raise SecretScanError("gitleaks report was empty")
        data = json.loads(raw)
    except ValueError:
        raise SecretScanError("gitleaks report was not valid JSON") from None
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        raise SecretScanError("gitleaks report had an unexpected shape")
    leaks = []
    for d in data:
        leak = {k: d.get(k) for k in _KEPT_FIELDS}
        leak["File"] = _relative_posix(str(leak["File"] or ""), repo)
        leaks.append(leak)
    return leaks


def _allowed(allowlist: list[AllowEntry], fp: str, path: str) -> bool:
    for entry in allowlist:
        # Empty strings are treated as unset; an entry with nothing usable never matches.
        want_fp = entry.fingerprint or None
        want_path = entry.path or None
        if want_fp is None and want_path is None:
            continue
        if want_fp is not None and want_fp != fp:
            continue
        if want_path is not None and not pathspec.PathSpec.from_lines(
            "gitwildmatch", [want_path]
        ).match_file(path):
            continue
        return True
    return False


def secret_findings(
    leaks: list[dict],
    changed: list[ChangedFile] | None,
    allowlist: list[AllowEntry],
) -> tuple[CheckResult, Redactor]:
    by_path = {c.path: c for c in changed} if changed is not None else None
    best: dict[str, Finding] = {}
    secrets: list[str] = []
    for leak in leaks:
        secret = leak["Secret"] or ""
        secrets.append(secret)
        path, rule = leak["File"], leak["RuleID"]
        fp = fingerprint("secrets", rule, path, hashlib.sha256(secret.encode("utf-8")).hexdigest())
        if _allowed(allowlist, fp, path):
            continue
        line: int | None = leak.get("StartLine")
        if by_path is not None:
            cf = by_path.get(path)
            first = secret.splitlines()[0] if secret.splitlines() else ""
            text = cf.added.get(line) if cf is not None and line is not None else None
            line = line if text is not None and first and first in text else None
        finding = Finding(
            check=Check.SECRETS,
            path=path,
            line=line,
            severity=Severity.HIGH,
            title=f"Hardcoded secret ({leak['Description']})",
            message=(
                f"Possible secret `{mask(secret)}` detected by rule `{rule}`. "
                f"Remove it and rotate the credential. If this is a false positive, "
                f"allowlist fingerprint `{fp}`."
            ),
            fingerprint=fp,
            commit=leak.get("Commit") or None,
            rule=rule,
        )
        prev = best.get(fp)
        if prev is None or (prev.line is None and finding.line is not None):
            best[fp] = finding
    return CheckResult(Check.SECRETS, list(best.values())), Redactor(secrets)
