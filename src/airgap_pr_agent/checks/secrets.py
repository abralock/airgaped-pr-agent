"""Deterministic secrets check backed by gitleaks.

Raw secret values live only in the in-memory leak dicts and the Redactor; they
are never placed in findings, log lines or exception messages.
"""
from __future__ import annotations

import hashlib
import json
import os
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


class SecretScanError(Exception):
    pass


def mask(secret: str) -> str:
    return "****" if len(secret) < 8 else secret[:4] + "****"


class Redactor:
    def __init__(self, secrets: Iterable[str]) -> None:
        # Longest first so a secret that contains another is replaced whole.
        self._secrets = sorted({s for s in secrets if s}, key=len, reverse=True)

    def redact(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, mask(s))
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


def run_gitleaks(
    repo: Path,
    mode: Literal["range", "dir", "history"],
    refs: DiffRefs | None = None,
    bin: str = "gitleaks",
) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        base = [bin]
        if mode == "range":
            if refs is None:
                raise SecretScanError("range mode requires refs")
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
            str(repo),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True)
        except OSError as e:
            raise SecretScanError(f"could not run gitleaks: {e.strerror or type(e).__name__}") from None
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace")[-_STDERR_LIMIT:]
            raise SecretScanError(f"gitleaks exited with {proc.returncode}: {stderr}")
        try:
            raw = report.read_bytes()
        except OSError:
            raise SecretScanError("gitleaks produced no report") from None
        finally:
            report.unlink(missing_ok=True)
    try:
        data = json.loads(raw) if raw.strip() else []
    except ValueError:
        raise SecretScanError("gitleaks report was not valid JSON") from None
    if data is None:
        data = []
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
