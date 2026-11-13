"""JSON, HTML and SARIF reports for full-scan mode.

Findings already carry masked secret values; raw scanner output never reaches here.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from urllib.parse import quote

from jinja2 import Environment, PackageLoader

from .models import CheckResult, Finding, Severity
from .summary import TITLES

_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}


def _finding_dict(f: Finding) -> dict:
    return {
        "check": f.check.value,
        "path": f.path,
        "line": f.line,
        "severity": f.severity.value,
        "title": f.title,
        "message": f.message,
        "fingerprint": f.fingerprint,
        "commit": f.commit,
        "rule": f.rule,
        "suggestion": f.suggestion,
    }


def write_json(results: list[CheckResult], path: Path, repo_name: str = "") -> None:
    doc = {
        "version": 1,
        "repo": repo_name,
        "checks": [
            {
                "check": r.check.value,
                "status": r.status,
                "note": r.note,
                "unreviewed": list(r.unreviewed),
                "findings": [_finding_dict(f) for f in r.findings],
            }
            for r in results
        ],
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_html(results: list[CheckResult], path: Path, repo_name: str) -> None:
    env = Environment(loader=PackageLoader("airgap_pr_agent", "templates"), autoescape=True)
    sections = []
    for r in results:
        groups: dict[Severity, dict[str, list[Finding]]] = {}
        for sev in sorted(Severity, key=lambda s: -s.rank):
            by_file: dict[str, list[Finding]] = defaultdict(list)
            for f in r.findings:
                if f.severity is sev:
                    by_file[f.path].append(f)
            if by_file:
                groups[sev] = {p: sorted(fs, key=lambda x: x.line or 0) for p, fs in sorted(by_file.items())}
        sections.append({"title": TITLES[r.check], "result": r, "groups": groups})
    html = env.get_template("report.html.j2").render(
        repo_name=repo_name, sections=sections, total=sum(len(r.findings) for r in results)
    )
    path.write_text(html, encoding="utf-8")


def write_sarif(results: list[CheckResult], path: Path) -> None:
    findings = [f for r in results for f in r.findings]
    rules: dict[str, dict] = {}
    sarif_results = []
    for f in findings:
        rule_id = f"{f.check.value}/{f.rule or f.title}"
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": f.title}})
        physical: dict = {"artifactLocation": {"uri": quote(f.path, safe="/"), "uriBaseId": "%SRCROOT%"}}
        if f.line is not None:
            physical["region"] = {"startLine": f.line}
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.message}"},
                "locations": [{"physicalLocation": physical}],
                "partialFingerprints": {"prAgentFingerprint": f.fingerprint},
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "pr-agent", "rules": list(rules.values())}},
                "results": sarif_results,
            }
        ],
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
