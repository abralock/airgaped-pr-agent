from __future__ import annotations

from .markers import SUMMARY_MARKER, fp_marker
from .models import Check, CheckResult, Finding, Severity

TITLES = {
    Check.SECRETS: "Secrets",
    Check.NON_ENGLISH: "Non-English",
    Check.SECURITY: "Security",
}


def render_inline(f: Finding) -> str:
    parts = [f"**{f.severity.value.upper()}: {f.title}**", "", f.message]
    if f.suggestion:
        parts += ["", "```suggestion", f.suggestion, "```"]
    parts += ["", fp_marker(f.fingerprint)]
    return "\n".join(parts)


def render_summary(results: list[CheckResult], blocked: bool) -> str:
    lines = [SUMMARY_MARKER, "## PR Agent review", ""]
    all_findings = [f for r in results for f in r.findings]
    if not all_findings:
        lines.append("✅ No issues found.")
        lines.append("")
    else:
        lines += ["| Check | High | Medium | Low |", "|---|---|---|---|"]
        for r in results:
            if r.status == "skipped":
                continue
            counts = {s: sum(1 for f in r.findings if f.severity == s) for s in Severity}
            lines.append(
                f"| {TITLES[r.check]} | {counts[Severity.HIGH]} | "
                f"{counts[Severity.MEDIUM]} | {counts[Severity.LOW]} |"
            )
        lines.append("")
    n_secrets = sum(
        1 for r in results if r.check is Check.SECRETS for _ in r.findings
    )
    if blocked:
        lines += [
            f"**Merge blocked:** {n_secrets} hardcoded secret(s) found. Remove them and "
            "**rotate each secret**: deleting it from the code does not remove it from git history.",
            "",
        ]
    summary_level = [f for f in all_findings if f.line is None]
    if summary_level:
        lines.append("**Findings without an inline location:**")
        for f in summary_level:
            where = f"`{f.path}`"
            if f.commit:
                where += f" (commit `{f.commit[:8]}`)"
            lines.append(f"- {where}: {f.title}. {f.message}")
        lines.append("")
    for r in results:
        title = TITLES[r.check]
        if r.status == "skipped":
            lines.append(f"⚠️ {title} check skipped: {r.note}")
        elif r.status == "partial":
            lines.append(f"⚠️ {title} check incomplete: {r.note}")
    unreviewed = sorted({p for r in results for p in r.unreviewed})
    if unreviewed:
        lines += ["", "Files not reviewed by the model:"]
        lines += [f"- `{p}`" for p in unreviewed]
    return "\n".join(lines).rstrip() + "\n"
