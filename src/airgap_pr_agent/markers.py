from __future__ import annotations

import re

SUMMARY_MARKER = "<!-- pr-agent:summary -->"
_FP = re.compile(r"<!-- pr-agent:fp=([0-9A-Za-z]+) -->")


def fp_marker(fp: str) -> str:
    return f"<!-- pr-agent:fp={fp} -->"


def parse_fp(body: str) -> str | None:
    # The agent writes its marker last; an earlier one is quoted text.
    found = _FP.findall(body)
    return found[-1] if found else None


def is_summary(body: str) -> bool:
    """The summary body starts with its marker; elsewhere it is quoted text."""
    return body.lstrip().startswith(SUMMARY_MARKER)


def strip_comment_markers(text: str) -> str:
    """Remove HTML comment delimiters, so untrusted text cannot forge a marker."""
    while "<!--" in text or "-->" in text:
        text = text.replace("<!--", "").replace("-->", "")
    return text
