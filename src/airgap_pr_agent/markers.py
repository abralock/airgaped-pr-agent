from __future__ import annotations

import re

SUMMARY_MARKER = "<!-- pr-agent:summary -->"
_FP = re.compile(r"<!-- pr-agent:fp=([0-9A-Za-z]+) -->")


def fp_marker(fp: str) -> str:
    return f"<!-- pr-agent:fp={fp} -->"


def parse_fp(body: str) -> str | None:
    m = _FP.search(body)
    return m.group(1) if m else None
