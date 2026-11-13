from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Check(str, Enum):
    SECRETS = "secrets"
    NON_ENGLISH = "non_english"
    SECURITY = "security"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


@dataclass(frozen=True)
class Finding:
    check: Check
    path: str
    line: int | None  # None means a summary-level finding
    severity: Severity
    title: str
    message: str
    fingerprint: str
    commit: str | None = None
    rule: str = ""
    suggestion: str | None = None


@dataclass
class CheckResult:
    check: Check
    findings: list[Finding]
    status: Literal["ok", "skipped", "partial"] = "ok"
    note: str = ""
    unreviewed: list[str] = field(default_factory=list)


def fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
