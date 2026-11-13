from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from .models import Severity


class ConfigError(Exception):
    pass


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChecksConfig(_Section):
    secrets: bool
    non_english: bool
    security: bool


class PathsConfig(_Section):
    include: list[str]
    exclude: list[str]


class SecurityConfig(_Section):
    min_severity: Severity
    context_lines: int


class NonEnglishConfig(_Section):
    min_words: int
    min_confidence: float
    exclude: list[str]


class AllowEntry(_Section):
    fingerprint: str | None = None
    path: str | None = None

    @model_validator(mode="after")
    def _require_one(self) -> "AllowEntry":
        if self.fingerprint is None and self.path is None:
            raise ValueError("allowlist entry needs a fingerprint or a path")
        return self


class SecretsConfig(_Section):
    allowlist: list[AllowEntry]


class LLMConfig(_Section):
    prompt_token_budget: int
    concurrency: int
    timeout_seconds: int
    retries: int
    max_requests_per_mr: int
    max_requests_full_scan: int
    json_mode: bool


class FullScanConfig(_Section):
    fail_on_secrets: bool
    sarif: bool


class Config(_Section):
    checks: ChecksConfig
    paths: PathsConfig
    security: SecurityConfig
    non_english: NonEnglishConfig
    secrets: SecretsConfig
    llm: LLMConfig
    full_scan: FullScanConfig


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, val in over.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], val)
        else:
            out[key] = val
    return out


def load_config(repo: Path) -> Config:
    defaults = yaml.safe_load(
        resources.files("airgap_pr_agent").joinpath("defaults.yml").read_text(encoding="utf-8")
    )
    data = defaults
    repo_file = Path(repo) / ".pr-agent.yml"
    if repo_file.is_file():
        try:
            override = yaml.safe_load(repo_file.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{repo_file.name}: invalid YAML: {exc}") from exc
        if not isinstance(override, dict):
            raise ConfigError(f"{repo_file.name}: top level must be a mapping")
        data = _merge(defaults, override)
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"invalid configuration: {details}") from exc
