import pytest

from airgap_pr_agent.config import ConfigError, load_config
from airgap_pr_agent.models import Severity


def test_defaults_load_without_repo_file(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg.checks.secrets and cfg.checks.non_english and cfg.checks.security
    assert cfg.security.min_severity == Severity.MEDIUM
    assert cfg.non_english.min_words == 4
    l = cfg.llm
    assert (l.prompt_token_budget, l.concurrency, l.timeout_seconds, l.retries,
            l.max_requests_per_mr, l.max_requests_full_scan) == (8000, 2, 120, 2, 30, 300)
    assert cfg.full_scan.fail_on_secrets is True and cfg.full_scan.sarif is False


def test_repo_file_deep_merges(tmp_path):
    (tmp_path / ".pr-agent.yml").write_text("security:\n  min_severity: high\nllm:\n  concurrency: 4\n")
    cfg = load_config(tmp_path)
    assert cfg.security.min_severity == Severity.HIGH
    assert cfg.security.context_lines == 20
    assert cfg.llm.concurrency == 4 and cfg.llm.max_requests_per_mr == 30


def test_invalid_value_raises_config_error(tmp_path):
    (tmp_path / ".pr-agent.yml").write_text("security:\n  min_severity: urgent\n")
    with pytest.raises(ConfigError, match="min_severity"):
        load_config(tmp_path)


def test_allowlist_entry_requires_fingerprint_or_path(tmp_path):
    (tmp_path / ".pr-agent.yml").write_text("secrets:\n  allowlist:\n    - {fingerprint: abcd}\n    - {path: 'tests/**'}\n")
    assert [e.path for e in load_config(tmp_path).secrets.allowlist] == [None, "tests/**"]
    (tmp_path / ".pr-agent.yml").write_text("secrets:\n  allowlist:\n    - {}\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_malformed_yaml_raises_config_error(tmp_path):
    (tmp_path / ".pr-agent.yml").write_text("security: [unclosed\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)
