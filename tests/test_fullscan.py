import json

import pytest

from airgap_pr_agent.cli import main
from airgap_pr_agent.config import load_config
from airgap_pr_agent.fullscan import run_full_scan
from conftest import GITLEAKS

TOKEN = "AKIAQYLPMN5HHHFPZAM2"
LEAKY = f'x = 1\ntoken = "{TOKEN}"\n'


def _scan(repo, cfg, out, history=False):
    return run_full_scan(repo.path, cfg, None, GITLEAKS, out, history)


def _no_secrets(cfg):
    cfg.checks.secrets = False
    return cfg


def test_writes_json_and_html_not_sarif_by_default(git_repo, tmp_cfg, tmp_path, capsys):
    git_repo.commit({"a.py": "x = 1\n"})
    out = tmp_path / "out"
    assert _scan(git_repo, _no_secrets(tmp_cfg), out) == 0
    assert (out / "report.json").is_file() and (out / "report.html").is_file()
    assert not (out / "report.sarif").exists()
    assert capsys.readouterr().out.strip()


def test_sarif_when_enabled(git_repo, tmp_cfg, tmp_path):
    git_repo.commit({"a.py": "# 这是一个中文注释，用于测试语言检测功能\nx = 1\n"})
    cfg = _no_secrets(tmp_cfg)
    cfg.full_scan.sarif = True
    out = tmp_path / "out"
    _scan(git_repo, cfg, out)
    sarif = json.loads((out / "report.sarif").read_text())
    findings = [f for c in json.loads((out / "report.json").read_text())["checks"] for f in c["findings"]]
    assert sarif["version"] == "2.1.0" and findings
    assert len(sarif["runs"][0]["results"]) == len(findings)


def test_excluded_paths_skip_language_check(git_repo, tmp_cfg, tmp_path):
    git_repo.commit({"vendor/a.py": "# 这是一个中文注释，用于测试语言检测功能\nx = 1\n"})
    out = tmp_path / "out"
    _scan(git_repo, _no_secrets(tmp_cfg), out)
    doc = json.loads((out / "report.json").read_text())
    ne = next(c for c in doc["checks"] if c["check"] == "non_english")
    assert ne["findings"] == []


def test_binary_and_untracked_skipped(git_repo, tmp_cfg, tmp_path):
    git_repo.commit({"a.bin": b"\0\x01 \xe8\xbf\x99", "a.py": "x = 1\n"})
    assert _scan(git_repo, _no_secrets(tmp_cfg), tmp_path / "out") == 0


@pytest.mark.requires_gitleaks
def test_reports_never_contain_raw_secret(git_repo, tmp_cfg, tmp_path):
    git_repo.commit({"a.py": LEAKY})
    out = tmp_path / "out"
    tmp_cfg.full_scan.sarif = True
    _scan(git_repo, tmp_cfg, out)
    files = list(out.iterdir())
    assert len(files) == 3
    for f in files:
        assert TOKEN not in f.read_text()
    secrets = json.loads((out / "report.json").read_text())["checks"][0]["findings"]
    assert secrets and secrets[0]["line"] == 2


@pytest.mark.requires_gitleaks
def test_exit_1_on_secrets_and_0_when_fail_disabled(git_repo, tmp_cfg, tmp_path):
    git_repo.commit({"a.py": LEAKY})
    assert _scan(git_repo, tmp_cfg, tmp_path / "o1") == 1
    tmp_cfg.full_scan.fail_on_secrets = False
    assert _scan(git_repo, tmp_cfg, tmp_path / "o2") == 0


@pytest.mark.requires_gitleaks
def test_history_flag_finds_removed_secret(git_repo, tmp_cfg, tmp_path):
    git_repo.commit({"a.py": LEAKY})
    git_repo.commit({"a.py": "x = 1\n"})
    assert _scan(git_repo, tmp_cfg, tmp_path / "o1") == 0
    out = tmp_path / "o2"
    assert _scan(git_repo, tmp_cfg, out, history=True) == 1
    doc = json.loads((out / "report.json").read_text())
    assert len(doc["checks"][0]["findings"]) == 1
    assert TOKEN not in (out / "report.json").read_text()


@pytest.mark.requires_gitleaks
def test_history_dedupes_across_dir_and_history(git_repo, tmp_cfg, tmp_path):
    git_repo.commit({"a.py": LEAKY})
    out = tmp_path / "o"
    _scan(git_repo, tmp_cfg, out, history=True)
    assert len(json.loads((out / "report.json").read_text())["checks"][0]["findings"]) == 1


def test_cli_scan_error_exit_3(tmp_path, capsys):
    assert main(["scan", "--repo", str(tmp_path), "--out-dir", str(tmp_path / "o")]) == 3
