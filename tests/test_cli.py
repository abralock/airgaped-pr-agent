import subprocess
import sys

import pytest

from airgap_pr_agent.cli import main

TOKEN = "AKIAQYLPMN5HHHFPZAM2"


def _leaky(git_repo):
    base = git_repo.commit({"a.py": "x = 1\n"})
    git_repo.commit({"a.py": f'x = 1\ntoken = "{TOKEN}"\n'})
    return base


@pytest.mark.requires_gitleaks
def test_cli_local_review_blocks_on_secret(git_repo, capsys):
    base = _leaky(git_repo)
    rc = main(["review", "--platform", "local", "--repo", str(git_repo.path), "--base", base])
    assert rc == 1
    assert TOKEN not in capsys.readouterr().out


def test_cli_exit_3_when_gitleaks_missing(git_repo, monkeypatch, capsys):
    base = _leaky(git_repo)
    monkeypatch.setenv("GITLEAKS_BIN", "/nonexistent/gitleaks")
    rc = main(["review", "--platform", "local", "--repo", str(git_repo.path), "--base", base])
    assert rc == 3
    assert "pr-agent: error:" in capsys.readouterr().err


def test_cli_exit_3_on_bad_config(git_repo, capsys):
    base = _leaky(git_repo)
    (git_repo.path / ".pr-agent.yml").write_text("security: {min_severity: bogus}\n")
    rc = main(["review", "--platform", "local", "--repo", str(git_repo.path), "--base", base])
    assert rc == 3
    assert "security.min_severity" in capsys.readouterr().err


def test_cli_local_requires_base(git_repo, capsys):
    assert main(["review", "--platform", "local", "--repo", str(git_repo.path)]) == 3
    assert "--base" in capsys.readouterr().err


def test_python_dash_m_runs():
    r = subprocess.run([sys.executable, "-m", "airgap_pr_agent", "--help"], capture_output=True)
    assert r.returncode == 0


@pytest.mark.requires_gitleaks
def test_cli_local_review_blocks_on_hardcoded_password(git_repo, capsys):
    # The spec's acceptance example: the default gitleaks rules alone miss it.
    base = git_repo.commit({"app.py": "x = 1\n"})
    git_repo.commit({"app.py": 'x = 1\n// 获取用户信息\npassword = "Hunter2!prod"\n'})
    rc = main(["review", "--platform", "local", "--repo", str(git_repo.path), "--base", base])
    out = capsys.readouterr().out
    assert rc == 1
    assert "--- app.py:3" in out and "Hunt****" in out
    assert "Hunter2!prod" not in out
    assert "Merge blocked" in out


@pytest.mark.requires_gitleaks
def test_cli_scan_from_repo_cwd_with_default_repo(git_repo, monkeypatch, tmp_path, capsys):
    # The shipped templates run `pr-agent scan` from the checkout with the default --repo ".".
    git_repo.commit({"a.py": f'x = 1\ntoken = "{TOKEN}"\n'})
    monkeypatch.chdir(git_repo.path)
    out = tmp_path / "reports"
    rc = main(["scan", "--out-dir", str(out)])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert (out / "report.json").is_file() and (out / "report.html").is_file()
    assert TOKEN not in captured.out + captured.err


@pytest.mark.requires_gitleaks
def test_cli_review_from_repo_cwd_with_default_repo(git_repo, monkeypatch, capsys):
    base = _leaky(git_repo)
    monkeypatch.chdir(git_repo.path)
    rc = main(["review", "--platform", "local", "--base", base])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "Merge blocked" in captured.out
    assert TOKEN not in captured.out + captured.err
