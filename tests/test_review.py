import pytest

from airgap_pr_agent.checks.secrets import run_gitleaks, secret_findings
from airgap_pr_agent.gitops import DiffRefs, changed_files
from airgap_pr_agent.markers import SUMMARY_MARKER, fp_marker, parse_fp
from airgap_pr_agent.models import Check, CheckResult, Finding, Severity
from airgap_pr_agent.platforms.base import Thread
from airgap_pr_agent.review import reconcile, run_review
from airgap_pr_agent.summary import render_inline, render_summary
from conftest import GITLEAKS
from fakes import FakePlatform

# A token real gitleaks flags (the brief's ghp_ literal is not detected).
TOKEN = "AKIAQYLPMN5HHHFPZAM2"
LEAKY = f'x = 1\ntoken = "{TOKEN}"\n'

def _fp(repo, base, head):
    leaks = run_gitleaks(repo.path, "range", DiffRefs(base, head), bin=GITLEAKS)
    res, _ = secret_findings(leaks, changed_files(repo.path, DiffRefs(base, head)), [])
    return res.findings[0].fingerprint


def _leaky(git_repo):
    base = git_repo.commit({"a.py": "x = 1\n"})
    head = git_repo.commit({"a.py": LEAKY})
    return base, head


@pytest.mark.requires_gitleaks
def test_secret_on_changed_line_posts_inline_and_blocks(git_repo, tmp_cfg):
    base, head = _leaky(git_repo)
    p = FakePlatform(DiffRefs(base, head))
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 1
    [(path, line, body)] = p.posted
    assert (path, line) == ("a.py", 2)
    assert TOKEN not in body and "<!-- pr-agent:fp=" in body
    assert TOKEN not in p.summaries[-1]
    assert "Merge blocked" in p.summaries[-1] and "rotate each secret" in p.summaries[-1]


@pytest.mark.requires_gitleaks
def test_clean_mr_exit_0_and_summary_ok(git_repo, tmp_cfg):
    base = git_repo.commit({"a.py": "x = 1\n"})
    head = git_repo.commit({"a.py": "x = 2\n"})
    p = FakePlatform(DiffRefs(base, head))
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 0
    assert "✅ No issues found." in p.summaries[-1] and p.posted == []


@pytest.mark.requires_gitleaks
def test_existing_thread_not_reposted(git_repo, tmp_cfg):
    base, head = _leaky(git_repo)
    fp = _fp(git_repo, base, head)
    t = Thread("t1", f"old\n{fp_marker(fp)}", False, "n1")
    p = FakePlatform(DiffRefs(base, head), threads=[t])
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 1
    assert p.posted == [] and p.resolved == []


@pytest.mark.requires_gitleaks
def test_summary_thread_reused(git_repo, tmp_cfg):
    base, head = _leaky(git_repo)
    t = Thread("s1", f"{SUMMARY_MARKER}\nold", False, "n1")
    p = FakePlatform(DiffRefs(base, head), threads=[t])
    run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS)
    assert p.summary_existing == [t] and p.resolved == []


@pytest.mark.requires_gitleaks
def test_stale_bot_thread_resolved_human_untouched(git_repo, tmp_cfg):
    base = git_repo.commit({"a.py": "x = 1\n"})
    head = git_repo.commit({"a.py": "x = 2\n"})
    threads = [
        Thread("t1", f"stale\n{fp_marker('dead')}", False),
        Thread("t2", "LGTM", False),
    ]
    p = FakePlatform(DiffRefs(base, head), threads=threads)
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 0
    assert p.resolved == [("t1", True)]


@pytest.mark.requires_gitleaks
def test_resolved_bot_thread_reopened_when_finding_returns(git_repo, tmp_cfg):
    base, head = _leaky(git_repo)
    fp = _fp(git_repo, base, head)
    p = FakePlatform(DiffRefs(base, head), threads=[Thread("t1", fp_marker(fp), True)])
    run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS)
    assert p.resolved == [("t1", False)] and p.posted == []


@pytest.mark.requires_gitleaks
def test_head_moved_skips_inline(git_repo, tmp_cfg):
    base, head = _leaky(git_repo)
    p = FakePlatform(DiffRefs(base, head), inline_ok=False)
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 1
    assert p.posted == [] and len(p.summaries) == 1


@pytest.mark.requires_gitleaks
def test_post_failure_still_blocks_and_logs(git_repo, tmp_cfg, capsys):
    base, head = _leaky(git_repo)
    p = FakePlatform(DiffRefs(base, head), fail_posts=True)
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 1
    out = capsys.readouterr().out
    assert "a.py:2" in out and TOKEN not in out


@pytest.mark.requires_gitleaks
def test_secrets_disabled_by_config(git_repo, tmp_cfg):
    base, head = _leaky(git_repo)
    tmp_cfg.checks.secrets = False
    p = FakePlatform(DiffRefs(base, head))
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 0
    assert p.posted == []


# Pure unit tests (no gitleaks needed)
def _finding(line=2, fp="abc123", check=Check.SECRETS, sev=Severity.HIGH):
    return Finding(check, "a.py", line, sev, "T", "msg", fp, commit="deadbeefcafe")


def test_marker_roundtrip():
    assert parse_fp(f"hello\n{fp_marker('abc123')}") == "abc123"
    assert parse_fp("no marker") is None


def test_render_inline_has_marker():
    assert parse_fp(render_inline(_finding())) == "abc123"


def test_render_summary_skipped_partial_and_unreviewed():
    results = [
        CheckResult(Check.NON_ENGLISH, [], status="skipped", note="model down"),
        CheckResult(Check.SECURITY, [], status="partial", note="budget hit",
                    unreviewed=["big.py"]),
    ]
    s = render_summary(results, False)
    assert "⚠️ Non-English check skipped: model down" in s
    assert "⚠️ Security check incomplete: budget hit" in s
    assert "Files not reviewed by the model:" in s and "big.py" in s


def test_render_summary_summary_level_secret():
    s = render_summary([CheckResult(Check.SECRETS, [_finding(line=None)])], True)
    assert "deadbeef" in s and "1 hardcoded secret(s)" in s


def test_reconcile_dedupes_same_fingerprint():
    p = FakePlatform(None)
    reconcile([_finding(), _finding(line=5)], [], p)
    assert len(p.posted) == 1


def test_non_english_is_advisory_exit_0_and_posts_inline(git_repo, tmp_cfg):
    tmp_cfg.checks.secrets = False
    base = git_repo.commit({"a.py": "x = 1\n"})
    head = git_repo.commit({"a.py": "x = 1\n# 获取用户信息\n"})
    p = FakePlatform(DiffRefs(base, head))
    assert run_review(git_repo.path, p, tmp_cfg, None, GITLEAKS) == 0
    [(path, line, body)] = p.posted
    assert (path, line) == ("a.py", 2) and "Non-English" in body
