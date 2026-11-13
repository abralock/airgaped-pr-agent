import json
import os
import stat

import pytest

from airgap_pr_agent.checks.secrets import (
    Redactor,
    SecretScanError,
    mask,
    run_gitleaks,
    secret_findings,
)
from airgap_pr_agent.config import AllowEntry
from airgap_pr_agent.gitops import ChangedFile, DiffRefs
from airgap_pr_agent.models import Check, Severity

RAW = "Hunter2!prodSecret"
LEAK = {"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "app.py",
        "StartLine": 3, "Secret": RAW, "Match": f'password = "{RAW}"', "Commit": "abc123"}
CF = ChangedFile("app.py", None, {3: f'password = "{RAW}"'}, f'a\nb\npassword = "{RAW}"\n')

# A token real gitleaks flags (the brief's AKIA2E0A... literal is not detected).
AWS = "AKIAQYLPMN5HHHFPZAM2"


def test_mask():
    assert mask(RAW) == "Hunt****" and mask("short") == "****"


def test_inline_when_still_on_changed_line():
    res, _ = secret_findings([LEAK], [CF], [])
    [f] = res.findings
    assert (f.line, f.severity, f.check) == (3, Severity.HIGH, Check.SECRETS)
    assert RAW not in repr(f) and "Hunt****" in f.message and f.fingerprint in f.message


def test_summary_level_when_removed_in_later_commit():
    res, _ = secret_findings([LEAK], [ChangedFile("app.py", None, {1: "x"}, "x\n")], [])
    assert res.findings[0].line is None and res.findings[0].commit == "abc123"


def test_same_secret_in_two_commits_deduped_preferring_inline():
    older = {**LEAK, "Commit": "old111", "StartLine": 9}
    res, _ = secret_findings([older, LEAK], [CF], [])
    assert [(f.line, f.commit) for f in res.findings] == [(3, "abc123")]


def test_allowlist_by_fingerprint_and_path():
    res, _ = secret_findings([LEAK], [CF], [])
    fp = res.findings[0].fingerprint
    assert secret_findings([LEAK], [CF], [AllowEntry(fingerprint=fp)])[0].findings == []
    assert secret_findings([LEAK], [CF], [AllowEntry(path="*.py")])[0].findings == []


def test_allowlist_path_matches_at_depth():
    deep = {**LEAK, "File": "a/b/app.py"}
    assert secret_findings([deep], None, [AllowEntry(path="*.py")])[0].findings == []
    assert secret_findings([deep], None, [AllowEntry(path="docs/**")])[0].findings != []


def test_allowlist_empty_or_wrong_entries_never_match_all():
    entries = [AllowEntry(fingerprint=""), AllowEntry(path=""), AllowEntry(fingerprint="deadbeef")]
    assert len(secret_findings([LEAK], [CF], entries)[0].findings) == 1


def test_full_scan_mode_keeps_start_line():
    assert secret_findings([LEAK], None, [])[0].findings[0].line == 3


def test_redactor():
    _, red = secret_findings([LEAK], [CF], [])
    assert red.redact(f"x={RAW}; y={RAW}") == "x=Hunt****; y=Hunt****"


def test_redactor_covers_allowlisted_and_longest_first():
    res, red = secret_findings([LEAK], [CF], [AllowEntry(path="*.py")])
    assert res.findings == [] and red.redact(RAW) == "Hunt****"
    r = Redactor(["abcdefgh1", "abcdefgh1234"])
    assert r.redact("abcdefgh1234") == "abcd****"
    assert Redactor([""]).redact("hello") == "hello"


def test_gitleaks_failure_raises(tmp_path):
    with pytest.raises(SecretScanError):
        run_gitleaks(tmp_path, "dir", bin="/nonexistent/gitleaks")
    with pytest.raises(SecretScanError):
        run_gitleaks(tmp_path, "dir", bin="false")


def _fake_gitleaks(tmp_path, body):
    p = tmp_path / "fake-gitleaks"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_unparseable_report_raises_without_leaking_contents(tmp_path):
    # last arg is the repo; --report-path value is the arg after the flag
    fake = _fake_gitleaks(
        tmp_path,
        'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && echo "Hunter2!NOPE" > "$2"; shift; done\n',
    )
    with pytest.raises(SecretScanError) as ei:
        run_gitleaks(tmp_path, "dir", bin=fake)
    assert "Hunter2" not in str(ei.value)


def test_paths_normalized_and_only_known_fields_kept(tmp_path):
    report = [{"RuleID": "r", "Description": "d", "File": str(tmp_path / "sub" / "a.py"),
               "StartLine": 1, "Secret": "s", "Commit": "", "Match": "m", "Extra": 1}]
    fake = _fake_gitleaks(
        tmp_path,
        'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && cat > "$2" <<\'EOF\'\n'
        + json.dumps(report) + "\nEOF\nshift; done\n",
    )
    [leak] = run_gitleaks(tmp_path, "dir", bin=fake)
    assert leak["File"] == "sub/a.py"
    assert set(leak) == {"RuleID", "Description", "File", "StartLine", "Secret", "Commit"}


@pytest.mark.requires_gitleaks
def test_real_gitleaks_range_catches_added_then_removed(git_repo):
    base = git_repo.commit({"a.py": "x = 1\n"})
    git_repo.commit({"a.py": f'aws_access_key_id = "{AWS}"\n'})
    head = git_repo.commit({"a.py": "x = 1\n"})
    leaks = run_gitleaks(git_repo.path, "range", DiffRefs(base, head), bin=os.environ.get("GITLEAKS_BIN", "gitleaks"))
    assert any(AWS == l["Secret"] for l in leaks)


@pytest.mark.requires_gitleaks
def test_real_gitleaks_dir_mode_relative_file(git_repo):
    git_repo.commit({"sub/a.py": f'aws_access_key_id = "{AWS}"\n'})
    leaks = run_gitleaks(git_repo.path, "dir", bin=os.environ.get("GITLEAKS_BIN", "gitleaks"))
    assert [l["File"] for l in leaks if l["Secret"] == AWS] == ["sub/a.py"]


def _bin():
    return os.environ.get("GITLEAKS_BIN", "gitleaks")


def test_err_log_with_exit_zero_and_empty_report_raises(tmp_path):
    fake = _fake_gitleaks(
        tmp_path,
        'printf "\\033[90m8:40PM\\033[0m \\033[31mERR\\033[0m [git] fatal: bad\\n" >&2\n'
        'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && echo "[]" > "$2"; shift; done\n',
    )
    with pytest.raises(SecretScanError) as ei:
        run_gitleaks(tmp_path, "dir", bin=fake)
    assert "\x1b" not in str(ei.value)


def test_empty_report_raises(tmp_path):
    fake = _fake_gitleaks(
        tmp_path, 'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && : > "$2"; shift; done\n'
    )
    with pytest.raises(SecretScanError):
        run_gitleaks(tmp_path, "dir", bin=fake)


def test_clean_fake_report_returns_empty(tmp_path):
    fake = _fake_gitleaks(
        tmp_path, 'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && echo "[]" > "$2"; shift; done\n'
    )
    assert run_gitleaks(tmp_path, "dir", bin=fake) == []


def test_bundled_config_isolation_flags_passed(tmp_path):
    log = tmp_path / "args.txt"
    fake = _fake_gitleaks(
        tmp_path,
        f'echo "$@" > {log}\n'
        'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && echo "[]" > "$2"; shift; done\n',
    )
    run_gitleaks(tmp_path, "dir", bin=fake)
    args = log.read_text()
    assert "--config" in args and "gitleaks.toml" in args
    assert "--ignore-gitleaks-allow" in args and "--gitleaks-ignore-path" in args


def test_range_with_unknown_base_raises(git_repo):
    head = git_repo.commit({"a.py": "x = 1\n"})
    with pytest.raises(SecretScanError):
        run_gitleaks(git_repo.path, "range", DiffRefs("deadbeef" * 5, head), bin="false")


def test_range_non_repo_raises(tmp_path):
    with pytest.raises(SecretScanError):
        run_gitleaks(tmp_path, "range", DiffRefs("a", "b"), bin="false")
    with pytest.raises(SecretScanError):
        run_gitleaks(tmp_path, "history", bin="false")


KEY_BODY = ["MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxx", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"]
KEY = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(KEY_BODY) + "\n-----END RSA PRIVATE KEY-----"


def test_redactor_multiline_secret_in_diff_and_crlf():
    red = Redactor([KEY])
    diff = "\n".join("+" + l for l in KEY.splitlines())
    crlf = KEY.replace("\n", "\r\n")
    for text in (diff, crlf, KEY):
        out = red.redact(text)
        assert not any(b in out for b in KEY_BODY)


@pytest.mark.requires_gitleaks
def test_real_gitleaks_invalid_range_raises(git_repo):
    head = git_repo.commit({"a.py": "x = 1\n"})
    with pytest.raises(SecretScanError):
        run_gitleaks(git_repo.path, "range", DiffRefs("deadbeef" * 5, head), bin=_bin())


@pytest.mark.requires_gitleaks
def test_real_gitleaks_ignores_repo_controlled_suppression(git_repo):
    git_repo.commit({
        ".gitleaks.toml": '[allowlist]\npaths = [".*"]\n',
        "a.py": f'aws_access_key_id = "{AWS}"\n',
        "b.py": f'k = "{AWS}"  # gitleaks:allow\n',
    })
    leaks = run_gitleaks(git_repo.path, "dir", bin=_bin())
    assert {l["File"] for l in leaks if l["Secret"] == AWS} == {"a.py", "b.py"}
    head = git_repo.git("rev-parse", "HEAD")
    (git_repo.path / ".gitleaksignore").write_text(f"{head}:a.py:aws-access-token:1\n")
    leaks = run_gitleaks(git_repo.path, "history", bin=_bin())
    assert any(l["Secret"] == AWS and l["File"] == "a.py" for l in leaks), leaks


@pytest.mark.requires_gitleaks
def test_real_gitleaks_dir_ignores_gitleaksignore(git_repo):
    git_repo.commit({"a.py": f'aws_access_key_id = "{AWS}"\n', ".gitleaksignore": "a.py:aws-access-token:1\n"})
    assert any(l["Secret"] == AWS for l in run_gitleaks(git_repo.path, "dir", bin=_bin()))
