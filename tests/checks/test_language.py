import pytest

from airgap_pr_agent.checks.language import classify, extract_spans, non_english_findings
from airgap_pr_agent.config import load_config
from airgap_pr_agent.gitops import ChangedFile, DiffRefs, changed_files
from airgap_pr_agent.models import Severity
from airgap_pr_agent.paths import PathFilter

_cfg = load_config(__import__("pathlib").Path("/nonexistent-dir-for-defaults"))
CFG = _cfg.non_english
FILTER = PathFilter.from_globs(_cfg.paths.include, _cfg.paths.exclude, CFG.exclude)


def _all_added(path, source):
    return ChangedFile(path, None, {i: l for i, l in enumerate(source.splitlines(), 1)}, source)


def test_extract_python_comment_and_string():
    spans = extract_spans("a.py", '# 获取用户\nx = "hello"\n')
    assert [(s.start, s.kind) for s in spans] == [(1, "comment"), (2, "string")]


@pytest.mark.parametrize("text,expect", [
    ("获取用户信息", "non-Latin"), ("Получить пользователя", "non-Latin"),
    ("Get the current user info", None), ("Obtener la información del usuario actual", "Spanish"),
    ("ok", None), ("café", None), ("see https://例子.com/x", None), ("%s {name} ${x}", None)])
def test_classify(text, expect):
    r = classify(text, 4, 0.7)
    assert (r is None) if expect is None else (expect in r)


def test_only_changed_lines():
    f = ChangedFile("a.py", None, {2: "# 新的"}, "# 旧的\n# 新的\n")
    [finding] = non_english_findings([f], CFG, FILTER).findings
    assert finding.line == 2 and finding.severity == Severity.LOW


def test_multiline_block_comment_reported_once():
    res = non_english_findings([_all_added("a.c", "/* 第一行\n 第二行 */\nint x;\n")], CFG, FILTER)
    assert [f.line for f in res.findings] == [1]


def test_locale_file_excluded():
    f = _all_added("app/locales/zh.json", '{"a": "获取用户信息"}\n')
    assert non_english_findings([f], CFG, FILTER).findings == []


def test_unknown_extension_non_latin_only():
    assert len(non_english_findings([_all_added("notes.xyz", "数据\n")], CFG, FILTER).findings) == 1
    es = "Obtener la información del usuario actual\n"
    assert non_english_findings([_all_added("notes.xyz", es)], CFG, FILTER).findings == []


def test_gb18030_file_flagged_end_to_end(git_repo):
    base = git_repo.commit({"a.c": "int x;\n"})
    head = git_repo.commit({"a.c": "int x;\n// 获取用户信息\n".encode("gb18030")})
    res = non_english_findings(changed_files(git_repo.path, DiffRefs(base, head)), CFG, FILTER)
    assert [f.line for f in res.findings] == [2]
