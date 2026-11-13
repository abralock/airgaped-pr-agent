import json
from pathlib import Path

import httpx

from airgap_pr_agent.checks.secrets import Redactor
from airgap_pr_agent.checks.security import SYSTEM_PROMPT, build_chunks, security_findings
from airgap_pr_agent.config import load_config
from airgap_pr_agent.gitops import ChangedFile
from airgap_pr_agent.llm import LLMClient
from airgap_pr_agent.models import Check, Severity
from airgap_pr_agent.paths import PathFilter

_cfg = load_config(Path("/nonexistent-dir-for-defaults"))
SEC = _cfg.security
LLM = _cfg.llm
FILTER = PathFilter.from_globs(_cfg.paths.include, _cfg.paths.exclude)


def reply(findings):
    return httpx.Response(
        200, json={"choices": [{"message": {"content": json.dumps({"findings": findings})}}]}
    )


def make_client(handler, max_requests=100, sent=None):
    def wrapped(request):
        if sent is not None:
            sent.append(request.content.decode())
        return handler(request)

    return LLMClient("http://llm.invalid/v1", "k", "m", timeout=1, retries=0,
                     max_requests=max_requests, transport=httpx.MockTransport(wrapped),
                     sleep=lambda s: None)


def item(line=1, severity="high", category="Injection", **kw):
    return {"line": line, "severity": severity, "category": category,
            "explanation": "bad", "suggestion": "fix", **kw}


def one_file(path="a.py"):
    return ChangedFile(path, None, {1: "eval(x)"}, "eval(x)\n")


def run(files, handler, **kw):
    return security_findings(files, make_client(handler, **kw), SEC, LLM, Redactor([]), FILTER)


def test_chunks_number_and_mark_lines():
    src = "\n".join(f"line{i}" for i in range(1, 11)) + "\n"
    f = ChangedFile("a.py", None, {5: "line5"}, src)
    [c] = build_chunks([f], 2, 6000)
    assert (c.path, c.start, c.end, c.changed) == ("a.py", 3, 7, {5})
    lines = c.text.split("\n")
    assert lines[0] == "     3   line3"
    assert lines[2] == "     5 + line5"
    assert len(lines) == 5


def test_chunks_merge_overlapping_windows():
    src = "\n".join(f"l{i}" for i in range(1, 21)) + "\n"
    f = ChangedFile("a.py", None, {3: "l3", 6: "l6", 18: "l18"}, src)
    chunks = build_chunks([f], 2, 6000)
    assert [(c.start, c.end, c.changed) for c in chunks] == [(1, 8, {3, 6}), (16, 20, {18})]


def test_chunks_respect_budget():
    src = "\n".join(f"v{i} = {i}" for i in range(1, 2001)) + "\n"
    f = ChangedFile("a.py", None, {i: f"v{i} = {i}" for i in range(1, 2001)}, src)
    chunks = build_chunks([f], 2, 2000)
    assert len(chunks) > 1
    assert all(len(c.text) <= (2000 - 1500) * 4 for c in chunks)
    covered = sorted(n for c in chunks for n in c.changed)
    assert covered == list(range(1, 2001))


def test_keeps_valid_finding_on_changed_line():
    res = run([one_file()], lambda r: reply([item(1)]))
    [f] = res.findings
    assert (f.check, f.path, f.line, f.severity) == (Check.SECURITY, "a.py", 1, Severity.HIGH)
    assert f.title == "Security: Injection" and f.message == "bad" and f.suggestion == "fix"
    assert res.status == "ok" and res.unreviewed == []


def test_fingerprint_stable_across_line_moves():
    a = ChangedFile("a.py", None, {1: "eval(x)"}, "eval(x)\n")
    b = ChangedFile("a.py", None, {3: "eval(x)"}, "\n\neval(x)\n")
    fa = run([a], lambda r: reply([item(1)])).findings[0].fingerprint
    fb = run([b], lambda r: reply([item(3)])).findings[0].fingerprint
    assert fa == fb


def test_drops_off_diff_line_and_low_severity():
    f = ChangedFile("a.py", None, {2: "eval(x)"}, "ctx\neval(x)\n")
    SEC_MED = SEC.model_copy(update={"min_severity": Severity.MEDIUM})
    reply_items = [item(1), item(2, "low"), item(2, "medium"), item(99)]
    res = security_findings([f], make_client(lambda r: reply(reply_items)), SEC_MED, LLM,
                            Redactor([]), FILTER)
    assert [(x.line, x.severity) for x in res.findings] == [(2, Severity.MEDIUM)]


def test_invalid_items_dropped():
    bad = [{"line": "x"}, item(1, "critical"), "junk", item(1, category=""), item(1)]
    res = run([one_file()], lambda r: reply(bad))
    assert len(res.findings) == 1 and res.status == "ok"


def test_model_path_ignored():
    res = run([one_file()], lambda r: reply([item(1, path="other.py")]))
    assert [f.path for f in res.findings] == ["a.py"]


def test_unparseable_reply_marks_file_unreviewed_and_continues():
    def handler(request):
        if "bad.py" in request.content.decode():
            return httpx.Response(200, json={"choices": [{"message": {"content": "no json"}}]})
        return reply([item(1)])

    res = run([one_file("bad.py"), one_file("good.py")], handler)
    assert res.status == "partial" and res.unreviewed == ["bad.py"]
    assert [f.path for f in res.findings] == ["good.py"]


def test_non_list_findings_is_unparseable():
    res = run([one_file()], lambda r: httpx.Response(
        200, json={"choices": [{"message": {"content": '{"findings": 3}'}}]}))
    assert res.status == "partial" and res.unreviewed == ["a.py"]


def test_prompt_never_contains_raw_secret():
    raw = "Hunter2!prodSecret"
    f = ChangedFile("a.py", None, {1: f'pw = "{raw}"'}, f'pw = "{raw}"\n')
    sent = []
    security_findings([f], make_client(lambda r: reply([]), sent=sent), SEC, LLM,
                      Redactor([raw]), FILTER)
    assert sent and all(raw not in body for body in sent) and any("Hunt****" in b for b in sent)


def test_finding_fingerprint_does_not_depend_on_raw_secret():
    raw = "Hunter2!prodSecret"
    f = ChangedFile("a.py", None, {1: f'pw = "{raw}"'}, f'pw = "{raw}"\n')
    res = security_findings([f], make_client(lambda r: reply([item(1)])), SEC, LLM,
                            Redactor([raw]), FILTER)
    assert raw not in repr(res)


def test_system_prompt_contract():
    assert "+" in SYSTEM_PROMPT and '"findings"' in SYSTEM_PROMPT
    for key in ("line", "severity", "category", "explanation", "suggestion"):
        assert f'"{key}"' in SYSTEM_PROMPT


def test_filtered_paths_not_sent():
    sent = []
    f = ChangedFile("node_modules/x.js", None, {1: "eval(x)"}, "eval(x)\n")
    res = security_findings([f], make_client(lambda r: reply([]), sent=sent), SEC, LLM,
                            Redactor([]), FILTER)
    assert sent == [] and res.status == "ok"


def test_no_client_skipped():
    res = security_findings([one_file()], None, SEC, LLM, Redactor([]), FILTER)
    assert (res.status, res.note) == ("skipped", "model not configured")


def test_unreachable_skipped():
    def down(request):
        raise httpx.ConnectError("refused")

    res = run([one_file()], down)
    assert (res.status, res.note) == ("skipped", "model unreachable")


def test_unreachable_after_success_is_partial():
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) > 1:
            raise httpx.ConnectError("refused")
        return reply([])

    llm = LLM.model_copy(update={"concurrency": 1})
    files = [one_file(f"f{i}.py") for i in range(3)]
    res = security_findings(files, make_client(handler), SEC, llm, Redactor([]), FILTER)
    assert (res.status, res.note) == ("partial", "model unreachable")
    assert res.unreviewed == ["f1.py", "f2.py"]


def test_request_cap_marks_rest_unreviewed():
    files = [ChangedFile(f"f{i}.py", None, {1: "eval(x)"}, "eval(x)\n") for i in range(40)]
    calls = []

    def handler(request):
        calls.append(1)
        return reply([])

    res = security_findings(files, make_client(handler, max_requests=30), SEC, LLM,
                            Redactor([]), FILTER)
    assert len(calls) == 30 and res.status == "partial" and res.note == "request cap reached"
    assert len(res.unreviewed) == 10
