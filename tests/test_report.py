import json

from airgap_pr_agent.models import Check, CheckResult, Finding, Severity
from airgap_pr_agent.report import write_html, write_json, write_sarif


def _results(message="msg"):
    f1 = Finding(Check.SECRETS, "a.py", 3, Severity.HIGH, "Hardcoded secret", message, "fp1", rule="aws")
    f2 = Finding(Check.SECURITY, "b.py", None, Severity.MEDIUM, "SQL injection", "bad", "fp2")
    return [
        CheckResult(Check.SECRETS, [f1]),
        CheckResult(Check.NON_ENGLISH, [], status="skipped", note="off"),
        CheckResult(Check.SECURITY, [f2], status="partial", note="n", unreviewed=["c.py"]),
    ]


def test_json_shape(tmp_path):
    p = tmp_path / "r.json"
    write_json(_results(), p)
    doc = json.loads(p.read_text())
    assert doc["version"] == 1 and "repo" in doc
    assert [c["check"] for c in doc["checks"]] == ["secrets", "non_english", "security"]
    sec = doc["checks"][2]
    assert sec["status"] == "partial" and sec["unreviewed"] == ["c.py"]
    assert doc["checks"][0]["findings"][0] == {
        "check": "secrets", "path": "a.py", "line": 3, "severity": "high",
        "title": "Hardcoded secret", "message": "msg", "fingerprint": "fp1",
        "commit": None, "rule": "aws", "suggestion": None,
    }


def test_sarif_shape(tmp_path):
    p = tmp_path / "r.sarif"
    write_sarif(_results(), p)
    doc = json.loads(p.read_text())
    assert doc["version"] == "2.1.0"
    res = doc["runs"][0]["results"]
    assert [r["ruleId"] for r in res] == ["secrets/aws", "security/SQL injection"]
    loc0 = res[0]["locations"][0]["physicalLocation"]
    assert loc0["region"]["startLine"] == 3
    assert "region" not in res[1]["locations"][0]["physicalLocation"]


def test_html_escapes(tmp_path):
    p = tmp_path / "r.html"
    write_html(_results("<script>alert(1)</script>"), p, "repo<x>")
    html = p.read_text()
    assert "&lt;script&gt;" in html and "<script>alert" not in html
    assert "repo&lt;x&gt;" in html
