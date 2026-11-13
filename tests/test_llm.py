import json

import httpx
import pytest

from airgap_pr_agent.config import load_config
from airgap_pr_agent.llm import LLMClient, LLMUnavailable, RequestCapReached, extract_json


def make(handler, **kw):
    params = dict(timeout=5, retries=2, max_requests=10)
    params.update(kw)
    return LLMClient(
        "http://llm.local/v1",
        "k-secret",
        "m",
        transport=httpx.MockTransport(handler),
        sleep=lambda s: None,
        **params,
    )


def ok(content='{"a": 1}'):
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def test_request_shape():
    seen = []

    def handler(req):
        seen.append(req)
        return ok()

    assert make(handler).complete_json("sys", "usr") == {"a": 1}
    req = seen[0]
    assert req.method == "POST"
    assert str(req.url) == "http://llm.local/v1/chat/completions"
    assert req.headers["Authorization"] == "Bearer k-secret"
    body = json.loads(req.content)
    assert body["model"] == "m"
    assert body["temperature"] == 0
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["messages"][1] == {"role": "user", "content": "usr"}
    assert "response_format" not in body


def test_trailing_slash_stripped():
    seen = []
    client = LLMClient(
        "http://llm.local/v1/", "k", "m", timeout=1, retries=0, max_requests=1,
        transport=httpx.MockTransport(lambda r: seen.append(r) or ok()),
    )
    client.complete_json("s", "u")
    assert str(seen[0].url) == "http://llm.local/v1/chat/completions"


def test_json_mode_adds_response_format():
    bodies = []

    def handler(req):
        bodies.append(json.loads(req.content))
        return ok()

    make(handler, json_mode=True).complete_json("s", "u")
    assert bodies[0]["response_format"] == {"type": "json_object"}


def test_extract_json_from_fenced_reply():
    assert extract_json('```json\n{"findings": []}\n```') == {"findings": []}
    assert extract_json('Sure! {"a": {"b": 1}} done') == {"a": {"b": 1}}


def test_extract_json_unparseable():
    with pytest.raises(ValueError):
        extract_json("no json here")
    with pytest.raises(ValueError):
        extract_json("{not json}")


def test_unparseable_reply_raises_value_error():
    with pytest.raises(ValueError):
        make(lambda r: ok("nope")).complete_json("s", "u")


def test_retries_5xx_then_succeeds():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(500) if len(calls) == 1 else ok()

    assert make(handler).complete_json("s", "u") == {"a": 1}
    assert len(calls) == 2


def test_timeouts_exhaust_to_unavailable():
    calls = []

    def handler(req):
        calls.append(1)
        raise httpx.ReadTimeout("slow", request=req)

    with pytest.raises(LLMUnavailable):
        make(handler).complete_json("s", "u")
    assert len(calls) == 3


def test_401_no_retry():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(401)

    with pytest.raises(LLMUnavailable):
        make(handler).complete_json("s", "u")
    assert len(calls) == 1


def test_cap_reached_without_http():
    calls = []

    def handler(req):
        calls.append(1)
        return ok()

    client = make(handler, max_requests=2)
    client.complete_json("s", "u")
    client.complete_json("s", "u")
    with pytest.raises(RequestCapReached):
        client.complete_json("s", "u")
    assert len(calls) == 2
    assert client.requests_made == 2


def test_from_env_none_when_unset(tmp_path):
    cfg = load_config(tmp_path).llm
    assert LLMClient.from_env(cfg, {}, max_requests=5) is None
    assert LLMClient.from_env(cfg, {"LLM_BASE_URL": "http://x/v1"}, max_requests=5) is None
    assert LLMClient.from_env(cfg, {"LLM_API_KEY": "k"}, max_requests=5) is None


def test_from_env_builds_client(tmp_path):
    cfg = load_config(tmp_path).llm
    env = {"LLM_BASE_URL": "http://x/v1", "LLM_API_KEY": "k-secret"}
    client = LLMClient.from_env(cfg, env, max_requests=7)
    assert client is not None
    assert "k-secret" not in repr(client)


def test_api_key_never_in_error_message():
    with pytest.raises(LLMUnavailable) as ei:
        make(lambda r: httpx.Response(401)).complete_json("s", "u")
    assert "k-secret" not in str(ei.value)
    assert "k-secret" not in repr(ei.value)


def test_api_key_not_in_transport_error_message():
    def handler(req):
        raise httpx.ConnectError("boom Bearer k-secret", request=req)

    with pytest.raises(LLMUnavailable) as ei:
        make(handler, retries=0).complete_json("s", "u")
    assert "k-secret" not in str(ei.value)
