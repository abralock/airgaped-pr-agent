from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Mapping

import httpx

from .config import LLMConfig


class LLMUnavailable(Exception):
    """The model endpoint could not produce a usable response."""


class RequestCapReached(Exception):
    """The per-run request cap was hit; no HTTP request was sent."""


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _loads_dict(text: str) -> dict | None:
    try:
        value = json.loads(text.strip())
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def extract_json(text: str) -> dict:
    """Parse a JSON object from a model reply.

    Tries the whole text, then each fenced block, then every '{' position
    (first JSON object that decodes wins), so surrounding prose, braces in
    prose and fences inside string values do not break parsing.
    """
    found = _loads_dict(text)
    if found is not None:
        return found
    for block in _FENCE.findall(text):
        found = _loads_dict(block)
        if found is not None:
            return found
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text, match.start())
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("model reply contains no parseable JSON object")


class LLMClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        timeout: float,
        retries: int,
        max_requests: int,
        json_mode: bool = False,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._model = model
        self._retries = retries
        self._max_requests = max_requests
        self._json_mode = json_mode
        self._sleep = sleep
        self._lock = threading.Lock()
        self.requests_made = 0
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def __repr__(self) -> str:
        return f"LLMClient(url={self._url!r}, model={self._model!r})"

    @classmethod
    def from_env(
        cls, cfg: LLMConfig, env: Mapping[str, str], max_requests: int
    ) -> LLMClient | None:
        base_url, api_key = env.get("LLM_BASE_URL"), env.get("LLM_API_KEY")
        if not base_url or not api_key:
            return None
        return cls(
            base_url,
            api_key,
            env.get("LLM_MODEL") or "default",
            timeout=cfg.timeout_seconds,
            retries=cfg.retries,
            max_requests=max_requests,
            json_mode=cfg.json_mode,
        )

    def _reserve_request(self) -> None:
        with self._lock:
            if self.requests_made >= self._max_requests:
                raise RequestCapReached(f"LLM request cap of {self._max_requests} reached")
            self.requests_made += 1

    def complete_json(self, system: str, user: str) -> dict:
        body: dict = {
            "model": self._model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self._json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self._api_key}"}

        last = "no attempt made"
        for attempt in range(self._retries + 1):
            if attempt:
                self._sleep(2 ** (attempt - 1))
            self._reserve_request()
            try:
                resp = self._http.post(self._url, json=body, headers=headers)
            except httpx.TransportError as exc:
                last = f"transport error ({type(exc).__name__})"
                continue
            status = resp.status_code
            if status == 429 or status >= 500:
                last = f"model endpoint returned {status}"
                continue
            if status >= 400:
                raise LLMUnavailable(f"model endpoint returned {status}")
            try:
                content = resp.json()["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise LLMUnavailable("model endpoint returned a malformed response") from None
            if not isinstance(content, str):
                raise ValueError("model reply content is not text")
            return extract_json(content)
        raise LLMUnavailable(f"model endpoint unavailable after {self._retries + 1} attempts: {last}")
