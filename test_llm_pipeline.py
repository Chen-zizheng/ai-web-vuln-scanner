"""提示词构造与 LLM 输出解析的单元测试。

覆盖 range 最容易被忽略、也最容易在线上炸掉的两段逻辑：
  1. build_prompt —— 送给模型的提示词是否带上了来源、特征，以及是否明确约束了输出字段
  2. call_llm     —— 模型返回 ```json 围栏 / 裸 JSON / 非 JSON 时，分别如何解析与降级

这里不发起任何真实网络请求：用 monkeypatch 替换 requests.post，
既能让测试跑在 CI 的无网环境里，也不会消耗 API 额度。
"""

import json

import pytest

import scanner_core


class _FakeResponse:
    """最小化的 requests.Response 替身，只实现 call_llm 用到的三个方法。"""

    def __init__(self, content):
        self._payload = {"choices": [{"message": {"content": content}}]}

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _install_fake_post(monkeypatch, content):
    """把 requests.post 换成假实现，并返回一个用于断言调用参数的记录字典。"""
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _FakeResponse(content)

    monkeypatch.setattr(scanner_core.requests, "post", fake_post)
    return captured


FEATURES = {
    "forms": [{"action": "/login", "method": "POST",
               "inputs": [{"name": "user", "type": "text"}]}],
    "script_blocks": ["document.body.innerHTML = userInput;"],
    "inline_events": ['onclick="doIt()"'],
    "suspicious_patterns": ["innerHTML"],
}


# ---------------------------------------------------------------- build_prompt

def test_build_prompt_returns_str():
    assert isinstance(scanner_core.build_prompt("a.html", FEATURES), str)


def test_build_prompt_includes_source():
    prompt = scanner_core.build_prompt("http://example.com/login", FEATURES)
    assert "http://example.com/login" in prompt


def test_build_prompt_includes_serialized_features():
    prompt = scanner_core.build_prompt("a.html", FEATURES)
    # 特征必须被序列化进提示词，否则模型看不到页面长什么样
    assert "innerHTML" in prompt
    assert "/login" in prompt


def test_build_prompt_declares_all_output_fields():
    """输出字段名是下游解析的契约，少一个就会让报告缺字段。"""
    prompt = scanner_core.build_prompt("a.html", FEATURES)
    for field in ("vulnerability_type", "risk_level", "location",
                  "reason", "fix_suggestion"):
        assert field in prompt, f"提示词缺少输出字段 {field}"


def test_build_prompt_accepts_empty_features():
    """空特征不应抛异常——空页面也要能走完流程。"""
    prompt = scanner_core.build_prompt("a.html", {})
    assert "a.html" in prompt


# -------------------------------------------------------------------- call_llm

def test_call_llm_raises_without_api_key(monkeypatch):
    monkeypatch.setattr(scanner_core, "API_KEY", "")
    with pytest.raises(Exception, match="DEEPSEEK_API_KEY"):
        scanner_core.call_llm("hi")


def test_call_llm_sends_bearer_token(monkeypatch):
    monkeypatch.setattr(scanner_core, "API_KEY", "test-key-123")
    captured = _install_fake_post(monkeypatch, "[]")
    scanner_core.call_llm("hi")
    assert captured["headers"]["Authorization"] == "Bearer test-key-123"


def test_call_llm_sets_request_timeout(monkeypatch):
    """没有 timeout 的 requests.post 会在弱网下把 GUI 卡死。"""
    monkeypatch.setattr(scanner_core, "API_KEY", "k")
    captured = _install_fake_post(monkeypatch, "[]")
    scanner_core.call_llm("hi")
    assert captured["timeout"] == 60


def test_call_llm_parses_plain_json(monkeypatch):
    monkeypatch.setattr(scanner_core, "API_KEY", "k")
    payload = [{"vulnerability_type": "XSS", "risk_level": "HIGH"}]
    _install_fake_post(monkeypatch, json.dumps(payload))
    assert scanner_core.call_llm("hi") == payload


def test_call_llm_strips_json_fence(monkeypatch):
    monkeypatch.setattr(scanner_core, "API_KEY", "k")
    payload = [{"risk_level": "LOW"}]
    _install_fake_post(monkeypatch, "```json\n" + json.dumps(payload) + "\n```")
    assert scanner_core.call_llm("hi") == payload


def test_call_llm_strips_bare_fence(monkeypatch):
    monkeypatch.setattr(scanner_core, "API_KEY", "k")
    payload = [{"risk_level": "MEDIUM"}]
    _install_fake_post(monkeypatch, "```\n" + json.dumps(payload) + "\n```")
    assert scanner_core.call_llm("hi") == payload


def test_call_llm_degrades_on_invalid_json(monkeypatch):
    """模型返回散文时不能崩，要降级成 raw_analysis 让上层仍能出报告。"""
    monkeypatch.setattr(scanner_core, "API_KEY", "k")
    _install_fake_post(monkeypatch, "这个页面看起来挺安全的")
    assert scanner_core.call_llm("hi") == {"raw_analysis": "这个页面看起来挺安全的"}


def test_call_llm_propagates_http_error(monkeypatch):
    """HTTP 4xx/5xx 必须冒泡，否则会静默产出空报告。"""
    monkeypatch.setattr(scanner_core, "API_KEY", "k")

    class _Boom(_FakeResponse):
        def raise_for_status(self):
            raise RuntimeError("429 Too Many Requests")

    monkeypatch.setattr(scanner_core.requests, "post",
                        lambda url, **kw: _Boom(""))
    with pytest.raises(RuntimeError, match="429"):
        scanner_core.call_llm("hi")
