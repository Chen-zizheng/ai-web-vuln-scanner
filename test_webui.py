import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import webui


class FakeResponse:
    def __init__(self, status=200, headers=None, chunks=None, encoding="utf-8"):
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self._chunks = chunks or [b"<html><body>ok</body></html>"]
        self.encoding = encoding
        self.closed = False

    def iter_content(self, size):
        for c in self._chunks:
            yield c

    def close(self):
        self.closed = True


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), webui.Handler)
    webui.Handler.token = "test-token"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd, httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(port, path, token=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    req = urllib.request.Request(url)
    if token:
        req.add_header("X-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _post(port, payload, token="test-token", origin=None):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:%d/api/scan" % port, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Token", token)
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def test_page_requires_token(server):
    _, port = server
    assert _get(port, "/")[0] == 403
    assert _get(port, "/?t=wrong")[0] == 403
    status, body = _get(port, "/?t=test-token")
    assert status == 200
    assert "XSS 风险扫描器" in body
    assert "{{LLM_AVAILABLE}}" not in body


def test_page_flag_follows_env(server, monkeypatch):
    _, port = server
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    assert "const LLM_AVAILABLE = false" in _get(port, "/?t=test-token")[1]
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    assert "const LLM_AVAILABLE = true" in _get(port, "/?t=test-token")[1]


def test_scan_html_finds_sink(server):
    _, port = server
    html = ('<div id="out"></div><script>'
            'document.getElementById("out").innerHTML = location.hash.slice(1);'
            '</script>')
    status, data = _post(port, {"mode": "html", "html": html, "name": "t.html"})
    assert status == 200
    assert data["findings"], data
    assert data["findings"][0]["risk_level"] in ("HIGH", "MEDIUM")
    assert "source" in data and data["stats"]["script_blocks"] >= 1


def test_scan_rejects_missing_token(server):
    _, port = server
    status, _ = _post(port, {"mode": "html", "html": "<b>x</b>"}, token="")
    assert status == 403


def test_scan_rejects_foreign_origin(server):
    _, port = server
    status, _ = _post(port, {"mode": "html", "html": "<b>x</b>"}, origin="https://evil.example")
    assert status == 403


def test_scan_rejects_oversized_html(server, monkeypatch):
    _, port = server
    monkeypatch.setattr(webui, "MAX_UPLOAD_BYTES", 100)
    status, _ = _post(port, {"mode": "html", "html": "x" * 200})
    assert status == 413


def test_rejects_private_hosts():
    for url in ("http://127.0.0.1/", "http://localhost/", "http://10.0.0.1/", "http://[::1]/"):
        with pytest.raises(webui.FetchError):
            webui.fetch_page(url)


def test_rejects_other_schemes_and_ports():
    with pytest.raises(webui.FetchError, match="只支持 http"):
        webui.fetch_page("file:///etc/passwd")
    with pytest.raises(webui.FetchError, match="端口"):
        webui.fetch_page("http://example.com:22/")


def test_fetch_truncates_large_body(monkeypatch):
    monkeypatch.setattr(webui, "_assert_public_host", lambda host: None)
    big = b"a" * (webui.MAX_UPLOAD_BYTES + 10)
    monkeypatch.setattr(webui.requests, "get", lambda *a, **k: FakeResponse(chunks=[big]))
    html, note = webui.fetch_page("https://example.com/")
    assert len(html) == webui.MAX_UPLOAD_BYTES
    assert note == "已按 2 MB 截断"


def test_fetch_follows_redirect_then_stops(monkeypatch):
    monkeypatch.setattr(webui, "_assert_public_host", lambda host: None)
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        return FakeResponse(status=302, headers={"Location": "https://example.com/next"})

    monkeypatch.setattr(webui.requests, "get", fake_get)
    with pytest.raises(webui.FetchError, match="跳转次数超过"):
        webui.fetch_page("https://example.com/")
    assert calls["n"] == webui.MAX_REDIRECTS + 1


def test_fetch_rejects_non_html(monkeypatch):
    monkeypatch.setattr(webui, "_assert_public_host", lambda host: None)
    monkeypatch.setattr(webui.requests, "get",
                        lambda *a, **k: FakeResponse(headers={"Content-Type": "image/png"}))
    with pytest.raises(webui.FetchError, match="不是 HTML"):
        webui.fetch_page("https://example.com/")


def test_scan_html_llm_failure_does_not_break_static(monkeypatch):
    def boom(prompt, api_key=""):
        raise RuntimeError("no network")

    monkeypatch.setattr(webui.scanner_core, "call_llm", boom)
    out = webui.scan_html("<script>eval(location.hash)</script>", "unit", use_llm=True)
    assert out["findings"]
    assert "no network" in out["llm_note"]


def test_page_has_api_key_field(server):
    body = _get(server[1], "/?t=test-token")[1]
    assert 'id="key"' in body
    assert "api_key" in body


def test_scan_forwards_pasted_key_but_never_echoes_it(server, monkeypatch):
    _, port = server
    seen = {}

    def fake_call_llm(prompt, api_key=""):
        seen["api_key"] = api_key
        return [{"risk_level": "LOW", "location": "x", "snippet": "", "reason": "r"}]

    monkeypatch.setattr(webui.scanner_core, "call_llm", fake_call_llm)
    status, data = _post(port, {"mode": "html", "html": "<b>x</b>",
                                "use_llm": True, "api_key": "sk-pasted-secret"})
    assert status == 200
    assert seen["api_key"] == "sk-pasted-secret"
    assert data["suspected"], data
    assert "sk-pasted-secret" not in json.dumps(data, ensure_ascii=False)


def test_scan_without_key_falls_back_to_static_only(server, monkeypatch):
    def boom(prompt, api_key=""):
        raise Exception("缺少 API Key")

    monkeypatch.setattr(webui.scanner_core, "call_llm", boom)
    status, data = _post(server[1], {"mode": "html", "html": "<script>eval(location.hash)</script>",
                                     "use_llm": True})
    assert status == 200
    assert data["findings"]
    assert data["llm_note"].startswith("模型研判失败")


def test_scan_rejects_oversized_api_key(server):
    status, _ = _post(server[1], {"mode": "html", "html": "<b>x</b>",
                                  "use_llm": True, "api_key": "sk-" + "a" * 300})
    assert status == 400


def test_scan_reports_llm_not_requested(server):
    status, data = _post(server[1], {"mode": "html", "html": "<b>x</b>"})
    assert status == 200
    assert data["llm"]["requested"] is False
    assert data["llm"]["ok"] is False
    assert data["llm"]["count"] == 0


def test_scan_reports_llm_success(server, monkeypatch):
    def fake_call_llm(prompt, api_key=""):
        return [{"risk_level": "MEDIUM", "vulnerability_type": "XSS", "location": "x",
                 "reason": "r", "fix_suggestion": "f"}]

    monkeypatch.setattr(webui.scanner_core, "call_llm", fake_call_llm)
    status, data = _post(server[1], {"mode": "html", "html": "<b>x</b>", "use_llm": True,
                                     "api_key": "sk-x"})
    assert status == 200
    assert data["llm"]["requested"] is True
    assert data["llm"]["ok"] is True
    assert data["llm"]["count"] == 1
    assert data["llm"]["model"]


def test_scan_reports_llm_failure_reason(server, monkeypatch):
    def boom(prompt, api_key=""):
        raise Exception("401 Unauthorized")

    monkeypatch.setattr(webui.scanner_core, "call_llm", boom)
    status, data = _post(server[1], {"mode": "html", "html": "<b>x</b>", "use_llm": True,
                                     "api_key": "sk-x"})
    assert status == 200
    assert data["llm"]["requested"] is True
    assert data["llm"]["ok"] is False
    assert "401" in data["llm"]["error"]


def test_page_labels_static_and_ai_sections(server):
    body = _get(server[1], "/?t=test-token")[1]
    assert "静态分析 · 已证实" in body
    assert "大模型研判 · 疑似" in body
