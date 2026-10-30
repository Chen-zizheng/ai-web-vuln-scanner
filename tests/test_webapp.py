"""启动入口（webapp.py）的参数解析。窗口与 HTTP 处理分别在 webui 与页面里测。"""
import webapp


def test_parses_port_and_no_browser(monkeypatch):
    captured = {}
    monkeypatch.setattr(webapp.webui, "serve", lambda **kw: captured.update(kw))
    assert webapp.main(["--port", "8899", "--no-browser"]) == 0
    assert captured == {"port": 8899, "open_browser": False}


def test_defaults_to_random_port_and_browser(monkeypatch):
    captured = {}
    monkeypatch.setattr(webapp.webui, "serve", lambda **kw: captured.update(kw))
    assert webapp.main([]) == 0
    assert captured == {"port": 0, "open_browser": True}


def test_ignores_dangling_port_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(webapp.webui, "serve", lambda **kw: captured.update(kw))
    webapp.main(["--port"])
    assert captured["port"] == 0
