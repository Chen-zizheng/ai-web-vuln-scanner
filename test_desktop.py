"""桌面界面（main.py）与启动入口（webapp.py）里不依赖 Tk 事件循环的部分。

GUI 的交互层不在单元测试里做：那部分靠打包后的冒烟验证（见 TESTING.md）。
这里只测被 GUI 调用的纯函数与参数解析。
"""
import shutil
import uuid
from pathlib import Path

import pytest

# main.py 在模块级 import tkinter。GitHub Actions 的 setup-python 不带 _tkinter，
# 所以没有 Tk 的环境里整层跳过；本机照常跑满 11 例。
pytest.importorskip("tkinter", reason="运行环境没有 tkinter（CI 的 setup-python 不带 _tkinter）")

import main
import webapp


def test_md_field_none_becomes_na():
    assert main._md_field(None) == "N/A"


def test_md_field_collapses_whitespace():
    assert main._md_field("  a\n\tb   c ") == "a b c"


def test_md_field_empty_string_becomes_na():
    assert main._md_field("   ") == "N/A"


def test_md_field_truncates_to_limit():
    assert len(main._md_field("x" * 900, limit=50)) == 50


def test_md_field_limit_can_not_be_exceeded_by_newlines():
    assert "\n" not in main._md_field("a\nb", limit=20)


def _workdir():
    """save_report 把报告写到 ./output，这里给它一个隔离的工作目录。"""
    path = Path("output") / ("t-" + uuid.uuid4().hex[:8])
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_save_report_writes_json_and_markdown(monkeypatch):
    workdir = _workdir()
    monkeypatch.chdir(workdir)
    try:
        json_path, md_path = main.save_report(
            "file:///page.html",
            {"scripts": 1},
            [{"vulnerability_type": "XSS", "risk_level": "HIGH", "location": "12",
              "reason": "location.hash 进入 innerHTML", "fix_suggestion": "改用 textContent"}],
        )
        assert json_path.exists() and md_path.exists()
        text = md_path.read_text(encoding="utf-8")
        assert "# Web 漏洞分析报告" in text
        assert "共发现 **1** 个风险点" in text
        assert "location.hash 进入 innerHTML" in text
    finally:
        monkeypatch.undo()
        shutil.rmtree(workdir, ignore_errors=True)


def test_save_report_handles_plain_text_analysis(monkeypatch):
    workdir = _workdir()
    monkeypatch.chdir(workdir)
    try:
        _, md_path = main.save_report("stdin", {}, "模型返回了一段说明")
        assert "模型返回了一段说明" in md_path.read_text(encoding="utf-8")
    finally:
        monkeypatch.undo()
        shutil.rmtree(workdir, ignore_errors=True)


def test_save_report_neutralises_markdown_in_fields(monkeypatch):
    """模型输出里的换行不能改写报告结构。"""
    workdir = _workdir()
    monkeypatch.chdir(workdir)
    try:
        _, md_path = main.save_report(
            "p", {}, [{"vulnerability_type": "XSS\n## 伪造标题", "risk_level": "HIGH"}])
        lines = md_path.read_text(encoding="utf-8").splitlines()
        assert not any(line.startswith("## 伪造标题") for line in lines)
    finally:
        monkeypatch.undo()
        shutil.rmtree(workdir, ignore_errors=True)


def test_webapp_parses_port_and_no_browser(monkeypatch):
    captured = {}
    monkeypatch.setattr(webapp.webui, "serve", lambda **kw: captured.update(kw))
    assert webapp.main(["--port", "8899", "--no-browser"]) == 0
    assert captured == {"port": 8899, "open_browser": False}


def test_webapp_defaults(monkeypatch):
    captured = {}
    monkeypatch.setattr(webapp.webui, "serve", lambda **kw: captured.update(kw))
    assert webapp.main([]) == 0
    assert captured == {"port": 0, "open_browser": True}


def test_webapp_ignores_dangling_port_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(webapp.webui, "serve", lambda **kw: captured.update(kw))
    webapp.main(["--port"])
    assert captured["port"] == 0
