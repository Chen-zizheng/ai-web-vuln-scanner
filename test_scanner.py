import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from 扫描器.scanner_core import extract_features

def test_extract_forms():
    """测试能否正确提取表单和输入框"""
    html = '<form action="/login"><input name="user"><input type="password" name="pwd"></form>'
    features = extract_features(html)
    assert len(features["forms"]) == 1
    assert features["forms"][0]["inputs"][0]["name"] == "user"

def test_extract_dangerous_js():
    """测试能否识别 innerHTML 等危险函数"""
    html = '<script>document.body.innerHTML = userInput;</script>'
    features = extract_features(html)
    found = False
    for block in features["script_blocks"]:
        if "innerHTML" in block:
            found = True
    assert found is True, "未能识别 innerHTML 风险"

def test_empty_html():
    """测试空页面不报错"""
    features = extract_features("")
    assert features["forms"] == []
    assert features["script_blocks"] == []
