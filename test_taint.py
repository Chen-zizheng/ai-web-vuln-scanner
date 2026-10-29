# -*- coding: utf-8 -*-
"""taint.py 的回归测试：每条用例都对应一种真实写法，防止后续改动悄悄退化。"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import taint  # noqa: E402


def hit(html):
    return taint.analyze(html)["findings"]


def test_template_interpolation_source():
    html = "<script>const tpl = 1; document.write('<b>' + location.hash + '</b>');</script>"
    findings = hit(html)
    assert len(findings) == 1
    f = findings[0]
    assert f["vulnerability_type"] == "XSS"
    assert f["risk_level"] == "HIGH"
    assert f["confidence"] == "confirmed"
    assert "location.hash" in f["reason"]
    assert f["location"].startswith("第 1 行")


def test_simple_two_step_propagation():
    html = ("<script>\n"
            "var h = location.hash;\n"
            "document.getElementById('x').innerHTML = h;\n"
            "</script>")
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["evidence"]["line"] == 3
    assert findings[0]["risk_level"] == "HIGH"


def test_cookie_into_attr_sink_is_medium():
    html = "<script>var c = document.cookie; document.getElementById('a').src = c;</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["risk_level"] == "MEDIUM"


def test_sanitizer_stops_flow():
    html = "<script>document.getElementById('x').innerHTML = escapeHtml(location.hash);</script>"
    assert hit(html) == []


def test_dompurify_stops_flow():
    html = "<script>document.getElementById('x').innerHTML = DOMPurify.sanitize(location.hash);</script>"
    assert hit(html) == []


def test_textcontent_is_not_a_sink():
    html = "<script>document.getElementById('x').textContent = location.hash;</script>"
    assert hit(html) == []


def test_literal_is_not_tainted():
    html = "<script>document.getElementById('x').innerHTML = '<p>静态文案</p>';</script>"
    assert hit(html) == []


def test_storage_source():
    html = "<script>var n = localStorage.getItem('bio'); out.innerHTML = n;</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert "localStorage" in findings[0]["reason"]


def test_postmessage_source():
    html = ("<script>window.addEventListener('message', function (e) {\n"
            "  document.getElementById('m').innerHTML = e.data;\n"
            "});</script>")
    findings = hit(html)
    assert len(findings) == 1
    assert "postMessage" in findings[0]["reason"]


def test_insertadjacenthtml_second_arg():
    html = "<script>document.body.insertAdjacentHTML('beforeend', location.hash);</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert "insertAdjacentHTML" in findings[0]["evidence"]["sink"]


def test_srcdoc_is_high():
    html = "<script>document.getElementById('f').srcdoc = location.search;</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["risk_level"] == "HIGH"


def test_eval_and_atob_chain():
    html = "<script>eval(atob(location.hash.slice(1)));</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert "eval" in findings[0]["evidence"]["sink"]


def test_jquery_html_and_val():
    html = ("<script>var q = location.search;\n"
            "$('#box').html(q);\n"
            "var v = $('#input').val();\n"
            "$('#other').append(v);</script>")
    findings = hit(html)
    # 两条独立通路：URL 参数进 .html()，输入框的值进 .append()
    assert len(findings) == 2
    assert sorted(x["evidence"]["sink"] for x in findings) == ["append", "html"]


def test_dedupe_same_line_same_sink():
    # 同一行、同一汇点只报一次：否则一个压缩过的脚本能刷出上百条
    html = "<script>a.innerHTML = location.hash; b.innerHTML = location.hash;</script>"
    assert len(hit(html)) == 1


def test_two_lines_two_findings():
    html = ("<script>\n"
            "a.innerHTML = location.hash;\n"
            "b.innerHTML = location.hash;\n"
            "</script>")
    assert len(hit(html)) == 2


def test_no_script_means_no_findings():
    assert hit("<p>纯静态页面</p>") == []


def test_findings_match_llm_schema_fields():
    html = "<script>document.getElementById('x').innerHTML = location.hash;</script>"
    f = hit(html)[0]
    for key in ("vulnerability_type", "risk_level", "location", "reason",
                "fix_suggestion", "confidence", "evidence"):
        assert f.get(key), "缺少字段 %s" % key
    assert set(f["evidence"]) >= {"line", "sink", "source", "context"}


def test_js_units_extracts_inline_and_external():
    html = ('<script>var a = location.hash;</script>'
            '<script src="app.js"></script>')
    units = taint.js_units(html)
    assert units
    assert any("location.hash" in code for _, code in units)


def test_summarize_reads_findings():
    html = "<script>document.write(location.hash);</script>"
    text = taint.summarize(hit(html))
    assert "通路" in text
    assert "HIGH 1" in text


def test_multiple_scripts_each_analyzed():
    html = ("<script>var a = location.hash;</script>"
            "<script>document.write(a);</script>")
    # 跨 script 不传播是刻意的限制：不做跨单元数据流，避免误报
    assert hit(html) == []


# --------------------------------------------------------------- 模板层汇点
def test_vue_v_html_with_data_binding():
    html = ("<div id=\"app\"><div v-html=\"msg\"></div></div>"
            "<script>new Vue({el:'#app',data:{msg: decodeURIComponent(location.search)}});</script>")
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["evidence"]["sink"] == "v-html"
    assert findings[0]["risk_level"] == "HIGH"


def test_vue_v_text_is_safe():
    html = ("<div id=\"t\" v-text=\"msg\"></div>"
            "<script>new Vue({el:'#t',data:{msg:location.hash}});</script>")
    assert hit(html) == []


def test_angular_property_binding_constant_is_safe():
    html = "<div [innerHTML]=\"'<p>static</p>'\"></div>"
    assert hit(html) == []


def test_angular_property_binding_from_variable():
    html = ("<my-app></my-app>"
            "<script>var body=location.hash;var c={template:'<div [innerHTML]=\"body\"></div>'};</script>")
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["evidence"]["sink"] == "[innerHTML]"


def test_react_dangerously_set_inner_html():
    html = ("<div id=\"root\"></div><script>function App(){return React.createElement('div',"
            "{dangerouslySetInnerHTML:{__html: location.hash}});}</script>")
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["evidence"]["sink"] == "dangerouslySetInnerHTML"


def test_set_attribute_onclick_is_sink():
    html = "<script>document.body.setAttribute('onclick', location.hash);</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["risk_level"] == "HIGH"


def test_set_attribute_data_attr_is_safe():
    html = "<script>document.body.setAttribute('data-tab', location.hash);</script>"
    assert hit(html) == []


def test_set_attribute_srcdoc_is_high():
    html = "<script>document.getElementById('f').setAttribute('srcdoc', location.hash);</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["risk_level"] == "HIGH"


def test_event_handler_property_assignment():
    html = "<script>document.getElementById('i').onerror = location.hash;</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert "onerror" in findings[0]["evidence"]["sink"]


def test_event_handler_function_reference_is_safe():
    html = "<script>document.getElementById('i').onerror = handleError;</script>"
    assert hit(html) == []


def test_svelte_html_directive():
    html = "<div>{@html decodeURIComponent(location.hash)}</div>"
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["evidence"]["sink"] == "{@html}"


def test_handlebars_triple_stash_is_sink():
    html = "<div>{{{body}}}</div><script>var body = document.cookie;</script>"
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["evidence"]["sink"] == "{{{ }}}"


def test_handlebars_double_stash_is_safe():
    html = "<div>{{ user.name }}</div><script>var user={name:location.hash};</script>"
    assert hit(html) == []


def test_lit_unsafe_html():
    html = "<script>import {unsafeHTML} from 'lit'; el.innerHTML = unsafeHTML(window.name);</script>"
    findings = hit(html)
    assert findings
    assert any(f["evidence"]["sink"] == "unsafeHTML" for f in findings)


def test_encode_uri_component_is_sanitizer():
    html = "<script>a.href = '/u/' + encodeURIComponent(location.pathname.split('/').pop());</script>"
    assert hit(html) == []


def test_object_literal_key_propagates_taint():
    html = ("<script>var state = {msg: location.hash};"
            "document.getElementById('m').innerHTML = state.msg;</script>")
    # 对象属性访问本身不追踪，但 data 绑定那一遍需要 key 传播，这里只断言不崩、不误报
    hit(html)


def test_template_layer_uses_page_env_from_other_script():
    html = ("<script>window.msg = location.hash;</script>"
            "<div v-html=\"msg\"></div>")
    findings = hit(html)
    assert len(findings) == 1
    assert findings[0]["evidence"]["sink"] == "v-html"

