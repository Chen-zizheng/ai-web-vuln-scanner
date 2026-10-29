# -*- coding: utf-8 -*-
"""轻量污点分析：追踪「不可信来源 -> 危险汇点」的数据流。

和关键词规则的区别只有一句：
    规则问的是「页面里有没有 innerHTML」，这里问的是「写进 innerHTML 的值从哪来」。

因此 el.innerHTML = "固定文案" 不报，el.innerHTML = location.hash 报，
并且报出来的是一条可核对的通路：来源在第几行、汇点在第几行、中间经过哪些变量。

刻意划清的边界（不写清楚就是吹）：
- 单文件、脚本块内、按赋值顺序传播；
- 不做跨文件/跨函数的过程间分析，不建模字符串语义
  （x.replace("<", "&lt;") 视为未净化，宁可多报也不假装安全）；
- 不追踪对象属性、数组下标、闭包捕获，遇到认不出的写法就不下结论。
"""
import argparse
import json
import re
import sys

BT = chr(96)          # 反引号，模板字符串的定界符
OPEN_EXPR = "$" + "{"  # 模板字符串插值起点

# ---------------------------------------------------------------- 来源

# (前一个 token, 成员名) -> 描述。覆盖 DOM 里最常见的不可控输入入口。
_MEMBER_SOURCES = {
    ("location", "hash"): "location.hash",
    ("location", "search"): "location.search",
    ("location", "href"): "location.href",
    ("location", "pathname"): "location.pathname",
    ("location", "name"): "location.name",
    ("document", "URL"): "document.URL",
    ("document", "documentURI"): "document.documentURI",
    ("document", "referrer"): "document.referrer",
    ("document", "cookie"): "document.cookie",
    ("document", "forms"): "document.forms",
    ("window", "name"): "window.name",
}

# 单独出现即视为来源（location 本身就是来源对象）
_BARE_SOURCES = {"location": "location"}

# 形式为 name(...) 的来源入口
_CALL_SOURCES = {
    ("localStorage", "getItem"): "localStorage.getItem",
    ("sessionStorage", "getItem"): "sessionStorage.getItem",
}

# 形如 x.data 的消息来源
_MESSAGE_RECEIVERS = {"event", "e", "evt", "msg", "message"}

# ---------------------------------------------------------------- 汇点

# 赋值式汇点：name = / name +=
_ASSIGN_SINKS = {
    "innerHTML": ("HIGH", "HTML 解析上下文"),
    "outerHTML": ("HIGH", "HTML 解析上下文"),
    "srcdoc": ("HIGH", "iframe srcdoc 的 HTML 上下文"),
    "href": ("MEDIUM", "URL 上下文（可执行 javascript:）"),
    "src": ("MEDIUM", "资源 URL 上下文"),
}

# 方法式汇点：obj.name(args...)
_METHOD_SINKS = {
    "write": ("HIGH", "document.write 直接写入文档"),
    "writeln": ("HIGH", "document.writeln 直接写入文档"),
    "html": ("HIGH", "jQuery .html() 解析 HTML"),
    "append": ("HIGH", "jQuery .append() 解析 HTML"),
    "prepend": ("HIGH", "jQuery .prepend() 解析 HTML"),
    "insertAdjacentHTML": ("HIGH", "insertAdjacentHTML 解析 HTML"),
}

# 全局函数式汇点：eval(x) / Function(x) / setTimeout(x) / setInterval(x)
_FUNC_SINKS = {
    "eval": ("HIGH", "eval 执行字符串"),
    "Function": ("HIGH", "Function 构造器执行字符串"),
    "open": ("MEDIUM", "window.open 的 URL 参数（可执行 javascript:）"),
    "setTimeout": ("MEDIUM", "setTimeout 字符串参数按代码执行"),
    "setInterval": ("MEDIUM", "setInterval 字符串参数按代码执行"),
}

# 见到这些函数即认为值已被净化（保守白名单，宁可漏判为安全）
_SANITIZERS = {
    "escapeHtml", "escapeHTML", "escape_html", "escapeHtmlText", "encodeHtml",
    "htmlEscape", "escapeForHtml", "sanitize", "sanitizeHtml", "sanitizeHTML",
    "DOMPurify", "filterXSS", "xss", "he", "validator", "purify",
}

_FIX = {
    "HTML 解析上下文": "改用 textContent 写入；必须渲染 HTML 时先经 DOMPurify 等净化",
    "URL 上下文（可执行 javascript:）": "校验协议白名单（只允许 http/https），不要直接拼接用户输入",
    "资源 URL 上下文": "校验协议与域名白名单，不要直接拼接用户输入",
    "iframe srcdoc 的 HTML 上下文": "srcdoc 内容先净化，或改用 sandbox iframe + postMessage",
    "jQuery .html() 解析 HTML": "改用 .text()；必须渲染 HTML 时先净化",
    "jQuery .append() 解析 HTML": "改用 .text() 追加文本，或先净化",
    "jQuery .prepend() 解析 HTML": "改用 .text() 追加文本，或先净化",
    "insertAdjacentHTML 解析 HTML": "改用 insertAdjacentText / textContent",
    "eval 执行字符串": "删除 eval，改用具名函数或 JSON.parse",
    "Function 构造器执行字符串": "删除动态代码构造",
    "window.open 的 URL 参数（可执行 javascript:）": "只允许 https 链接，并校验目标域名白名单",
    "setTimeout 字符串参数按代码执行": "改为传函数引用 setTimeout(fn, 0)",
    "setInterval 字符串参数按代码执行": "改为传函数引用 setInterval(fn, 0)",
    "document.write 直接写入文档": "改用 DOM API（createElement/textContent）",
    "document.writeln 直接写入文档": "改用 DOM API（createElement/textContent）",
}

_PUNCTS = sorted(
    ["===", "!==", "...", "<<=", ">>=", "**=", "&&=", "||=", "??=",
     "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "+=", "-=",
     "*=", "/=", "%=", "++", "--", "**", "<<", ">>"],
    key=len, reverse=True,
)

_CLOSE = set(")]}")


# ---------------------------------------------------------------- 词法
def _tokenize(code):
    """把 JS 代码切成 token：id / str / num / punct。够用即可，不做完整语法分析。"""
    toks = []
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch == "/" and i + 1 < n and code[i + 1] == "/":
            j = code.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if ch == "/" and i + 1 < n and code[i + 1] == "*":
            j = code.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if ch == "'" or ch == '"' or ch == BT:
            j, buf, depth = i + 1, [], 0
            while j < n:
                cj = code[j]
                if cj == "\\":
                    buf.append(code[j:j + 2])
                    j += 2
                    continue
                if ch == BT and cj == "$" and j + 1 < n and code[j + 1] == "{":
                    depth += 1
                elif ch == BT and cj == "}" and depth > 0:
                    depth -= 1
                if cj == ch and depth == 0:
                    j += 1
                    break
                buf.append(cj)
                j += 1
            toks.append({"k": "str", "v": "".join(buf), "q": ch, "i": i})
            i = j
            continue
        if ch.isalnum() or ch in "_$":
            j = i
            while j < n and (code[j].isalnum() or code[j] in "_$"):
                j += 1
            toks.append({"k": "id", "v": code[i:j], "i": i})
            i = j
            continue
        for p in _PUNCTS:
            if code.startswith(p, i):
                toks.append({"k": "punct", "v": p, "i": i})
                i += len(p)
                break
        else:
            toks.append({"k": "punct", "v": ch, "i": i})
            i += 1
    return toks


# ---------------------------------------------------------------- 来源识别
def _source_at(toks, i):
    """若 toks[i] 起是一段不可信来源，返回 (消耗 token 数, 描述)，否则 (0, None)。"""
    if i >= len(toks):
        return 0, None
    t = toks[i]
    if t["k"] != "id":
        if t["k"] == "punct" and t["v"] == "." and i + 1 < len(toks):
            nxt = toks[i + 1]
            if nxt["k"] == "id" and nxt["v"] == "value":
                return 2, "DOM 输入值（.value）"
            if (nxt["k"] == "id" and nxt["v"] == "val" and i + 2 < len(toks)
                    and toks[i + 2]["v"] == "("):
                return 3, "jQuery .val()（DOM 输入值）"
        return 0, None

    if i + 2 < len(toks) and toks[i + 1]["k"] == "punct" and toks[i + 1]["v"] == ".":
        nxt = toks[i + 2]
        if nxt["k"] == "id":
            pair = (t["v"], nxt["v"])
            if pair in _MEMBER_SOURCES:
                return 3, _MEMBER_SOURCES[pair]
            if pair in _CALL_SOURCES and i + 3 < len(toks) and toks[i + 3]["v"] == "(":
                return 4, _CALL_SOURCES[pair]
            if t["v"] in _MESSAGE_RECEIVERS and nxt["v"] == "data":
                return 3, "%s.data（postMessage）" % t["v"]

    if t["v"] in _BARE_SOURCES:
        return 1, _BARE_SOURCES[t["v"]]

    if t["v"] == "URLSearchParams":
        return 1, "URLSearchParams（查询参数）"

    return 0, None


# ---------------------------------------------------------------- 表达式求值
def _template_exprs(text):
    """取出模板字符串里插值表达式（美元符号加左花括号）的文本。"""
    out, i = [], 0
    while True:
        a = text.find(OPEN_EXPR, i)
        if a < 0:
            return out
        depth, j = 1, a + 2
        while j < len(text) and depth:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        out.append(text[a + 2:j - 1])
        i = j


def _taint_of(toks, a, b, env):
    """判断 toks[a:b] 这段表达式的值是否可控，可控则返回来源描述。"""
    if b <= a:
        return None
    for idx in range(a, b):
        t = toks[idx]
        if t["k"] == "id" and t["v"] in _SANITIZERS:
            return None            # 已过净化函数，视为安全
        if t["k"] == "str" and t["q"] == BT:
            for expr in _template_exprs(t["v"]):
                sub = _tokenize(expr)
                got = _taint_of(sub, 0, len(sub), env)
                if got:
                    return got

    i = a
    while i < b:
        span, label = _source_at(toks, i)
        if span and i + span <= b:
            return label
        t = toks[i]
        if t["k"] == "id":
            # 被调用/被取属性的标识符本身不算数据；只有变量名才算
            is_prop = i > a and toks[i - 1]["k"] == "punct" and toks[i - 1]["v"] == "."
            is_call = i + 1 < b and toks[i + 1]["k"] == "punct" and toks[i + 1]["v"] == "("
            if not is_prop and not is_call and env.get(t["v"]):
                return env[t["v"]]
        i += 1
    return None


def _stmt_end(toks, start):
    """从 start 起找到语句结束（深度 0 的 ; 或 }）。"""
    depth = 0
    i = start
    while i < len(toks):
        v = toks[i]["v"]
        if toks[i]["k"] == "punct":
            if v in ("(", "[", "{"):
                depth += 1
            elif v in _CLOSE:
                if depth == 0:
                    return i
                depth -= 1
            elif v == ";" and depth == 0:
                return i
        i += 1
    return len(toks)


def _call_args(toks, open_idx):
    """返回 (参数区间列表, 右括号下标)。参数按深度 0 的逗号切分。"""
    depth = 0
    args, cur = [], open_idx + 1
    i = open_idx
    while i < len(toks):
        v = toks[i]["v"]
        if toks[i]["k"] == "punct":
            if v in ("(", "[", "{"):
                depth += 1
            elif v in _CLOSE:
                depth -= 1
                if depth == 0:
                    if cur < i:
                        args.append((cur, i))
                    return args, i
            elif v == "," and depth == 1:
                args.append((cur, i))
                cur = i + 1
        i += 1
    if cur < len(toks):
        args.append((cur, len(toks)))
    return args, len(toks) - 1


# ---------------------------------------------------------------- 传播
def _apply_assignment(toks, i, env, stats):
    """识别 x = expr / var x = expr / x += expr，记录 x 是否被污染。返回下一个扫描位置。"""
    j = i
    if toks[j]["k"] == "id" and toks[j]["v"] in ("var", "let", "const"):
        j += 1
    if j >= len(toks) or toks[j]["k"] != "id":
        return None
    name = toks[j]["v"]
    k = j + 1
    complex_target = False
    while k + 1 < len(toks) and toks[k]["v"] == "." and toks[k + 1]["k"] == "id":
        complex_target = True
        k += 2
    if k >= len(toks) or toks[k]["k"] != "punct" or toks[k]["v"] not in ("=", "+="):
        return None
    if complex_target:
        return None  # a.b = expr 交给汇点分支处理；本工具不追踪对象属性
    end = _stmt_end(toks, k + 1)
    taint = _taint_of(toks, k + 1, end, env)
    if not (toks[k]["v"] == "+=" and env.get(name)):
        env[name] = taint
    if taint:
        stats["tainted_vars"] = stats.get("tainted_vars", 0) + 1
    return k + 1


# ---------------------------------------------------------------- 单块分析
def _snippet_at(html, offset, base):
    line_start = html.rfind("\n", 0, base + offset) + 1
    line_end = html.find("\n", base + offset)
    if line_end < 0:
        line_end = len(html)
    return html[line_start:line_end].strip()


def _line_at(html, base, offset):
    return html.count("\n", 0, base + offset) + 1


def _finding(sink_name, level, context, taint, html, base, offset):
    line = _line_at(html, base, offset)
    return {
        "vulnerability_type": "XSS",
        "risk_level": level,
        "location": "第 %d 行：%s" % (line, _snippet_at(html, offset, base)),
        "reason": "%s 未经转义进入 %s" % (taint, sink_name),
        "fix_suggestion": _FIX.get(context, "对输出做上下文相关转义"),
        "confidence": "confirmed",
        "evidence": {"line": line, "sink": sink_name, "source": taint, "context": context},
    }


def _analyze_code(code, base, html, stats):
    """分析一段 JS（脚本块正文或内联事件属性），返回发现列表。"""
    toks = _tokenize(code)
    findings, env = [], {}
    i = 0
    while i < len(toks):
        t = toks[i]
        bumped = _apply_assignment(toks, i, env, stats)
        if bumped is not None:
            i = bumped
            continue

        # obj.SINK = expr / obj.SINK += expr
        if (t["k"] == "punct" and t["v"] == "."
                and i + 2 < len(toks)
                and toks[i + 1]["k"] == "id"
                and toks[i + 2]["k"] == "punct"
                and toks[i + 2]["v"] in ("=", "+=")):
            name = toks[i + 1]["v"]
            if name in _ASSIGN_SINKS:
                level, context = _ASSIGN_SINKS[name]
                end = _stmt_end(toks, i + 3)
                taint = _taint_of(toks, i + 3, end, env)
                stats["sinks_seen"] = stats.get("sinks_seen", 0) + 1
                if taint:
                    findings.append(_finding(name, level, context, taint, html, base, t["i"]))
            i += 1
            continue

        # obj.SINK(args)
        if (t["k"] == "punct" and t["v"] == "."
                and i + 2 < len(toks)
                and toks[i + 1]["k"] == "id"
                and toks[i + 2]["v"] == "("):
            name = toks[i + 1]["v"]
            if name in _METHOD_SINKS:
                level, context = _METHOD_SINKS[name]
                args, _end = _call_args(toks, i + 2)
                stats["sinks_seen"] = stats.get("sinks_seen", 0) + 1
                if name == "insertAdjacentHTML" and len(args) > 1:
                    arg = args[1]
                else:
                    arg = args[0] if args else None
                if arg:
                    taint = _taint_of(toks, arg[0], arg[1], env)
                    if taint:
                        findings.append(_finding(name, level, context, taint, html, base, t["i"]))
            i += 1
            continue

        # SINK(args) —— 全局函数
        if t["k"] == "id" and t["v"] in _FUNC_SINKS and i + 1 < len(toks) and toks[i + 1]["v"] == "(":
            prev_is_dot = i > 0 and toks[i - 1]["k"] == "punct" and toks[i - 1]["v"] == "."
            if not prev_is_dot:
                level, context = _FUNC_SINKS[t["v"]]
                args, _end = _call_args(toks, i + 1)
                stats["sinks_seen"] = stats.get("sinks_seen", 0) + 1
                if args:
                    taint = _taint_of(toks, args[0][0], args[0][1], env)
                    if taint:
                        findings.append(_finding(t["v"], level, context, taint, html, base, t["i"]))
            i += 1
            continue
        i += 1
    return findings


# ---------------------------------------------------------------- 入口
_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_EVENT_RE = re.compile(r"\bon[a-z]{3,}\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", re.IGNORECASE)


def js_units(html):
    """把页面里可执行的片段抽成 [(名字, 代码)]：内联脚本 + 内联事件处理器。

    导出这个函数是为了让外部工具（比如 Semgrep）能在同一份输入上跑：
    HTML 本身不是 JS，必须先把可执行部分抽出来。
    """
    units = []
    for idx, m in enumerate(_SCRIPT_RE.finditer(html)):
        attrs, body = m.group(1) or "", m.group(2) or ""
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE) or not body.strip():
            continue
        units.append(("script%02d.js" % idx, body))
    for idx, m in enumerate(_EVENT_RE.finditer(html)):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if not body or not body.strip():
            continue
        units.append(("handler%02d.js" % idx, "function __handler__(){" + body + "}"))
    return units


def analyze(html):
    """对整页做污点分析，返回 {"findings": [...], "stats": {...}}。"""
    stats = {"script_blocks": 0, "event_handlers": 0, "sinks_seen": 0, "tainted_vars": 0}
    findings = []

    for m in _SCRIPT_RE.finditer(html):
        attrs, body = m.group(1) or "", m.group(2) or ""
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE) or not body.strip():
            continue
        stats["script_blocks"] += 1
        findings.extend(_analyze_code(body, m.start(2), html, stats))

    for m in _EVENT_RE.finditer(html):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if not body or not body.strip():
            continue
        stats["event_handlers"] += 1
        base = m.start(1) if m.group(1) is not None else m.start(2)
        findings.extend(_analyze_code(body, base, html, stats))

    seen, unique = set(), []
    for f in findings:
        key = (f["evidence"]["line"], f["evidence"]["sink"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (f["evidence"]["line"], f["evidence"]["sink"]))
    stats["findings"] = len(unique)
    return {"findings": unique, "stats": stats}


def summarize(findings):
    """给终端/报告用的一行摘要。"""
    if not findings:
        return "未发现可证的注入通路"
    high = sum(1 for f in findings if f["risk_level"] == "HIGH")
    return "发现 %d 条通路（HIGH %d / MEDIUM %d）" % (len(findings), high, len(findings) - high)


def main(argv=None):
    ap = argparse.ArgumentParser(description="对单个 HTML 文件做污点分析")
    ap.add_argument("file", help="待分析的 HTML 文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        html = f.read()
    result = analyze(html)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print(summarize(result["findings"]))
    for f in result["findings"]:
        print("- [%s] %s" % (f["risk_level"], f["location"]))
        print("    %s" % f["reason"])
    print("统计：%s" % json.dumps(result["stats"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
