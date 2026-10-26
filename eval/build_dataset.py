# -*- coding: utf-8 -*-
"""生成 eval/dataset.jsonl。

每条样本由人工编写并人工标注，标注规则见 eval/README.md：
判定的是「页面是否存在 XSS 风险点」，即不可信输入是否可能进入可执行上下文。
这里刻意混入大量「有 sink 但无 source」的干扰样本，用来暴露纯关键词规则的误报。
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# (id, 是否风险, 风险等级, 说明, html)
SAMPLES = [
    # ---------------- 正例：source 进入 sink（22 条）
    ("xss-001", True, "HIGH", "表单输入直接写入 innerHTML",
     '<form><input name="q" id="q"></form><div id="out"></div>'
     '<script>document.getElementById("out").innerHTML = document.getElementById("q").value;</script>'),
    ("xss-002", True, "HIGH", "document.write 输出 URL 查询参数",
     '<script>document.write(location.search);</script>'),
    ("xss-003", True, "HIGH", "eval 执行用户输入",
     '<form><input id="cmd"></form><script>var c=document.getElementById("cmd").value; eval(c);</script>'),
    ("xss-004", True, "HIGH", "内联事件拼接不可信数据",
     "<a href=\"#\" onclick=\"go('+location.hash+')\">go</a>"),
    ("xss-005", True, "HIGH", "setTimeout 传入用户字符串",
     '<script>var n=location.hash.slice(1); setTimeout(n, 100);</script>'),
    ("xss-006", True, "HIGH", "图片 onerror 执行拼接数据",
     '<img src="x" onerror="this.src=location.search">'),
    ("xss-007", True, "HIGH", "src 属性由查询参数赋值",
     '<script>document.getElementById("pic").src = location.search.slice(1);</script><img id="pic">'),
    ("xss-008", True, "HIGH", "搜索结果原样回显到 innerHTML",
     '<form><input name="kw"></form><div id="r"></div>'
     '<script>var kw=new URLSearchParams(location.search).get("kw"); document.getElementById("r").innerHTML=kw;</script>'),
    ("xss-009", True, "HIGH", "评论内容写入页面",
     '<textarea id="c"></textarea><div id="list"></div>'
     '<script>document.getElementById("list").innerHTML += document.getElementById("c").value;</script>'),
    ("xss-010", True, "HIGH", "隐藏字段回填后写入 DOM",
     '<form><input type="hidden" id="back" value=""></form><div id="bx"></div>'
     '<script>document.getElementById("bx").innerHTML=document.getElementById("back").value;</script>'),
    ("xss-011", True, "HIGH", "location.hash 直接 document.write",
     '<div id="main"></div><script>document.write("<p>"+location.hash+"</p>");</script>'),
    ("xss-012", True, "HIGH", "模板字符串拼进 innerHTML",
     '<script>var u=new URLSearchParams(location.search).get("u");'
     'document.body.innerHTML=`<h1>${u}</h1>`;</script>'),
    ("xss-013", True, "MEDIUM", "jQuery html 写入输入框值",
     '<form><input id="nm"></form><div id="d"></div>'
     '<script>$("#d").html($("#nm").val());</script>'),
    ("xss-014", True, "MEDIUM", "srcdoc 由查询参数构造",
     '<iframe id="f"></iframe><script>document.getElementById("f").srcdoc=location.search;</script>'),
    ("xss-015", True, "MEDIUM", "onmouseover 内联处理器读取参数",
     "<div onmouseover=\"this.innerHTML=location.hash\">hover</div>"),
    ("xss-016", True, "HIGH", "eval 执行回调名（JSONP 风格）",
     '<script>var cb=new URLSearchParams(location.search).get("cb"); eval(cb+"({})");</script>'),
    ("xss-017", True, "HIGH", "document.write 输出 hash",
     '<script>var h=location.hash.substring(1); document.write(h);</script>'),
    ("xss-018", True, "MEDIUM", "localStorage 中的值写入 innerHTML",
     '<script>document.getElementById("u").innerHTML=localStorage.getItem("nick");</script><div id="u"></div>'),
    ("xss-019", True, "HIGH", "表单提交值拼进新窗口文档",
     '<form onsubmit="open(this.q.value)"><input name="q"></form>'),
    ("xss-020", True, "HIGH", "字符串拼接后交给 setTimeout",
     '<script>var p=new URLSearchParams(location.search).get("p"); setTimeout("alert("+p+")",500);</script>'),
    ("xss-021", True, "MEDIUM", "innerHTML 写入 URL 片段",
     '<div id="t"></div><script>document.getElementById("t").innerHTML=decodeURIComponent(location.hash.slice(1));</script>'),
    ("xss-022", True, "HIGH", "留言板内容以 HTML 形式输出",
     '<form><input name="msg" id="m"></form><div id="wall"></div>'
     '<script>document.getElementById("wall").insertAdjacentHTML("beforeend", document.getElementById("m").value);</script>'),

    # ---------------- 负例：有 sink 但数据源不可控（16 条）
    ("safe-001", False, "LOW", "innerHTML 写入常量",
     '<div id="a"></div><script>document.getElementById("a").innerHTML="<b>hello</b>";</script>'),
    ("safe-002", False, "LOW", "document.write 输出常量",
     '<script>document.write("<p>Copyright 2026</p>");</script>'),
    ("safe-003", False, "LOW", "eval 执行常量表达式",
     '<script>eval("1+1");</script>'),
    ("safe-004", False, "LOW", "setTimeout 传函数引用",
     '<script>setTimeout(function(){console.log("tick")},1000);</script>'),
    ("safe-005", False, "LOW", "img.src 赋值为静态路径",
     '<script>document.getElementById("i").src="/static/logo.png";</script><img id="i">'),
    ("safe-006", False, "LOW", "使用 textContent 而非 innerHTML",
     '<form><input id="q"></form><div id="o"></div>'
     '<script>document.getElementById("o").textContent=document.getElementById("q").value;</script>'),
    ("safe-007", False, "LOW", "服务端已转义后输出",
     '<div id="out"></div><script>var v="&lt;script&gt;"; document.getElementById("out").innerHTML=v;</script>'),
    ("safe-008", False, "LOW", "innerHTML 清空节点",
     '<div id="c"></div><script>document.getElementById("c").innerHTML="";</script>'),
    ("safe-009", False, "LOW", "setInterval 传常量字符串",
     '<script>setInterval("clock()",1000);</script>'),
    ("safe-010", False, "LOW", "document.write 输出静态公告",
     '<script>document.write("<marquee>系统维护通知</marquee>");</script>'),
    ("safe-011", False, "LOW", "innerHTML 拼接常量模板",
     '<script>var t="<li>%s</li>"; document.body.innerHTML=t.replace("%s","固定项");</script>'),
    ("safe-012", False, "LOW", "eval 调用本地定义函数",
     '<script>function f(){return 1} eval("f()");</script>'),
    ("safe-013", False, "LOW", "src 指向常量 CDN",
     '<script>var s=document.createElement("script"); s.src="https://cdn.example.com/lib.js"; document.head.appendChild(s);</script>'),
    ("safe-014", False, "LOW", "innerHTML 写入数字计算结果",
     '<div id="n"></div><script>document.getElementById("n").innerHTML=String(6*7);</script>'),
    ("safe-015", False, "LOW", "onclick 调用无参函数",
     '<button onclick="submitForm()">提交</button>'),
    ("safe-016", False, "LOW", "框架模板绑定（自动转义）",
     '<div id="app"><p>{{ message }}</p></div><script>new Vue({el:"#app",data:{message:"<b>x</b>"}});</script>'),

    # ---------------- 负例：表单但无执行型 sink（12 条）
    ("safe-017", False, "LOW", "登录表单，无前端输出",
     '<form action="/login.php" method="post"><input name="user"><input type="password" name="pwd">'
     '<button type="submit">登录</button></form>'),
    ("safe-018", False, "LOW", "搜索表单 GET 提交到后端",
     '<form action="/search" method="get"><input name="q"><button>搜索</button></form>'),
    ("safe-019", False, "LOW", "注册表单，前端仅做校验",
     '<form id="f"><input name="email" type="email"><span id="tip"></span></form>'
     '<script>document.getElementById("f").onsubmit=function(e){e.preventDefault();'
     'document.getElementById("tip").textContent="ok";};</script>'),
    ("safe-020", False, "LOW", "纯静态介绍页",
     '<h1>关于我们</h1><p>本公司成立于 2019 年。</p><footer>© 2026</footer>'),
    ("safe-021", False, "LOW", "表单 + alert 固定文案",
     '<form><input name="q"><button onclick="alert(\'已提交\')">提交</button></form>'),
    ("safe-022", False, "LOW", "无脚本的商品列表",
     '<ul><li>商品 A</li><li>商品 B</li></ul>'),
    ("safe-023", False, "LOW", "带 CSP 的页面",
     '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
     '<div id="x"></div><script>document.getElementById("x").textContent="hi";</script>'),
    ("safe-024", False, "LOW", "文件上传表单，无前端回显",
     '<form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="f"></form>'),
    ("safe-025", False, "LOW", "评论表单提交到后端接口",
     '<form id="c"><textarea name="body"></textarea><button>发表</button></form>'
     '<script>document.getElementById("c").addEventListener("submit",function(e){e.preventDefault();'
     'fetch("/api/comment",{method:"POST",body:new FormData(this)});});</script>'),
    ("safe-026", False, "LOW", "分页链接无脚本",
     '<nav><a href="?page=2">下一页</a><a href="?page=3">末页</a></nav>'),
    ("safe-027", False, "LOW", "表格展示服务端已渲染数据",
     '<table><tr><td>张三</td><td>2026-01-01</td></tr></table>'),
    ("safe-028", False, "LOW", "锚点跳转导航",
     '<a href="#section2">跳到第二节</a><h2 id="section2">第二节</h2>'),
]


def main():
    path = os.path.join(HERE, "dataset.jsonl")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for sid, risky, level, note, html in SAMPLES:
            rec = {
                "id": sid,
                "html": html,
                "note": note,
                "label": {"has_xss_risk": risky, "risk_level": level},
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    n_pos = sum(1 for s in SAMPLES if s[1])
    print("written %d samples (%d positive / %d negative) -> %s"
          % (len(SAMPLES), n_pos, len(SAMPLES) - n_pos, path))


if __name__ == "__main__":
    main()
