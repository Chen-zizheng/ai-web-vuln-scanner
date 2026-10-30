"""本地网页界面：拖入 HTML 文件或网址，直接在浏览器里看泄点分析结果。

设计上的两个硬约束：
1. 只监听 127.0.0.1，且只接受带本次启动随机 token 的请求（防止别的网页偷偷往 localhost 提交内容）。
2. 抓网址时禁内网/回环地址、限制跳转次数与响应大小（防止被当成 SSRF 跳板）。
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlparse

import requests

import scanner_core
import taint

MAX_UPLOAD_BYTES = 2 * 1024 * 1024      # 单个页面正文上限
MAX_REDIRECTS = 3
FETCH_TIMEOUT = 10
ALLOWED_PORTS = {80, 443, 8080, 8443}
USER_AGENT = "xss-taint-scanner/1.1 (+local)"


def _page_path() -> str:
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "page.html")


def page_bytes() -> bytes:
    """读出页面并把模型可用标记替换掉，每次请求都重新读（改页面不用重启）。"""
    with open(_page_path(), "rb") as fh:
        html = fh.read().decode("utf-8")
    flag = "true" if os.environ.get("DEEPSEEK_API_KEY") else "false"
    return html.replace("{{LLM_AVAILABLE}}", flag).encode("utf-8")


def _status_hint(code: int) -> str:
    if code in (401, 403):
        return ("目标返回 HTTP %d：站点拒绝了非浏览器请求（反爬、需要登录或需要 JS 渲染）。"
                "在浏览器里打开这个页面，Ctrl+S 另存为 HTML，再把文件拖进来扫描。" % code)
    if code == 429:
        return "目标返回 HTTP 429：被限流了，等一会儿再试。"
    if 300 <= code < 400:
        return "目标返回 HTTP %d：这种跳转方式无法跟随。" % code
    return "目标返回 HTTP %d" % code


class FetchError(Exception):
    """抓取失败，消息直接展示给用户。"""


def _assert_public_host(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise FetchError("域名解析失败：%s" % host)
    if not infos:
        raise FetchError("域名解析失败：%s" % host)
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise FetchError("无法识别的地址：%s" % addr)
        if not ip.is_global:
            raise FetchError("拒绝访问内网或保留地址：%s（%s）" % (host, addr))


def fetch_page(url: str) -> tuple[str, str]:
    """抓取公开页面，返回 (html, 说明)。只允许 http/https 与常见端口。"""
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise FetchError("只支持 http / https，收到：%s" % (parsed.scheme or "空"))
        if not parsed.hostname:
            raise FetchError("网址不完整：%s" % url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in ALLOWED_PORTS:
            raise FetchError("端口 %d 不在允许范围（80/443/8080/8443）" % port)
        _assert_public_host(parsed.hostname)

        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT, stream=True, allow_redirects=False,
                                headers={"User-Agent": USER_AGENT,
                                         "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                                         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"})
        except requests.RequestException as exc:
            raise FetchError("请求失败：%s" % exc)

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            resp.close()
            if not location:
                raise FetchError("服务器返回 %d 却没有跳转地址" % resp.status_code)
            url = urljoin(url, location)
            continue
        if resp.status_code >= 400:
            resp.close()
            raise FetchError(_status_hint(resp.status_code))

        ctype = (resp.headers.get("Content-Type") or "").lower()
        if ctype and "html" not in ctype and "text/" not in ctype:
            resp.close()
            raise FetchError("目标不是 HTML（Content-Type: %s）" % ctype)

        chunks, total, truncated = [], 0, False
        try:
            for chunk in resp.iter_content(65536):
                if not chunk:
                    continue
                if total + len(chunk) > MAX_UPLOAD_BYTES:
                    chunks.append(chunk[: MAX_UPLOAD_BYTES - total])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            resp.close()

        raw = b"".join(chunks)
        if not raw.strip():
            resp.close()
            raise FetchError("目标返回了空页面：内容由 JavaScript 在浏览器里渲染，抓下来没有可分析的 HTML。"
                             "请在浏览器里打开这个页面，Ctrl+S 另存为 HTML，再把文件拖进来。")
        text = raw.decode(resp.encoding or "utf-8", errors="replace")
        note = "已按 2 MB 截断" if truncated else "抓取成功"
        return text, note
    raise FetchError("跳转次数超过 %d 次" % MAX_REDIRECTS)


def scan_html(html: str, source: str, use_llm: bool = False, api_key: str = "") -> dict:
    """跑一遍静态分析，可选追加模型研判。返回给前端的结果结构。"""
    result = taint.analyze(html)
    payload = {
        "source": source,
        "findings": result["findings"],
        "stats": result["stats"],
        "summary": taint.summarize(result["findings"]),
        "suspected": [],
        "llm_note": "",
        "llm": {"requested": bool(use_llm), "ok": False, "dry_run": False,
                "model": scanner_core.MODEL, "count": 0, "error": ""},
        "truncated": len(html) > MAX_UPLOAD_BYTES,
    }
    if use_llm:
        try:
            # build_prompt 内部已经做了脱敏与截断，这里不要再手动拼一遍
            prompt = scanner_core.build_prompt(source, scanner_core.extract_features(html))
            answer = scanner_core.call_llm(prompt, api_key=api_key)
            if isinstance(answer, dict) and answer.get("dry_run"):
                payload["llm_note"] = "dry-run：payload 已落盘，未联网"
                payload["llm"]["ok"] = True
                payload["llm"]["dry_run"] = True
            elif isinstance(answer, list):
                payload["suspected"] = [x for x in answer if isinstance(x, dict)]
            elif isinstance(answer, dict):
                payload["suspected"] = [answer]
            if payload["suspected"]:
                payload["llm"]["ok"] = True
            elif not payload["llm"]["dry_run"]:
                payload["llm"]["ok"] = True
            payload["llm"]["count"] = len(payload["suspected"])
        except Exception as exc:  # 模型这一层失败不影响静态结论
            payload["llm_note"] = "模型研判失败：%s" % exc
            payload["llm"]["error"] = str(exc)
    return payload


class Handler(BaseHTTPRequestHandler):
    token = ""
    server_version = "xss-taint-scanner"

    def log_message(self, fmt, *args):  # 安静一点，别把每次请求都打到 stderr
        if "--verbose" in sys.argv:
            sys.stderr.write("%s\n" % (fmt % args))

    # ---------- 校验 ----------
    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        host = self.headers.get("Host", "")
        return origin in ("http://%s" % host, "https://%s" % host)

    def _token_ok(self) -> bool:
        supplied = self.headers.get("X-Token") or ""
        return bool(supplied) and secrets.compare_digest(supplied, self.token)

    # ---------- 响应 ----------
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _text(self, code: int, text: str) -> None:
        self._send(code, text.encode("utf-8"), "text/plain; charset=utf-8")

    # ---------- 路由 ----------
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path not in ("/", "/index.html"):
            return self._text(404, "没有这个地址")
        if not secrets.compare_digest(
                (parse_qs_token(parsed.query) or ""), self.token):
            return self._text(403, "缺少或错误的 token，请重新启动程序后使用它给出的地址")
        self._send(200, page_bytes(), "text/html; charset=utf-8")

    def do_POST(self):
        if urlparse(self.path).path != "/api/scan":
            return self._text(404, "没有这个地址")
        if not self._same_origin():
            return self._text(403, "跨站请求已拒绝")
        if not self._token_ok():
            return self._text(403, "缺少或错误的 token")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._text(400, "Content-Length 非法")
        if length <= 0 or length > MAX_UPLOAD_BYTES * 2:
            return self._text(413, "请求体过大")

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._text(400, "请求体不是合法 JSON")

        mode = payload.get("mode")
        use_llm = bool(payload.get("use_llm"))
        api_key = payload.get("api_key") or ""
        if not isinstance(api_key, str) or len(api_key) > 200:
            return self._json(400, {"error": "API Key 格式不正确"})
        api_key = api_key.strip()
        try:
            if mode == "url":
                url = str(payload.get("url") or "").strip()
                if not url:
                    return self._json(400, {"error": "网址为空"})
                html, note = fetch_page(url)
                result = scan_html(html, url, use_llm, api_key)
                result["fetch_note"] = note
                return self._json(200, result)
            if mode == "html":
                html = str(payload.get("html") or "")
                if len(html.encode("utf-8")) > MAX_UPLOAD_BYTES:
                    return self._json(413, {"error": "页面超过 2 MB，请先精简或只贴可疑片段"})
                return self._json(200, scan_html(html, str(payload.get("name") or "拖入的页面"), use_llm, api_key))
            return self._json(400, {"error": "未知的 mode"})
        except FetchError as exc:
            return self._json(400, {"error": str(exc)})


def parse_qs_token(query: str) -> str:
    for pair in query.split("&"):
        if pair.startswith("t="):
            return pair[2:]
    return ""


def _write_addr_file(url: str) -> None:
    path = os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "界面地址.txt")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(url + "\n")
    except OSError:
        pass


def _announce(url: str) -> None:
    # 打包成 exe 后没有控制台：sys.stdout 是 None，print() 会直接抛 AttributeError 并让进程退出，
    # 所以先落文件，别指望终端
    if getattr(sys, "frozen", False):
        _write_addr_file(url)
        return
    print("界面地址：%s" % url)
    print("按 Ctrl+C 退出。")


def _open_browser(url: str) -> None:
    try:
        if webbrowser.open(url):
            return
    except Exception:
        pass
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0, "浏览器没有自动打开，请手动访问：\n\n%s" % url, "XSS 风险扫描器", 0x40)
        except Exception:
            pass


def serve(port: int = 0, open_browser: bool = True) -> ThreadingHTTPServer:
    page_bytes()  # 页面文件缺失时立刻报错，而不是等浏览器打开才 500
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    Handler.token = secrets.token_urlsafe(18)
    url = "http://127.0.0.1:%d/?t=%s" % (httpd.server_address[1], Handler.token)
    _announce(url)
    if open_browser:
        threading.Timer(0.4, lambda: _open_browser(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return httpd