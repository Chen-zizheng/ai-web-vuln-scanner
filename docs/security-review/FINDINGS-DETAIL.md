# 已确认问题详情

环境：Windows，python 3.13.13，bs4 4.15.0，requests 2.33.1。探针在分析者本机运行，不联网；请求体由替换后的假 transport 记录。复现入口：

    python D:\deepharnes\audit-demo\avs-probes\probe1.py

产物落在 agents/hunter-a/artifacts/ 下，本题引用 egress-request-body.json 与 probe-results.json。

---

## avs-credential-egress-to-third-party（medium）

### 有序源码路径与证据

1. main.py:104 — start_scan 只做 Path(path).is_file() 校验。
2. main.py:109 — threading.Thread(target=self._scan) 把扫描移出 UI 线程。
3. main.py:114 — html = Path(path).read_text(encoding="utf-8")：整文件进内存，无内容限制。
4. scanner_core.py:13-25 — 表单的 action / method / 每个 input 的 name 与 type。
5. scanner_core.py:27 — script_blocks = [s.get_text() for s in soup.find_all("script") if s.get_text().strip()]：脚本正文逐字保留。
6. scanner_core.py:28 — 内联事件串（on\\w+="..."）前 200 字符。
7. scanner_core.py:37 — script_blocks[:5]：只限块数，不限单块长度。
8. scanner_core.py:43-49 — f-string 把 json.dumps(features, ensure_ascii=False, indent=2) 直接嵌进指令正文。
9. main.py:123 — build_prompt(path, features)：本地路径作为"来源"一并进入 prompt。
10. scanner_core.py:64-69 — requests.post(API_URL, headers={Authorization: Bearer <key>}, json={messages:[{role:"user", content: prompt}]}, timeout=60)。

### 假想主体与资源

- 低信任主体：被扫描页面的作者，或把页面转发给分析者的人。
- 受影响主体：分析者本人（工具的合法使用者）。
- 受影响资源：页面里的内联凭据、令牌、内部主机名与路径；以及"本地工具不会把文件内容送出去"这一预期。

### 原生输入与有界步骤

输入（除凭据外无任何特殊性）：

    <html><body>
      <h1>internal admin</h1>
      <script>const DB_PASSWORD = "hunter2-production-credential";
              const API_TOKEN = "tok_live_9f8e7d6c5b4a";</script>
    </body></html>

步骤：

1. os.environ["DEEPSEEK_API_KEY"] = "sk-dummy-not-a-real-key"（只为通过 scanner_core.py:62 的存在性检查）。
2. 用本进程内定义的假 transport 替换 requests.post：记录 url、headers、body，返回一个固定的 chat-completion 结构，不发任何网络请求。
3. features = scanner_core.extract_features(html)；prompt = scanner_core.build_prompt("internal-admin.html", features)；scanner_core.call_llm(prompt)。
4. 把记录的 body 写到 agents/hunter-a/artifacts/egress-request-body.json。

### 观测输出与被证明的不变量

- 请求体 920 字节，url 为 https://api.deepseek.com/v1/chat/completions，Authorization 头存在，timeout=60。
- body 中逐字出现 hunter2-production-credential、tok_live_9f8e7d6c5b4a、internal-admin.html。
- 被推翻的不变量：本地扫描不应把页面正文（含凭据）无过滤地交给第三方，且分析者应当能看到自己发出了什么。

### 条件与遏制

- 需要页面里存在脚本块、表单字段名或内联事件其中之一，且其中含敏感形态的值。
- 需要 DEEPSEEK_API_KEY 已设置；未设置时在 scanner_core.py:62-63 直接抛异常，请求不会组装。
- 遏制：只在隔离的 key 与隔离的账号下使用；不要把内部页面、含内联令牌的导出页交给它扫。

### 源码级修复与回归用例

最小修复（三选一，推荐同时做前两项）：

1. 只发结构性信号：把 script_blocks 的内容替换为长度、出现的危险模式类别，不发原文。
2. 若确实要发原文，加 SECRET_RE 脱敏，并在发送前把 payload 写到本地日志或要求 --confirm。
3. 加 --dry-run，只打印 payload 不发送。

回归用例：对含上述 payload 的页面跑 call_llm（假 transport），断言记录的 body 中不出现 hunter2-production-credential 与 tok_live_9f8e7d6c5b4a，且报告目录里有一份 payload 记录可供核对。

---

## avs-unbounded-scan-input（low）

### 源码路径

1. main.py:104 — 唯一输入校验是 is_file。
2. main.py:114 — read_text 无 stat、无大小上限。
3. scanner_core.py:37 — script_blocks[:5] 限块数。
4. scanner_core.py:49 — 按全长拼装 prompt，无预算检查。

### 复现与观测

构造页面："<html><body><script>" + "A" * (8 * 1024 * 1024) + "</script></body></html>"，调用 extract_features 与 build_prompt 并计时。

- extract_features：0.77 秒
- build_prompt：0.027 秒
- prompt 长度：9,321,064 字符（约 2,330,266 token）
- 最长单块 script：8,388,603 字符

随后请求在任何上下文窗口下都无法被服务，用户看到的是原始异常而不是"文件过大"。

### 不变量

工具的输入规模应当有确定上限，超限时明确拒绝并说明原因，而不是组装一个注定失败的请求。

### 修复与回归

加 MAX_INPUT_BYTES 闸门与 MAX_SCRIPT_CHARS 截断，并在 build_prompt 末尾检查 len(prompt) 是否超过 MAX_PROMPT_CHARS。回归用例：8 MB 页面应抛出可读的 ValueError，且不产生任何网络调用。
