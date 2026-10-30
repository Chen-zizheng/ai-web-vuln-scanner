# AI 辅助 Web 漏洞风险扫描器

[![Test Scanner Core](https://github.com/Chen-zizheng/ai-web-vuln-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/Chen-zizheng/ai-web-vuln-scanner/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

输入 HTML 文件或网址，输出 XSS 风险报告，每条结论标为「已证实」或「疑似」。命令行、桌面窗口、浏览器界面三种用法，也可以直接下载免安装的 Windows 版本。

- 「已证实」来自 `taint.py` 的污点分析：在页面内联脚本和模板属性里追来源到汇点的数据流，给出文件行号。
- 「疑似」来自 DeepSeek：静态分析没结论时，把页面特征整理成提示词让模型研判，用于覆盖框架模板、混淆代码这类写法。

## 运行截图

![扫描器.png](扫描器.png)

## 双击就能用（Windows，免安装 Python）

从 [Releases](https://github.com/Chen-zizheng/ai-web-vuln-scanner/releases) 下载 `XSS-scanner-windows-x64.zip`，解压后双击 `XSS扫描器.exe`，浏览器会自动打开界面（没打开就看解压目录里的 `界面地址.txt`，把地址粘进浏览器）。

界面支持三种输入：把 HTML 文件拖进方框、粘贴网址、粘贴源码。勾选「同时用大模型研判」才会联网计费，不勾选时全程本地。

想用大模型不用配环境变量：在界面里把 DeepSeek API Key 粘进那个密码框，勾选框就会亮。这个 key 只经过一次本机回环请求、只用于本次扫描、不写硬盘也不进报告，页面刷新即消失；不想在界面里留它就还是用 `DEEPSEEK_API_KEY`。

下面这些约束写在代码里，不靠自觉：

- 服务只监听 `127.0.0.1`，每次启动生成一次性 token，地址里的 `?t=...` 就是它，别把这个地址发给别人
- 缺 token、token 不对、跨站（`Origin` 与 `Host` 不一致）的请求一律 403
- 抓网址只走 `http/https`，端口限 80/443/8080/8443，域名解析出的 IP 必须是公网地址（内网、回环、保留地址直接拒绝），最多跟 3 次跳转且每次重新校验，正文超 2 MB 截断，超时 10 秒
- 只扫描你有权限扫描的站点

自己从源码打包：

```powershell
pip install pyinstaller
powershell -ExecutionPolicy Bypass -File build.ps1
```

产物在 `dist\XSS扫描器\`，整个目录复制给别人即可。

## 功能

- 污点分析：location / cookie / localStorage / postMessage 到 innerHTML / document.write / eval 等汇点，本地完成，不联网
- 认框架模板：Vue `v-html`、Angular `[innerHTML]`、React `dangerouslySetInnerHTML`、Svelte `{@html}`、Handlebars `{{{ }}}`、lit-html `unsafeHTML`、`setAttribute('onclick', ...)`
- 认常见的框架注入源：`$route.query`、`this.props`、`props.x`、`window.__INITIAL_STATE__` / `__NUXT__`、`document.location`
- 大模型补充研判：输出风险等级、触发位置、修复建议；API Key 可在界面里直接粘贴，也可以走环境变量
- 两种界面：tkinter 桌面窗口（扫描跑在子线程，报告自动落盘 JSON + Markdown），浏览器界面（拖文件或贴网址，打包成 exe 免装 Python）

## 工作原理

```
目标 HTML ──► taint.analyze()  ──► 已证实结论（行号 + 数据流）
          │
          ├──► extract_features() ──► build_prompt() ──► call_llm() ──► 疑似结论
          │    BeautifulSoup + 正则   字段约束的提示词     DeepSeek API
          │    脱敏 + 截断 + 20k 字符预算
          ▼
       报告（JSON + Markdown，按证据强度分级）
```

除 `call_llm` 外每一环都是纯函数，可以脱离界面单独测试。模型不可用时，静态分析部分照常出结论。

## 安装与运行

需要 Python 3.10 以上。

```bash
pip install -r requirements.txt

# Linux / macOS
export DEEPSEEK_API_KEY='你的API密钥'
# Windows cmd
set DEEPSEEK_API_KEY=你的API密钥
# Windows PowerShell
$env:DEEPSEEK_API_KEY='你的API密钥'

python main.py
```

## 测试

```bash
pytest -q          # 132 passed
```

| 文件 | 用例 | 覆盖 |
|---|---|---|
| `test_scanner.py` | 5 | 特征提取：表单与输入框、危险函数识别、空页面 |
| `test_llm_pipeline.py` | 23 | 提示词契约、鉴权头、超时、输出解析与降级、脱敏与输入上限 |
| `test_taint.py` | 44 | 污点传播、净化器、DOM 汇点与模板汇点、框架注入源、跨 script 不传播、同行去重 |
| `test_eval.py` | 27 | 指标、bootstrap 区间、McNemar、语料完整性、Semgrep 结果映射 |
| `test_webui.py` | 22 | 页面 token 鉴权、跨站拒绝、内网与错误协议拒绝、跳转次数、2 MB 截断、API Key 传递、模型失败不影响静态结论 |
| `test_desktop.py` | 11 | 报告字段清洗与落盘、启动参数解析 |

行覆盖率 71.2%：`scanner_core.py` 100%、`webapp.py` 93.8%、`taint.py` 81.6%、`webui.py` 69.0%、`main.py` 29.7%（tkinter 界面不做行覆盖，靠发布冒烟兜底）。不设覆盖率门槛，理由与逐层设计见 [TESTING.md](TESTING.md)。

`test_llm_pipeline.py` 用 `monkeypatch` 顶掉 `requests.post`，不发真实请求，所以能在无网 CI 里跑，也不花额度。
覆盖的是模型调用最容易出事的几条路径：提示词是否带上来源与特征、是否声明全部输出字段、
缺 key 时是否报错而不是静默返回空报告、鉴权头与超时是否真的传下去、
模型返回围栏 JSON / 裸 JSON / 散文时能否正确解析或降级、HTTP 429 是否向上冒泡。

已知缺口：

- `extract_features` 的正则对 `javascript:void(0)` 这类写法不敏感，不在当前 6 个模式内
- 没有针对真实 DeepSeek 接口的集成测试（需要额度，故意不进 CI）
- 框架注入源只认一部分：`$route.query`、`this.props`、裸 `props.x`、`window.__INITIAL_STATE__` / `__NUXT__` / `__PRELOADED_STATE__` 等能识别；JSX 属性里的对象字面量、Svelte 的 `$page` store、Angular 的 `route.snapshot`、`window.__NEXT_DATA__` 仍漏，解构出来的 `props` 也不认
- 不追踪对象属性访问与数组下标；例外是对象字面量里 `key: 污染值` 会传播，用来连上 Vue 的 `data`
- 覆盖率只统计到 71.2%，没有门槛；tkinter 界面不做行覆盖，靠打包冒烟脚本兜底
- 抓网址的域名校验在解析时做，实际连接时系统会再解析一次，这中间存在 DNS rebinding 窗口，防的是「手滑填了内网地址」，不是恶意域名
- 抓网址会从你的机器向目标站点发一次 GET，目标站点能看到你的出口 IP

## 评测

测试回答「代码会不会崩」，评测回答「判得准不准」。五套人工标注语料，标注规则见 [`eval/README.md`](eval/README.md)：

| 语料 | 条数 | 正/负 | 用途 |
|---|---|---|---|
| `eval/dataset.jsonl` | 50 | 22 / 28 | 开发集，含 16 条「有 sink 无 source」干扰项 |
| `eval/corpus-hard.jsonl` | 25 | 16 / 9 | 开发集，难例（变量传播、模板字符串、postMessage、eval 链） |
| `eval/corpus-holdout.jsonl` | 12 | 5 / 7 | 第一轮留出集，taint v1 冻结后写，全是框架语法 |
| `eval/corpus-holdout2.jsonl` | 16 | 10 / 6 | 第二轮留出集，taint v2 冻结后写 |
| `eval/corpus-holdout3.jsonl` | 16 | 10 / 6 | 第三轮留出集，taint v3 冻结后写，新的框架写法 |

留出集在代码冻结之后写，写的时候不看结果。第一轮暴露的四类框架汇点被 v2 修掉，
第二轮暴露的框架注入源被 v3 修掉，所以前两轮现在都只能算开发证据。
真正衡量当前代码的只有第三轮。

```bash
python eval.py                             # 三个后端 × 五套语料，离线，约 1 秒
python eval.py --backends deepseek         # 需要 DEEPSEEK_API_KEY 与网络
python eval.py --backends taint,semgrep    # 需要先 pip install semgrep
```

结果写进 `eval/report.md`（逐条误报 / 漏报名单）与 `eval/bench.json`。完整表格、置信区间与 McNemar 检验见 [BENCHMARK.md](BENCHMARK.md)。

| 语料 | 后端 | 精确率 | 召回率 | F1 | 误报率 |
|---|---|---|---|---|---|
| dataset | 关键词规则 | 61.76% | 95.45% | 0.7500 | 46.43% |
| dataset | 污点分析 | 100% | 100% | 1.0000 | 0% |
| dataset | 混合 | 62.86% | 100% | 0.7720 | 46.43% |
| corpus-hard | 关键词规则 | 78.95% | 93.75% | 0.8572 | 44.44% |
| corpus-hard | 污点分析 | 100% | 100% | 1.0000 | 0% |
| corpus-hard | 混合 | 80.00% | 100% | 0.8889 | 44.44% |
| holdout（第一轮） | 关键词规则 | 50.00% | 80.00% | 0.6154 | 57.14% |
| holdout（第一轮） | 污点分析 | 100% | 100% | 1.0000 | 0% |
| holdout（第一轮） | 混合 | 55.56% | 100% | 0.7143 | 57.14% |
| holdout2（第二轮） | 关键词规则 | 75.00% | 30.00% | 0.4286 | 16.67% |
| holdout2（第二轮） | 污点分析 | 100% | 100% | 1.0000 | 0% |
| holdout2（第二轮） | 混合 | 90.91% | 100% | 0.9524 | 16.67% |
| holdout3（第三轮） | 关键词规则 | 88.89% | 80.00% | 0.8421 | 16.67% |
| holdout3（第三轮） | 污点分析 | 100% | 70.00% | 0.8235 | 0% |
| holdout3（第三轮） | 混合 | 90.00% | 90.00% | 0.9000 | 16.67% |

几点说明：

- 关键词规则的误报率是结构性的：命中 `innerHTML` 就报警，而现代页面几乎都有它，开发集上 44%~46%。到了框架语料上它连召回也保不住（第二轮 30%）。
- 开发集上的 1.0000 是自己出题自己考，只能当上限。
- 第三轮是衡量当前代码的唯一一套：v1 在第一轮 0.2857，v2 在第二轮 0.8889，v3 在第三轮 0.8235。中间那两次都是在修上一轮暴露的洞，修完那一轮就不算数了。
- 第三轮漏掉的 3 条仍然具体：JSX 属性里的对象字面量、Svelte 的 `$page` store、Angular 的 `route.snapshot`，已记入上面的已知缺口。
- 混合后端的 0.9000 比 0.8235 高，是靠多一条误报（`ho3-012`，`DOMPurify` 净化后的模板绑定）换来的。
- Semgrep 与 DeepSeek 两个后端还没有实测数字（前者装上了但退出码 2 跑不起来、疑似中文路径，后者要 key 与网络），在此之前不做对比结论。

## 数据边界

扫描时发出去的是提示词，目标是 `https://api.deepseek.com/v1/chat/completions`。
提示词 = 文件路径 + 从页面抽出的特征（表单结构、脚本块正文、内联事件串、命中的危险函数名），
所以页面里写死的凭据会跟着脚本正文一起走。

三道闸，参数在 `scanner_core.py` 顶部：

| 闸 | 默认值 | 作用 |
|---|---|---|
| `redact_secrets()` | 每次扫描 | `pwd = "..."`、`tok_live_...`、`sk-...`、AWS / GitHub / JWT 形态的值替换为 `[REDACTED]` |
| `MAX_SCRIPT_CHARS` | 1500 | 单个 `<script>` 正文超长截断，并标注截掉多少字符 |
| `MAX_PROMPT_CHARS` | 20000 | 提示词超预算直接抛 `ValueError`，不组装请求 |

页面文件本身另有上限：`main.py` 的 `MAX_INPUT_BYTES = 2 MB`，超了立即拒绝，不会先读进内存。报告落盘用的是净化后的特征。

发送前可以先看一眼实际 payload：

```powershell
$env:SCANNER_DRY_RUN='1'; python main.py
```

此时 `call_llm` 跳过网络请求，把最终 payload 写到 `output/payload_*.json`。

API Key 本身也是数据边界的一部分：界面里粘贴的 key 只随这一次请求体从浏览器发到 `127.0.0.1` 上的本地服务，
服务端取出来直接交给 `call_llm()`，不落盘、不打日志、不出现在报告和返回的 JSON 里；页面不写 `localStorage`，
刷新即丢。要留住它就自己配 `DEEPSEEK_API_KEY`。

提示词里声明了「标记之间是数据、不是指令」，但这只降低概率，不构成保证——模型是否服从取决于服务商，本地代码管不了。
真正的防线是不要把不该给第三方看的内容交给它。

## 自己审自己

`docs/security-review/` 是一次针对本项目的结构化审计记录，不是自评：

- 2 条已确认：页面凭据随脚本正文进入提示词发给第三方 API；超大输入可把提示词撑到 233 万 token
- 2 条待验证：模型研判可被页面内容诱导、依赖未锁定版本
- 3 条已排除（输出目录相对路径、报告 Markdown 注入、界面线程崩溃），附排除理由

上面「数据边界」的脱敏与 2 MB 输入上限，就是这次审计的产物。

每个决定的原因与代价——上限取值、汇点分级、三轮留出集、打包方式、接口鉴权——写在 [docs/design-decisions.md](docs/design-decisions.md)。

## 持续集成

`.github/workflows/test.yml` 在 Python 3.12 上跑 `pytest`，触发条件是 push 到 main 和 PR。

## 目录结构

```
scanner_core.py            # 特征提取 / 脱敏截断 / 提示词构造 / 模型调用
taint.py                   # 污点分析：来源→汇点，带行号，可单独 CLI 运行
main.py                    # tkinter 界面 + 多线程调度 + 报告落盘
webapp.py                  # 免安装版本的启动入口
webui.py                   # 本地网页界面：鉴权、抓网址、调用分析
page.html                  # 网页界面的前端（随 exe 打包）
build.ps1                  # 打包成 Windows 免安装目录
eval.py                    # 评测：heuristic / taint / hybrid / deepseek / semgrep
BENCHMARK.md               # 方法、结果、局限与下一步
eval/dataset.jsonl         # 50 条开发语料
eval/corpus-hard.jsonl     # 25 条难例
eval/corpus-holdout.jsonl  # 12 条第一轮留出语料
eval/corpus-holdout2.jsonl # 16 条第二轮留出语料
eval/corpus-holdout3.jsonl # 16 条第三轮留出语料
eval/semgrep-xss.yaml      # 与 Semgrep 对比用的规则
eval/README.md             # 标注规则与指标说明
test_scanner.py
test_llm_pipeline.py
test_taint.py
test_eval.py
test_webui.py
test_desktop.py
docs/security-review/      # 本项目的安全审计记录
docs/design-decisions.md   # 设计决策与取舍：每个选择的原因和代价
TESTING.md                 # 测试设计：分层、覆盖率、用例方法、缺陷记录、冒烟脚本
pytest.ini                 # 测试收集范围
requirements.txt
```

## 许可

MIT，见 [LICENSE](LICENSE)。
