# AI 辅助 Web 漏洞风险扫描器

基于大模型的本地 Web 安全分析工具：解析 HTML 提取表单、内联事件、危险 JS 调用等风险特征，
调用 DeepSeek API 进行 XSS / SQL 注入风险分析，输出 JSON + Markdown 双格式报告。

## 运行截图
![扫描器.png](扫描器.png)

## 功能
- BeautifulSoup + 正则提取 4 类风险特征（表单 / 脚本块 / 内联事件 / 危险函数调用）
- 大模型结构化风险分析（风险等级 / 触发位置 / 修复建议）
- GUI 界面 + 多线程异步扫描，报告自动落盘 JSON + Markdown

## 工作原理

```
目标 HTML ──► extract_features()  ──► build_prompt() ──► call_llm() ──► 报告
              BeautifulSoup + 正则    约束输出字段的提示词    DeepSeek API    JSON + Markdown
              截断到 5/10/20 条防爆token
```

三个环节都是纯函数（`call_llm` 除外），所以可以脱离 GUI 单独测试。

## 测试

```bash
pip install -r requirements.txt pytest
pytest -q          # 16 passed
```

**16 个用例，分两组：**

| 文件 | 用例数 | 覆盖对象 |
|---|---|---|
| `test_scanner.py` | 3 | `extract_features`：表单与输入框提取、`innerHTML` 等危险函数识别、空页面不抛异常 |
| `test_llm_pipeline.py` | 13 | `build_prompt` + `call_llm`：提示词契约、鉴权头、超时、输出解析与降级 |

`test_llm_pipeline.py` 用 `monkeypatch` 替换 `requests.post`，**不发真实网络请求**，
因此可以跑在 CI 的无网环境里，也不消耗 API 额度。它覆盖的是模型调用最容易出事的几条路径：

- 提示词是否带上了来源与序列化后的特征（少一个模型就是「盲判」）
- 提示词是否声明了全部 5 个输出字段（字段名是下游解析的契约）
- 缺少 `DEEPSEEK_API_KEY` 时是否明确报错，而不是静默返回空报告
- `Authorization` 头与 60s 超时是否真的传下去了
- 模型返回 ` ```json ` 围栏 / 裸 ` ``` ` 围栏 / 纯 JSON 时能否正确解析
- 模型返回散文时是否降级为 `{"raw_analysis": ...}` 而不是崩溃
- HTTP 429 等错误是否向上冒泡（避免悄无声息地产出一份「零风险」报告）

**明确的未覆盖项（已知缺口）：**

- `extract_features` 的正则对 `javascript:void(0)` 这类写法不敏感——它不在当前 6 个模式内
- 没有针对真实 DeepSeek 接口的集成测试（需要额度，故意不放进 CI）
- 没有覆盖率门槛，也没有 UI 层测试

## 如何运行

1. 安装依赖

```bash
pip install -r requirements.txt
```

2. 配置环境变量

```bash
# Linux / macOS
export DEEPSEEK_API_KEY='你的API密钥'
# Windows (cmd)
set DEEPSEEK_API_KEY=你的API密钥
# Windows (PowerShell)
$env:DEEPSEEK_API_KEY='你的API密钥'
```

3. 运行

```bash
python main.py
```

## 持续集成

`.github/workflows/test.yml`：每次 push 到 main 与每个 PR，都会在 Python 3.9 上跑一遍 `pytest`。
CI 失败过的历史提交保留在 Actions 记录里，最近一次为通过状态。

## 目录结构

```
scanner_core.py        # 特征提取 / 提示词构造 / 模型调用
main.py                # tkinter GUI + 多线程调度 + 报告落盘
test_scanner.py        # 特征提取的单元测试
test_llm_pipeline.py   # 提示词与模型输出解析的单元测试
requirements.txt
```
