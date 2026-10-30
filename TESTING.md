# 测试设计说明

这份文档回答三个问题：测了什么、怎么设计的、凭什么说测够了。
数字都是本机实测（Windows 11 / Python 3.13 / pytest 9.1.1），命令在第 7 节，可复跑。

## 1. 四层，各证明一件事

| 层 | 对象 | 证明什么 | 规模 |
|---|---|---|---|
| 单元 | `scanner_core` / `taint` / `eval` | 每个判断规则在边界处是否正确 | 76 例 |
| 接口 | `webui` 的 HTTP 处理 | 鉴权、限额、异常路径是否按约定拒绝 | 22 例 |
| 桌面 | `main` 的报告生成、`webapp` 的参数解析 | 报告不被模型输出改写、启动参数不被拼坏 | 11 例（本机） |
| 数据集回归 | 五套语料 × 五个后端 | 检测能力有没有退化，漏报多了哪几条 | 15 行指标表 |
| 发布冒烟 | 打包后的 exe | 别人下载下来双击能不能用 | 手动脚本，见第 6 节 |

前四层在 `pytest` 里（`136 passed`），第五层不在自动化里——打包产物必须有人真的双击一次，
这一层抓到过一个单元测试永远抓不到的 bug（见第 5 节 D-3）。

## 2. 覆盖率（实测，不美化）

```
scanner_core.py    95 语句    0 未覆盖   100.0%
webapp.py          16 语句    1 未覆盖    93.8%
taint.py          414 语句   76 未覆盖    81.6%
webui.py          242 语句   75 未覆盖    69.0%
main.py           165 语句  116 未覆盖    29.7%
合计              932 语句  268 未覆盖    71.2%
```

怎么读这几个数字：

- `main.py` 只有 29.7%，因为它是 Tk 界面。界面层不做行覆盖——在 CI 里拉起窗口既不稳也没意义。
  它的业务逻辑已经抽到 `webui.scan_html()` 与 `scanner_core`（100%），界面只剩搬运。
  这层用第 6 节的冒烟脚本兜底：真启动、真点、真出结论。
- `webui.py` 缺的 75 行集中在抓网址的异常分支（跳转超限、非 HTML、空壳页面）与浏览器打开失败，
  这些分支已有用例覆盖主要路径，剩余是操作系统相关的边角。
- `eval/` 与 `eval.py` 不计入：评测脚本的正确性由它输出的指标表验证（跑出离谱数字即失败），
  行覆盖对这类脚本意义不大。

**没有设覆盖率门槛。** 一个 71% 但每条用例都有理由的仓库，比一个为了让数字变绿而堆断言的仓库更可信。

## 3. 用例怎么设计的

| 方法 | 在这个仓库里的落点 |
|---|---|
| 等价类划分 | 语料按「有 sink 有 source / 有 sink 无 source / 净化后 / 框架语法」分类，每类都有正负样本 |
| 边界值 | 2 MB 输入（正好 2 MB / 超 1 字节）、单脚本 1500 字符、提示词 20000 字符、跳转 3 次、key 200 字符、POST 4 MB |
| 判定表 | `webui` 的请求校验：Origin 有无 × token 对错 × Content-Length 是否合法 × JSON 是否可解析 |
| 状态迁移 | 扫描流程：无 key → 勾选禁用 → 填 key → 可勾选 → 勾选后调用失败 → 静态结论仍在 |
| 错误推测 | 模型返回围栏 JSON / 裸 JSON / 散文 / 空对象 / 429；报告字段里塞换行试图伪造标题 |
| 组合 | 五个后端 × 五套语料，指标表就是组合测试的结果 |
| 回归 | 每轮语料冻结后不再改；发现漏报 → 修规则 → 用**新一轮**语料验证（旧轮次降级为开发证据） |

## 4. 语料即测试数据

`eval/*.jsonl` 每条形如：

```json
{"id": "ho3-001", "html": "<div v-html=\"$route.params.slug\"></div>",
 "label": {"has_xss_risk": true, "risk_level": "HIGH"}, "note": "Vue v-html 绑定路由参数"}
```

- 标注规则写在 [eval/README.md](eval/README.md)：什么算 XSS 风险、什么算净化、如何标记风险等级。
- 每套语料有用途，不混用：`dataset` 开发、`corpus-hard` 难例、`holdout/2/3` 三轮留出。
- **留出集的规矩**：写完之后冻结；改代码不能回头改语料；哪一轮被用来指导修复，哪一轮就不再是留出集。
  所以现在只有第三轮（16 条）算数，前两轮降级为开发证据。这条规矩是整套评测可信的前提。

## 5. 缺陷记录

按「现象 → 根因 → 修复 → 回归用例」记录，比"我修了个 bug"更能说明测试怎么闭环。

| ID | 严重级 | 现象 | 根因 | 修复 | 回归用例 |
|---|---|---|---|---|---|
| D-1 | 中 | 页面里写死的密码跟着脚本正文进了第三方提示词 | `prepare_features` 只截断不脱敏 | `redact_secrets()` + 三道闸 | `tests/test_llm_pipeline.py` 脱敏两组、`prepare_features` 不改入参 |
| D-2 | 低 | 8 MB 页面能撑出 233 万 token 的提示词 | 输入与提示词都没有上限 | `MAX_INPUT_BYTES=2MB`、`MAX_PROMPT_CHARS=20000` | 超大 HTML 返回 413、超预算抛 `ValueError` |
| D-3 | 高 | 打包后的 exe 双击立即退出，什么都不显示 | `--noconsole` 下 `sys.stdout` 是 `None`，`print` 抛异常 | 改为写同目录 `界面地址.txt` | 第 6 节冒烟脚本：真启动、取地址、出页面、POST 扫描 |
| D-4 | 中 | 目标站点返回 403 或纯前端空壳时，工具给出「0 条」的假结论 | 只判 `status_code >= 400`，未处理空正文 | `_status_hint()` 按状态码给处置建议；空正文直接拒绝 | `test_fetch_403_suggests_saving_page`、`test_fetch_empty_body_rejected` |
| D-5 | 低 | 界面粘贴超长 key 时行为未定义 | 未校验请求体字段 | 非字符串或超 200 字符返回 400 | `test_key_too_long_rejected` |
| D-6 | 高 | `DOMPurify.sanitize(a) + location.hash` 这类「净化函数 + 真实污点」被判安全，真实绕过漏报 | `_taint_of` 只要区间里出现净化函数名就整段放行 | `_sanitized_spans()` 只豁免净化函数自己的实参 | `test_sanitizer_only_covers_its_own_argument`、`test_sanitizer_does_not_mask_other_taint_in_eval`、`test_expression_with_only_sanitizers_is_quiet` |
| D-7 | 中 | 网页界面的代码框永远是空的 | `_finding()` 不产出 `snippet` 字段，前端却在渲染它 | 补 `snippet` | `test_finding_carries_snippet_for_the_ui` |

D-1、D-2 来自 `docs/security-review/` 的审计结论，D-3、D-4、D-5 来自发布前的实际使用，D-6、D-7 来自评测时对漏报的逐条复核。

## 6. 发布冒烟（不进 CI）

打包后必须手工跑一遍，因为单元测试碰不到「窗口版没有 stdout」这类问题：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
cmd /c start "" "dist\XSS扫描器\XSS扫描器.exe" --no-browser --port 8943
Start-Sleep -Seconds 5
Get-Content "dist\XSS扫描器\界面地址.txt"          # 应当出现 http://127.0.0.1:8943/?t=...
```

拿到地址后：页面返回 200、页面里有 `id="key"`、POST 一个含 `location.hash → innerHTML` 的片段能出结论、
进程保持运行。四项都通过才算发布成功。

## 7. 怎么跑

```bash
pytest -q                                        # 136 passed，约 8 秒
pip install pytest-cov coverage
pytest -q --cov=scanner_core --cov=taint --cov=webui --cov=main --cov=webapp --cov-report=term-missing
```

CI 在 Python 3.12 上跑同一套用例，每次 push 到 main 与每个 PR 都会执行。

CI 的 runner 不带 `_tkinter`，`tests/test_desktop.py` 会在那里整体跳过（121 passed + 11 skipped），
覆盖率也只统计四个不依赖 Tk 的模块。桌面层那 11 例的结论只在本地成立——这是它的局限，不是隐瞒。

## 8. 没测的东西，以及为什么

- **真实 DeepSeek 接口的集成测试**：要额度、要网络，且模型输出不稳定，不适合进 CI。靠 `SCANNER_DRY_RUN=1` 落盘 payload 人工核对。
- **tkinter 界面交互**：无头环境不稳，用打包冒烟兜底。
- **并发与性能**：本地单用户工具，没有并发场景；抓取有 10 秒超时与 2 MB 截断，但没有吞吐基线。
- **兼容性**：只在 Windows 11 + Python 3.13 与本机 CI（Ubuntu + 3.12）上验证过，没有覆盖更老的 Python 与其它发行版。
- **真实恶意站点**：抓网址功能只针对公开页面做过验证，没有对反爬/蜜罐站点做对抗测试。
