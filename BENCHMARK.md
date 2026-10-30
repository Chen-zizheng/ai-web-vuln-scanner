# 基准测试

这份文件回答三个问题：**规则法错在哪、污点分析值不值、大模型那层还要不要留**。
所有数字都能用一条命令重跑，语料与标注规则都在仓库里。

## 方法

五套语料，用途不同：

| 语料 | 条数 | 正/负 | 用途 |
|---|---|---|---|
| eval/dataset.jsonl | 50 | 22 / 28 | 开发集，覆盖常见写法，含 16 条「有 sink 无 source」干扰项 |
| eval/corpus-hard.jsonl | 25 | 16 / 9 | 开发集，覆盖难例（变量传播、模板字符串、postMessage、eval 链）与安全对照 |
| eval/corpus-holdout.jsonl | 12 | 5 / 7 | **第一轮留出集**：taint v1 冻结后新写，故意用框架语法 |
| eval/corpus-holdout2.jsonl | 16 | 10 / 6 | **第二轮留出集**：taint v2 冻结后新写，覆盖 Svelte / Handlebars / lit-html 与框架注入源 |
| eval/corpus-holdout3.jsonl | 16 | 10 / 6 | **第三轮留出集**：taint v3 冻结后新写，覆盖 vue-router / props / SSR state 与 JSX 写法 |

前两套是「边写代码边看」的开发集。留出集是一次性拉开的卷子，但**卷子只能用一次**：
第一轮暴露了 4 类框架汇点，v2 照着它修完；第二轮暴露了框架注入源，v3 照着它修完。
所以前两轮都已降级为开发证据，真正衡量当前代码的只有第三套。这张清单本身就是工作日志，
写清楚哪一轮被谁改过，比任何免责声明都有用。

五个后端：

| 后端 | 做什么 | 会不会联网 |
|---|---|---|
| heuristic | 命中危险函数关键词就报（旧规则基线） | 否 |
| taint | 本仓库的污点分析：来源→汇点连起来才报，带行号 | 否 |
| hybrid | taint 优先，没发现时退回 heuristic（标 suspected） | 否 |
| deepseek | 所有样本都直接交给大模型判定 | 是 |
| llm_union | taint 优先，静态分析没结论时才问大模型（省调用） | 是 |
| semgrep | 工业界静态分析器对照，未跑通，见下文 | 否 |

两个模型后端用的是同一条提示词（`scanner_core.build_prompt`），只判 XSS；下表数字来自 2026-10-30
把提示词收窄之后的全量重跑。

指标用精确率 P、召回率 R、F1、误报率 FPR、混淆矩阵；区间是 2000 次 bootstrap 重采样的
95% 分位；两个后端的差距用 McNemar 精确检验（只看「一个判对、另一个判错」的样本）。

## 结果

| 语料 | 后端 | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|---|
| dataset | heuristic | 61.76% | 95.45% | 0.7500 | 46.43% | 21/13/15/1 |
| dataset | taint | 100% | 100% | 1.0000 | 0% | 22/0/28/0 |
| dataset | hybrid | 62.86% | 100% | 0.7720 | 46.43% | 22/13/15/0 |
| dataset | deepseek | 95.65% | 100% | 0.9778 | 3.57% | 22/1/27/0 |
| dataset | llm_union | 91.67% | 100% | 0.9565 | 7.14% | 22/2/26/0 |
| corpus-hard | heuristic | 78.95% | 93.75% | 0.8572 | 44.44% | 15/4/5/1 |
| corpus-hard | taint | 100% | 100% | 1.0000 | 0% | 16/0/9/0 |
| corpus-hard | hybrid | 80.00% | 100% | 0.8889 | 44.44% | 16/4/5/0 |
| corpus-hard | deepseek | 100% | 93.75% | 0.9677 | 0% | 15/0/9/1 |
| corpus-hard | llm_union | 100% | 100% | 1.0000 | 0% | 16/0/9/0 |
| corpus-holdout | heuristic | 50.00% | 80.00% | 0.6154 | 57.14% | 4/4/3/1 |
| corpus-holdout | taint (v1 → v3) | 50.00% → 100% | 20.00% → 100% | 0.2857 → 1.0000 | 14.29% → 0% | v1 1/1/6/4，v3 5/0/7/0 |
| corpus-holdout | hybrid | 55.56% | 100% | 0.7143 | 57.14% | 5/4/3/0 |
| corpus-holdout | deepseek | 66.67% | 80.00% | 0.7273 | 28.57% | 4/2/5/1 |
| corpus-holdout | llm_union | 71.43% | 100% | 0.8333 | 28.57% | 5/2/5/0 |
| corpus-holdout2 | heuristic | 75.00% | 30.00% | 0.4286 | 16.67% | 3/1/5/7 |
| corpus-holdout2 | taint (v2 → v3) | 100% → 100% | 80.00% → 100% | 0.8889 → 1.0000 | 0% → 0% | v2 8/0/6/2，v3 10/0/6/0 |
| corpus-holdout2 | hybrid | 90.91% | 100% | 0.9524 | 16.67% | 10/1/5/0 |
| corpus-holdout2 | deepseek | 85.71% | 60.00% | 0.7059 | 16.67% | 6/1/5/4 |
| corpus-holdout2 | llm_union | 90.91% | 100% | 0.9524 | 16.67% | 10/1/5/0 |
| **corpus-holdout3** | heuristic | 88.89% | 80.00% | 0.8421 | 16.67% | 8/1/5/2 |
| **corpus-holdout3** | **taint v3** | **100%** | **70.00%** | **0.8235** | **0%** | 7/0/6/3 |
| **corpus-holdout3** | hybrid | 90.00% | 90.00% | 0.9000 | 16.67% | 9/1/5/1 |
| **corpus-holdout3** | **deepseek** | **100%** | 70.00% | 0.8235 | **0%** | 7/0/6/3 |
| **corpus-holdout3** | **llm_union** | **100%** | **90.00%** | **0.9474** | **0%** | 9/0/6/1 |

显著性（McNemar，双侧）：

| 对比 | 语料 | p 值 | 结论 |
|---|---|---|---|
| heuristic vs taint | dataset | 0.0001 | 差距显著 |
| taint vs hybrid | dataset | 0.0002 | 差距显著 |
| heuristic vs taint | corpus-hard | 0.0625 | 样本量不足以判定 |
| taint vs hybrid | corpus-hard | 0.1250 | 样本量不足以判定 |
| heuristic vs taint | corpus-holdout | 0.0625 | 样本量不足以判定 |
| heuristic vs taint | corpus-holdout2 | 0.0078 | 差距显著 |
| heuristic vs hybrid | corpus-holdout2 | 0.0156 | 差距显著 |
| taint vs hybrid | corpus-holdout2 | 1.0000 | 样本量不足以判定 |
| heuristic vs taint | corpus-holdout3 | 1.0000 | 样本量不足以判定 |
| heuristic vs hybrid | corpus-holdout3 | 1.0000 | 样本量不足以判定 |
| taint vs hybrid | corpus-holdout3 | 1.0000 | 样本量不足以判定 |
| hybrid vs llm_union | dataset | 0.0034 | 差距显著：模型对 12 条、关键词对 1 条 |
| hybrid vs llm_union | corpus-hard | 0.1250 | 样本量不足以判定 |
| hybrid vs llm_union | corpus-holdout | 0.5000 | 样本量不足以判定 |
| hybrid vs llm_union | corpus-holdout2 | 1.0000 | 样本量不足以判定 |
| hybrid vs llm_union | corpus-holdout3 | 1.0000 | 只差 1 条，样本量不足以判定 |
| heuristic vs llm_union | dataset | 0.0018 | 差距显著：模型对 13 条、关键词对 1 条 |
| heuristic vs llm_union | corpus-holdout2 | 0.0156 | 差距显著：模型对 7 条、关键词对 0 条 |
| taint vs llm_union | corpus-holdout3 | 0.5000 | 模型补对 2 条、判错 0 条 |

完整表格（含每个指标的置信区间与逐条误报/漏报名单）由 eval.py 自动写进 eval/report.md。

## 怎么读这张表

**1. 规则法的误报率是结构性的，不是调参能救的。**
它在两套开发集上的 FPR 都在 44% 以上：只要页面出现 innerHTML / eval 这类词就报警，
而现代前端页面几乎都有；到了第二轮留出集，召回直接掉到 30%——框架语法里根本没有这些关键词。

**2. 开发集上的 1.000 是上限，不是成绩。**
这两套语料和 taint.py 出自同一人之手：我写样本时知道它支持哪些语法，写代码时也对着样本改。
这正是自建语料的陷阱，所以必须看留出集。

**3. 第一轮留出集：0.2857 起步，四个缺口都很具体，v2 就是照着这张清单修的。**

| 漏报 | 写法 | 为什么漏 | v2 怎么补 |
|---|---|---|---|
| ho-001 | Vue `v-html` | 模板指令不是 DOM API | 新增模板层汇点表 |
| ho-002 | React `dangerouslySetInnerHTML` | 数据在对象字面量的 `__html` 字段 | 按 `key: expr` 取值再判污点 |
| ho-003 | Angular `[innerHTML]` | 编译期属性绑定 | 模板层正则 + 字符串里的模板字面量 |
| ho-005 | `setAttribute('onclick', ...)` | 事件处理器属性没建进汇点表 | 按属性名分级（on* / srcdoc / URL） |
| ho-011（误报） | `encodeURIComponent` 嵌在拼接里 | 净化判定只认整个表达式是调用 | 把 URL 编码加入净化白名单 |

修完 v2 在第一轮留出集上是 12/12，**但这个数字不算数**——它是照着这份错误清单修出来的。

**4. 第二轮留出集：v2 是 0.8889，漏的 2 条是「框架注入源」，不是汇点。**

| 漏报 | 写法 | 为什么漏 |
|---|---|---|
| ho2-009 | Vue `v-html="$route.query.q"` | `$route.query` 是 vue-router 注入的源，不在 DOM 来源表里 |
| ho2-010 | React `dangerouslySetInnerHTML={{__html:this.props.html}}` | `this.props` 是框架注入的源，静态分析看不见它从哪来 |

v2 把「汇点」这一类补完了，卡住召回的不再是汇点，而是"框架给的源"。v3 就是补这一层：
`$route.*`、`route.*`、`this.props`、裸 `props.x`、`window.__INITIAL_STATE__` / `__NUXT__` /
`__PRELOADED_STATE__` / `__INITIAL_DATA__` / `__APOLLO_STATE__`、`document.location` 现在都算来源。
补完之后第二轮是 10/10，**同样不算数**——它是照着这两条漏报修的。

**5. 第三轮留出集：污点分析 0.8235，加上模型兜底 0.9474——这是当前代码唯一算数的成绩。**

| 漏报 | 写法 | 为什么漏 |
|---|---|---|
| ho3-003 | React `dangerouslySetInnerHTML={{__html:this.props.html}}`（写在 JSX 属性里） | 解析器只认 `key: expr` 形式的对象字面量，不认 JSX 属性 |
| ho3-006 | Svelte `{@html $page.query.body}` | `$page` 是 SvelteKit 的 store，不在来源表里 |
| ho3-007 | Angular `[innerHTML]="route.snapshot.queryParams.q"` | `ActivatedRoute.snapshot` 的成员链没建进来源表 |

另外 `window.__NEXT_DATA__` 也不在来源表里（ho3-005 只是被关键词规则兜住，taint 单独跑会漏）。
这三条都在「单文件、不跨函数」的边界之内可以补，但要再写第四轮留出集验证——不能改完拿第三轮报数。

**6. hybrid 的高召回是用误报换的。**
第三轮上 hybrid 的 F1（0.9000）高于 taint（0.8235），代价是 1 条误报（`ho3-012`，
`DOMPurify` 净化后的模板绑定被关键词规则误判）。它把 taint 认不出的写法交给关键词规则去猜，
猜对就赚、猜错就多一条 suspected。这就是产品里的取舍——**先给你已证实的，再给你存疑的**，
而不是混成一张没有等级的清单。但同样这条漏报，模型兜底在同样的召回下一条误报都没有（见第 8 条），
所以这套数据里更好的兜底是大模型，不是关键词规则。

**7. McNemar 的 p 值在这点样本量下多数不显著。**
这不是缺陷，是诚实：25 条、16 条的语料本来就撑不起「显著」两个字。
第二轮上 heuristic vs taint 的 p=0.0078 看起来显著，但它测的是「v3 补完的那两条写法」，
样本正好落在这两条上，不能外推成「普遍更准」。第三轮三个对比的 p 值全是 1.0000，
说明 0.8235 与 0.9000 的差距在这点样本量下跟抛硬币分不开。

**8. 大模型那层：提示词收窄之后，它才成为能加分的兜底。**

旧提示词写的是「判断 XSS 和 SQL 注入」，模型会顺着这句报越界项（后端注入、脚本外链），
在「只判有没有问题」的评测里一律算误报。改成只判 XSS 之后，同一批样本重跑：
开发集 28 条负样本上，DeepSeek 单跑误报 5 条降到 1 条，「污点+DeepSeek」7 条降到 2 条。
提示词的范围就是评测的范围，这条比任何调参都值。

改完之后的数字：四套开发证据上 taint 已经是 100/100，兜底仍然只掉分
（dataset 0.9565 / corpus-hard 1.0000 打平 / holdout 0.8333 / holdout2 0.9524）。
只有第三轮留出集上兜底得分，而且这次是模型赢：taint 0.8235 → **llm_union 0.9474**
（P 100%、R 90%、**0 条误报**），漏的只剩 ho3-006 一条 Svelte `{@html $page.query.body}`。
关键词兜底 hybrid 是 0.9000：召回同为 90%，漏的都是同一条 ho3-006，差别只在误报——
关键词多报一条 ho3-012（`DOMPurify` 净化后的模板绑定被当成可疑），模型 0 条。
上一版模型在这里的误报（ho3-014，一条死赋值 `var msg = $route.query.q;`）也随提示词收窄消失了。

两个保留意见，别把 0.9474 说成定论：

一是第三轮上 llm_union 与 hybrid 只差 1 条样本，McNemar p=1.0000，这点量级撑不起「显著」。
真正显著的只有开发集：llm_union 对 hybrid 是 12 比 1，p=0.0034；对关键词基线 heuristic 是
13 比 1，p=0.0018。也就是说「模型比关键词兜底准」这句话，证据主要来自 50 条的开发集，
不是来自 16 条的留出集。

二是运行间波动。第一轮留出集上，DeepSeek 单跑与 llm_union 的 F1 在两轮之间直接互换了
（0.8333 / 0.7143 → 0.7273 / 0.8333）。同一个后端、同一批样本，差 0.12 属于正常抖动，
比第三轮 0.9474 与 0.9000 的差距还大。单次运行的模型数字只能当区间看，bootstrap 区间已经写进
`eval/report.md`（第三轮 llm_union 的 F1 区间是 0.80–1.00）。

全交给模型仍然更差：DeepSeek 单跑在第二轮留出集召回只有 60%（F1 0.7059）。
先跑静态分析、只在它没结论时问模型，是这几套数据里唯一说得通的结构；
llm_union 也因此在第三轮只发 6 次请求，而不是 16 次。

## 没跑通的后端

- **semgrep**：装好 `semgrep 1.183.0` 后每个语料都返回退出码 2（`error.py:38` 的
  `FATAL_EXIT_CODE`），stderr 为空。最可能的原因是仓库路径含非 ASCII 字符，而 Semgrep 的
  OCaml 核心在 Windows 上处理这类路径有已知问题；尚未验证。规则文件已经写好
  （eval/semgrep-xss.yaml），换到纯英文路径后 `python eval.py --backends taint,semgrep`
  应当能出数字。

deepseek 与 llm_union 已经跑通，数字见上文与 `eval/report.md`。与 Semgrep 的对照仍是空缺，
所以站得住的比较只有三种：比关键词基线准、比关键词兜底准、比单跑的大模型干净——
都是同一台机器上真跑出来的，命令与语料都在仓库里。

## 下一步（按性价比排序）

1. **把剩下的三种写法补进来源表**：JSX 属性里的对象字面量、SvelteKit 的 `$page` store、
   Angular 的 `route.snapshot`，外加 `window.__NEXT_DATA__`。补完必须再写第四轮留出集验证，
   不能拿第三轮报数。
2. **真实站点语料**：从公开漏洞公告/靶场页面取样本，人工双标注、算标注一致性。
   自建语料再诚实也有天花板。
3. **与 Semgrep 同基线**：证明「不是重复造轮子」，或者证明「在 HTML 内联脚本这个切片上更准」。
4. **让模型数字可复现**：同一样本跑 3 次看波动，或把 temperature 调到 0。目前同一套语料
   两轮之间，同一后端的 F1 能差 0.12（第一轮留出集上两个后端直接互换高低），
   单次结果只能当区间看。

## 复现

    pip install -r requirements.txt
    python eval.py                                # 三个后端 × 五套语料，约 1 秒
    python eval.py --backends taint               # 只跑一个
    python eval.py --dataset eval/corpus-holdout2.jsonl
    python -m pytest tests/test_scanner.py tests/test_llm_pipeline.py tests/test_taint.py tests/test_eval.py -q

报告写到 eval/report.md，逐样本明细在 eval/bench.json（两者都不入库，跑一次就有）。

## 变更记录

- **2026-10-30（提示词收窄）**：scanner_core.py 的提示词从「XSS 和 SQL 注入」改成只判 XSS，
  输出枚举去掉 `SQL_INJECTION`。纯前端 HTML 判不出后端注入，越界结论只会污染评测。
  deepseek 与 llm_union 全量重测，第三轮留出集上 llm_union 0.8571 → 0.9474（误报 2 → 0），
  开发集上 deepseek 误报 5 → 1。
- **2026-10（v3）**：框架注入源（`$route.*`、`route.*`、`this.props`、裸 `props.x`、
  `window.__INITIAL_STATE__` / `__NUXT__` / `__PRELOADED_STATE__` / `__INITIAL_DATA__` / `__APOLLO_STATE__`、
  `document.location`）。测试 90 → 97。新增第三轮留出集 corpus-holdout3.jsonl（16 条），
  taint 在它上面 0.8235；第二轮因此降级为开发证据。
- **2026-10（v2）**：模板层汇点（v-html / [innerHTML] / dangerouslySetInnerHTML /
  setAttribute / {@html} / {{{ }}} / unsafeHTML）、对象字面量 `key: expr` 传播、
  `on*` 属性赋值汇点、`encodeURIComponent` 计入净化。测试 73 → 90。
  新增第二轮留出集 corpus-holdout2.jsonl；第一轮留出集因被用于诊断而降级为开发证据。
- **2026-10（v1）**：eval/dataset.jsonl 的 xss-004 原有标注错误：原样本 `onclick="go('+location.hash+')"`
  里，location.hash 落在字符串字面量内部，不是可执行拼接，标成「有风险」不成立。
  已改成 `document.getElementById('out').innerHTML = location.hash`，标注保持不变。
  因此旧 README 里规则基线的 F1（0.7273）与新表的 0.7500 不可直接比较。