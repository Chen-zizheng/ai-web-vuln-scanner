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

四个后端：

| 后端 | 做什么 | 会不会联网 |
|---|---|---|
| heuristic | 命中危险函数关键词就报（旧规则基线） | 否 |
| taint | 本仓库的污点分析：来源→汇点连起来才报，带行号 | 否 |
| hybrid | taint 优先，没发现时退回 heuristic（标 suspected） | 否 |
| deepseek / semgrep | 大模型判定 / 工业界静态分析器对照 | 是 / 否 |

指标用精确率 P、召回率 R、F1、误报率 FPR、混淆矩阵；区间是 2000 次 bootstrap 重采样的
95% 分位；两个后端的差距用 McNemar 精确检验（只看「一个判对、另一个判错」的样本）。

## 结果

| 语料 | 后端 | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|---|
| dataset | heuristic | 61.76% | 95.45% | 0.7500 | 46.43% | 21/13/15/1 |
| dataset | taint | 100% | 100% | 1.0000 | 0% | 22/0/28/0 |
| dataset | hybrid | 62.86% | 100% | 0.7720 | 46.43% | 22/13/15/0 |
| corpus-hard | heuristic | 78.95% | 93.75% | 0.8572 | 44.44% | 15/4/5/1 |
| corpus-hard | taint | 100% | 100% | 1.0000 | 0% | 16/0/9/0 |
| corpus-hard | hybrid | 80.00% | 100% | 0.8889 | 44.44% | 16/4/5/0 |
| corpus-holdout | heuristic | 50.00% | 80.00% | 0.6154 | 57.14% | 4/4/3/1 |
| corpus-holdout | taint (v1 → v3) | 50.00% → 100% | 20.00% → 100% | 0.2857 → 1.0000 | 14.29% → 0% | v1 1/1/6/4，v3 5/0/7/0 |
| corpus-holdout | hybrid | 55.56% | 100% | 0.7143 | 57.14% | 5/4/3/0 |
| corpus-holdout2 | heuristic | 75.00% | 30.00% | 0.4286 | 16.67% | 3/1/5/7 |
| corpus-holdout2 | taint (v2 → v3) | 100% → 100% | 80.00% → 100% | 0.8889 → 1.0000 | 0% → 0% | v2 8/0/6/2，v3 10/0/6/0 |
| corpus-holdout2 | hybrid | 90.91% | 100% | 0.9524 | 16.67% | 10/1/5/0 |
| **corpus-holdout3** | heuristic | 88.89% | 80.00% | 0.8421 | 16.67% | 8/1/5/2 |
| **corpus-holdout3** | **taint v3** | **100%** | **70.00%** | **0.8235** | **0%** | 7/0/6/3 |
| **corpus-holdout3** | hybrid | 90.00% | 90.00% | 0.9000 | 16.67% | 9/1/5/1 |

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

**5. 第三轮留出集：0.8235，这是当前代码唯一算数的成绩。**

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
而不是混成一张没有等级的清单。

**7. McNemar 的 p 值在这点样本量下多数不显著。**
这不是缺陷，是诚实：25 条、16 条的语料本来就撑不起「显著」两个字。
第二轮上 heuristic vs taint 的 p=0.0078 看起来显著，但它测的是「v3 补完的那两条写法」，
样本正好落在这两条上，不能外推成「普遍更准」。第三轮三个对比的 p 值全是 1.0000，
说明 0.8235 与 0.9000 的差距在这点样本量下跟抛硬币分不开。

## 没跑的两个后端（以及为什么写在这里而不是藏起来）

- **semgrep**：试过了，没跑成。装上 `semgrep 1.183.0` 之后每个语料都返回退出码 2
  （`error.py:38` 的 `FATAL_EXIT_CODE`），stderr 为空。最可能的原因是仓库路径含中文
  （`D:\deepharnes\04-求职\项目集\AI漏洞扫描器`），而 Semgrep 的 OCaml 核心在 Windows 上
  处理非 ASCII 路径有已知问题；尚未验证。规则文件已经写好（eval/semgrep-xss.yaml），
  在纯英文路径下装好 semgrep 后 `python eval.py --backends taint,semgrep` 应当能出数字。
- **deepseek**：需要 API key 与网络。命令是 `python eval.py --backends deepseek`，
  结果会进 eval/cache/ 供复跑。

在这两个数字出来之前，本文任何「比 X 好」的说法都不成立；上面只写了「比关键词规则好」，
因为那是同一台机器上真跑出来的。

## 下一步（按性价比排序）

1. **把剩下的三种写法补进来源表**：JSX 属性里的对象字面量、SvelteKit 的 `$page` store、
   Angular 的 `route.snapshot`，外加 `window.__NEXT_DATA__`。补完必须再写第四轮留出集验证，
   不能拿第三轮报数。
2. **真实站点语料**：从公开漏洞公告/靶场页面取样本，人工双标注、算标注一致性。
   自建语料再诚实也有天花板。
3. **与 Semgrep 同基线**：证明「不是重复造轮子」，或者证明「在 HTML 内联脚本这个切片上更准」。
4. **大模型那层做成可消融的**：LLM 只在污点分析无结论时调用，并测它的边际贡献。

## 复现

    pip install -r requirements.txt
    python eval.py                                # 三个后端 × 五套语料，约 1 秒
    python eval.py --backends taint               # 只跑一个
    python eval.py --dataset eval/corpus-holdout2.jsonl
    python -m pytest tests/test_scanner.py tests/test_llm_pipeline.py tests/test_taint.py tests/test_eval.py -q

报告写到 eval/report.md，逐样本明细在 eval/bench.json（两者都不入库，跑一次就有）。

## 变更记录

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
