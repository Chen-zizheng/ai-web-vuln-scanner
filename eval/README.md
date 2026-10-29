# 评测集与评测流程

这个目录回答一个问题：**扫描器的风险判定到底准不准，准在哪、错在哪。**

没有这个目录之前，项目里只有"能用"的证据；有了它，才有"有多准"的证据。
完整的方法、结果与局限见根目录 [BENCHMARK.md](../BENCHMARK.md)，这里只写标注规则与怎么跑。

## 三套语料

| 文件 | 条数 | 正/负 | 用途 |
|---|---|---|---|
| dataset.jsonl | 50 | 22 / 28 | 开发集：常规写法，含 16 条"有 sink 无 source"干扰项 |
| corpus-hard.jsonl | 25 | 16 / 9 | 开发集：难例（变量传播、模板字符串、postMessage、eval 链）与对应安全对照 |
| corpus-holdout.jsonl | 12 | 5 / 7 | **留出集**：污点分析代码冻结之后才写，故意使用 Vue / React / Angular 语法 |

前两套用来开发和调参，第三套只看不调。留出集的分数不是用来"证明做得好"，
是用来估计"换一批真实页面会掉到哪"——结果确实掉了，原因写在 BENCHMARK.md 里，没有藏。

dataset.jsonl 的负例分两类：

| 类别 | 条数 | 说明 |
|---|---|---|
| 负例 safe-001 ~ 016 | 16 | **有 sink 但数据源不可控**（innerHTML 写常量、eval 求常量、src 指向 CDN……） |
| 负例 safe-017 ~ 028 | 12 | 无执行型 sink（表单、静态页、框架模板绑定） |

后两类负例是刻意设计的干扰项。**关键词规则会把 safe-001 ~ 016 全部误报**，这正是我们想测出来的东西。

## 标注规则

判定目标是「**页面是否存在 XSS 风险点**」，即：是否存在一条从不可信输入到可执行上下文的通路。

- 记为**正例**：存在 sink（innerHTML / document.write / eval / setTimeout(字符串) / .src= / insertAdjacentHTML / 内联事件处理器 / srcdoc），**且**其数据来自不可控来源（表单值、location.*、localStorage、URL 参数、postMessage 消息体）。
- 记为**负例**：sink 存在但数据是常量/本地运算结果；数据来自不可控来源但经过了被认可的净化（textContent、escapeHtml、DOMPurify、encodeURIComponent 等）；页面无执行型 sink。
- 记为**负例（框架）**：Vue v-html、React dangerouslySetInnerHTML、Angular [innerHTML] 这类写法的判定取决于框架版本与默认转义行为，本仓库的静态分析**不认**它们——所以留出集里这些正例被漏，属于已知缺口而非标注错误。
- risk_level：不可信数据直达执行上下文记 HIGH；需要一次额外交互或二次编码才可触发记 MEDIUM；无可执行通路记 LOW。

标注由人工完成，规则写在这里而不是藏在代码里，**任何人可以按同样规则复核我的标注**。
有争议的样本应改标注而不是改规则；改过标注的样本必须在 BENCHMARK.md 的变更记录里留痕
（xss-004 就改过一次，因为它原来的写法在语法上不可执行，旧标注不成立）。

## 五个后端

| 后端 | 说明 |
|---|---|
| heuristic | 关键词规则：命中 sink 即报。作为对照的"平时那种写法" |
| taint | 单文件内联脚本的污点分析，来源→汇点传播，带行号 |
| hybrid | taint 优先；没有发现时退回 heuristic，结论标记为 suspected |
| deepseek | 真实调用大模型（需 DEEPSEEK_API_KEY 与网络），结果带缓存 |
| semgrep | 用 eval/semgrep-xss.yaml 的 taint 规则跑同一批脚本，作为同基线对比（需安装 semgrep） |

## 运行

~~~bash
# 默认：heuristic + taint + hybrid，三套语料全跑，离线，约 1 秒
python eval.py

# 只跑某一套语料
python eval.py --dataset eval/corpus-holdout.jsonl

# 真实调用大模型
export DEEPSEEK_API_KEY=sk-xxxx
python eval.py --backends deepseek

# 只跑前 10 条，快速验证链路
python eval.py --backends deepseek --limit 10

# 与 Semgrep 同基线（未装 semgrep 时该后端会被跳过，其余照常跑）
pip install semgrep
python eval.py --backends taint,semgrep
~~~

产物：

- eval/report.md —— 每套语料一张表，附误报与漏报名单，可直接贴进 README
- eval/bench.json —— 逐样本预测 + 汇总指标 + 统计检验结果，可复查每一条为什么判错
- eval/cache/*.json —— 模型返回缓存，重跑不重复计费（只对 deepseek 生效）

## 指标

| 指标 | 含义 |
|---|---|
| Precision | 报出来的风险里有多少是真的 —— **这决定用户会不会被误报淹没** |
| Recall | 真实风险里抓到了多少 —— **这决定会不会漏放** |
| F1 | 两者的调和平均 |
| FPR | 误报率，FP / (FP + TN) |
| 95% 置信区间 | 对 F1 做 2000 次 bootstrap 重采样（固定 seed=1234），取 2.5% / 97.5% 分位 |
| McNemar 精确检验 | 两个后端在同一批样本上是否显著不同；只统计判断不一致的样本，双侧精确二项 |
| 字段完整率 | 模型输出里五个字段（类型/等级/位置/依据/建议）都非空的比例 |

**为什么非要区间和检验**：在 12 条样本上，"F1 从 0.5 掉到 0.29"很可能只是随机波动。
不给区间的对比表看起来精确，实际是在卖确定性。区间宽就是在说"证据不够"。

## 当前结论（完整表见 BENCHMARK.md）

| 语料 | 后端 | P | R | F1 | FPR |
|---|---|---|---|---|---|
| dataset | heuristic | 0.6176 | 0.9545 | 0.7500 | 0.4643 |
| dataset | taint | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| dataset | hybrid | 0.6286 | 1.0000 | 0.7720 | 0.4643 |
| corpus-hard | heuristic | 0.7895 | 0.9375 | 0.8572 | 0.4444 |
| corpus-hard | taint | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| corpus-hard | hybrid | 0.8000 | 1.0000 | 0.8889 | 0.4444 |
| holdout | heuristic | 0.5000 | 0.8000 | 0.6154 | 0.5714 |
| holdout | taint | 0.5000 | 0.2000 | 0.2857 | 0.1429 |
| holdout | hybrid | 0.4444 | 0.8000 | 0.5714 | 0.7143 |

三句话：

1. 关键词规则的误报率是结构性的（两套开发集都 ≥44%），命中 innerHTML 就报警，而现代页面几乎都有它。
2. 污点分析在开发集上的 1.000 是上限，不是成绩——语料和代码出自同一人之手，这叫自证。
3. 留出集上的 0.2857 才是诚实起点，漏的全是框架语法，这是下一版最该补的四类汇点。

McNemar（dataset）：heuristic vs taint p=0.0001，taint vs hybrid p=0.0002。
corpus-hard 上 p=0.0625 / 0.1250，holdout 上 p=1.0000——样本太少，**不显著不等于没有差异**，
只说明以现在的语料量还证明不了差异。
