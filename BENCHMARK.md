# 基准测试

这份文件回答三个问题：**规则法错在哪、污点分析值不值、大模型那层还要不要留**。
所有数字都能用一条命令重跑，语料与标注规则都在仓库里。

## 方法

三套语料，用途不同：

| 语料 | 条数 | 正/负 | 用途 |
|---|---|---|---|
| eval/dataset.jsonl | 50 | 22 / 28 | 开发语料，覆盖常见写法，含 16 条「有 sink 无 source」干扰项 |
| eval/corpus-hard.jsonl | 25 | 16 / 9 | 开发语料，覆盖难例（变量传播、模板字符串、postMessage、eval 链）与安全对照 |
| eval/corpus-holdout.jsonl | 12 | 5 / 7 | **留出语料**：taint.py 冻结后新写，故意用框架语法，写完不再改代码 |

前两套是「边写代码边看」的开发集，第三套是「代码定稿后一次性拉开」。

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

| 语料 | 后端 | P | R | F1 | FPR | TP/FP/TN/FN | 每条耗时 |
|---|---|---|---|---|---|---|---|
| dataset | heuristic | 61.76% | 95.45% | 0.7500 | 46.43% | 21/13/15/1 | 0.0001s |
| dataset | taint | 100% | 100% | 1.0000 | 0% | 22/0/28/0 | 0.0000s |
| dataset | hybrid | 62.86% | 100% | 0.7720 | 46.43% | 22/13/15/0 | 0.0001s |
| corpus-hard | heuristic | 78.95% | 93.75% | 0.8572 | 44.44% | 15/4/5/1 | 0.0002s |
| corpus-hard | taint | 100% | 100% | 1.0000 | 0% | 16/0/9/0 | 0.0000s |
| corpus-hard | hybrid | 80.00% | 100% | 0.8889 | 44.44% | 16/4/5/0 | 0.0001s |
| corpus-holdout | heuristic | 50.00% | 80.00% | 0.6154 | 57.14% | 4/4/3/1 | 0.0001s |
| corpus-holdout | taint | 50.00% | 20.00% | 0.2857 | 14.29% | 1/1/6/4 | 0.0001s |
| corpus-holdout | hybrid | 44.44% | 80.00% | 0.5714 | 71.43% | 4/5/2/1 | 0.0002s |

显著性（McNemar，双侧）：

| 对比 | 语料 | p 值 | 结论 |
|---|---|---|---|
| heuristic vs taint | dataset | 0.0001 | 差距显著 |
| taint vs hybrid | dataset | 0.0002 | 差距显著 |
| heuristic vs taint | corpus-hard | 0.0625 | 样本量不足以判定 |
| taint vs hybrid | corpus-hard | 0.1250 | 样本量不足以判定 |
| heuristic vs taint | holdout | 1.0000 | 样本量不足以判定 |

完整表格（含每个指标的置信区间与逐条误报/漏报名单）由 eval.py 自动写进 eval/report.md。

## 怎么读这张表

**1. 规则法的误报率是结构性的，不是调参能救的。**
它在两套开发语料上的 FPR 都在 44% 以上：只要页面出现 innerHTML / eval 这类词就报警，
而现代前端页面几乎都有。所以「命中关键词即漏洞」这条路线可以判死刑了。

**2. 污点分析在开发语料上的 1.000 是上限，不是成绩。**
这两套语料和 taint.py 出自同一人之手：我写样本时知道它支持哪些语法，写代码时也对着样本改。
这正是自建语料的陷阱，所以必须看第三套。

**3. 留出语料上的 0.2857 才是真实起点，而且缺口很具体。**
5 条正样本只抓到 1 条，漏掉的 4 条全部是框架语法：

| 漏报 | 写法 | 为什么漏 |
|---|---|---|
| ho-001 | Vue v-html 绑定 | 模板指令不是 DOM API，汇点表里没有 |
| ho-002 | React dangerouslySetInnerHTML | 数据在一个对象字面量的 __html 字段里 |
| ho-003 | Angular [innerHTML] 属性绑定 | 同上，编译期语法 |
| ho-005 | setAttribute('onclick', ...) | 只建了少数属性名，事件处理器属性没建 |

唯一的误报 ho-011 也值得记：encodeURIComponent 嵌在字符串拼接里时，净化判定没生效。

**4. hybrid 的高召回是用误报换的。**
留出语料上召回 80%，但 FPR 71%：它把 taint 漏掉的框架写法交给关键词规则去猜。
这就是产品里的取舍——**先给你已证实的，再给你存疑的**，而不是混成一张没有等级的清单。

**5. McNemar 的 p 值在这点样本量下多数不显著。**
这不是缺陷，是诚实：25 条、12 条的语料本来就撑不起「显著」两个字。
规模化的那一步需要真实站点语料，见下。

## 没跑的两个后端（以及为什么写在这里而不是藏起来）

- **semgrep**：本机没装、沙箱无出网装不了。规则文件已经写好（eval/semgrep-xss.yaml），
  装好后 `python eval.py --backends taint,semgrep` 即可得到同基线对比。
- **deepseek**：需要 API key 与网络。命令是 `python eval.py --backends deepseek`，
  结果会进 eval/cache/ 供复跑。

在这两个数字出来之前，本文任何「比 X 好」的说法都不成立；上面只写了「比关键词规则好」，
因为那是同一台机器上真跑出来的。

## 下一步（按性价比排序）

1. **真实站点语料**：从公开的漏洞公告/靶场页面取样本，人工双标注、算标注一致性。
   这是唯一能把 0.2857 变成有意义的数字的路。
2. **框架层支持**：v-html / dangerouslySetInnerHTML / [innerHTML] / setAttribute 事件属性，
   预计把留出集召回从 20% 拉到 80%。
3. **与 Semgrep 同基线**：证明「不是重复造轮子」，或者证明「在 HTML 内联脚本这个切片上更准」。
4. **把大模型那层做成可消融的**：LLM 只在污点分析无结论时调用，并测它的边际贡献。

## 复现

    pip install -r requirements.txt
    python eval.py                          # 三个后端 × 三套语料，约 1 秒
    python eval.py --backends taint         # 只跑一个
    python eval.py --dataset eval/corpus-holdout.jsonl
    python -m pytest -q                     # 73 个用例

报告写到 eval/report.md，逐样本明细在 eval/bench.json。

## 变更记录

- eval/dataset.jsonl 的 xss-004 原有标注错误：原样本 `onclick="go('+location.hash+')"`
  里，location.hash 落在字符串字面量内部，不是可执行拼接，标成「有风险」不成立。
  已改成 `document.getElementById('out').innerHTML = location.hash`，标注保持不变。
  因此旧 README 里规则基线的 F1（0.7273）与新表的 0.7500 不可直接比较。
