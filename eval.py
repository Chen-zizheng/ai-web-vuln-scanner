# -*- coding: utf-8 -*-
"""离线评测：在同一份语料上跑多个后端，输出可比对的指标、置信区间与显著性检验。

用法：
    python eval.py                           # 规则基线 / 污点分析 / 混合，两套语料一起跑
    python eval.py --backends taint          # 只跑一个后端
    python eval.py --backends deepseek       # 真实调用大模型（需 DEEPSEEK_API_KEY）
    python eval.py --backends taint,semgrep  # 与 Semgrep 同基线对比（需已安装 semgrep）

产物：
    eval/bench.json   逐后端、逐样本的完整结果
    eval/report.md    可直接贴进 README 的对比报告
"""
import argparse
import datetime
import json
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))       # 仓库根目录
EVAL_DIR = os.path.join(HERE, "eval")
sys.path.insert(0, HERE)

import scanner_core  # noqa: E402
import taint  # noqa: E402

DEFAULT_DATASETS = [
    os.path.join(EVAL_DIR, "dataset.jsonl"),      # 开发语料：常规写法
    os.path.join(EVAL_DIR, "corpus-hard.jsonl"),  # 开发语料：难例与干扰项
    os.path.join(EVAL_DIR, "corpus-holdout.jsonl"),   # 第一轮留出集（已用于诊断，见 BENCHMARK.md）
    os.path.join(EVAL_DIR, "corpus-holdout2.jsonl"),  # 第二轮留出集：taint v2 冻结后新写
    os.path.join(EVAL_DIR, "corpus-holdout3.jsonl"),  # 第三轮留出集：taint v3 冻结后新写
]
DEFAULT_BACKENDS = "heuristic,taint,hybrid"
SEMGREP_CONFIG = os.path.join(EVAL_DIR, "semgrep-xss.yaml")
REQUIRED_FIELDS = ["vulnerability_type", "risk_level", "location", "reason", "fix_suggestion"]


class BackendUnavailable(RuntimeError):
    """后端依赖不满足（比如没装 semgrep），跳过该后端而不是让整轮评测失败。"""


# ----------------------------------------------------------------- 指标计算
def compute_binary_metrics(labels, preds):
    """labels / preds 均为布尔序列，返回混淆矩阵与常用指标。"""
    if len(labels) != len(preds):
        raise ValueError("labels 与 preds 长度不一致")
    tp = fp = tn = fn = 0
    for y, p in zip(labels, preds):
        if y and p:
            tp += 1
        elif p and not y:
            fp += 1
        elif not y and not p:
            tn += 1
        else:
            fn += 1

    def _div(a, b):
        return round(a / b, 4) if b else 0.0

    precision = _div(tp, tp + fp)
    recall = _div(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "total": len(labels),
        "accuracy": _div(tp + tn, len(labels)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": _div(tn, tn + fp),
        "false_positive_rate": _div(fp, fp + tn),
    }


def _metric_value(labels, preds, name):
    return compute_binary_metrics(labels, preds)[name]


def bootstrap_ci(labels, preds, name="f1", iters=2000, seed=1234):
    """percentile bootstrap：重采样同一批样本，给出指标的 95% 区间。

    样本量小时单点 F1 没有意义，区间才能说明这个差距是不是噪声。
    """
    n = len(labels)
    if n == 0:
        return [0.0, 0.0]
    rng = random.Random(seed)
    values = []
    for _ in range(iters):
        idx = [rng.randrange(n) for _ in range(n)]
        values.append(_metric_value([labels[i] for i in idx], [preds[i] for i in idx], name))
    values.sort()
    lo = values[int(0.025 * iters)]
    hi = values[min(iters - 1, int(0.975 * iters))]
    return [round(lo, 4), round(hi, 4)]


def mcnemar_test(labels, pred_a, pred_b):
    """同一批样本上两个后端的配对检验（精确二项，双侧）。

    a_only：a 判对而 b 判错的样本数；b_only 反之。p 值小才说明差距不是碰运气。
    """
    a_only = sum(1 for y, x, z in zip(labels, pred_a, pred_b) if x == y and z != y)
    b_only = sum(1 for y, x, z in zip(labels, pred_a, pred_b) if z == y and x != y)
    n = a_only + b_only
    if n == 0:
        return {"a_only": 0, "b_only": 0, "p_value": 1.0}
    k = min(a_only, b_only)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / float(2 ** n)
    return {"a_only": a_only, "b_only": b_only, "p_value": round(min(1.0, 2 * tail), 4)}


def compute_schema_completeness(findings):
    """findings: [[{...}, ...], ...]，返回字段完整率。"""
    total = complete = 0
    for item_list in findings:
        if not isinstance(item_list, list):
            continue
        for item in item_list:
            if not isinstance(item, dict):
                continue
            total += 1
            if all(str(item.get(k, "")).strip() for k in REQUIRED_FIELDS):
                complete += 1
    return {
        "findings_total": total,
        "findings_complete": complete,
        "schema_completeness": round(complete / total, 4) if total else 0.0,
    }


# ------------------------------------------------------------------- 后端
def backend_heuristic(features):
    """规则基线：只要命中可疑 sink 就报 XSS。

    这是刻意保留的笨基线，用来证明关键词规则会大量误报。
    """
    sinks = features.get("suspicious_patterns") or []
    if not sinks:
        return []
    level = "HIGH" if features.get("forms") else "MEDIUM"
    return [{
        "vulnerability_type": "XSS",
        "risk_level": level,
        "location": "inline script",
        "reason": "命中关键词：%s" % ", ".join(sorted(set(sinks))),
        "fix_suggestion": "对输出做上下文相关转义",
        "confidence": "suspected",
    }]


def backend_taint(html):
    """污点分析：只有来源到汇点能连起来才报，并带行号。"""
    return taint.analyze(html)["findings"]


def backend_hybrid(html, features):
    """混合：污点分析负责可证的部分，规则兜住它认不出的写法（标为 suspected）。"""
    static = backend_taint(html)
    if static:
        return static
    return backend_heuristic(features)


def backend_llm_union(html, features):
    """污点分析优先，漏掉的交给大模型补。这才是产品实际跑的那条线。"""
    static = backend_taint(html)
    if static:
        return static
    return normalize_findings(backend_deepseek(scanner_core.build_prompt("eval:llm_union", features)))


def backend_deepseek(prompt):
    return scanner_core.call_llm(prompt)


def normalize_findings(raw):
    """把模型返回统一成 list。模型要求返回数组，但可能返回对象或解析失败。"""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return []


# ------------------------------------------------------------------ Semgrep
def semgrep_predictions(rows, binary=None, config=None, timeout=900, workdir=None):
    """把每页的内联脚本抽成 .js，统一交给 Semgrep 跑一遍，返回 {样本 id: 是否报出}。

    HTML 本身不是 JS，Semgrep 解析不了；抽取规则与 taint.js_units 完全一致，
    这样两者比较的是数据流引擎，而不是谁抽得更全。
    """
    binary = binary or os.environ.get("SEMGREP_BIN") or "semgrep"
    config = config or os.environ.get("SEMGREP_CONFIG") or SEMGREP_CONFIG
    if not os.path.exists(config):
        raise BackendUnavailable("找不到 Semgrep 规则文件：%s" % config)

    # workdir 供测试注入（部分沙箱里系统临时目录不可写）；正常调用走 mkdtemp
    tmp = workdir or tempfile.mkdtemp(prefix="avs-semgrep-")
    cleanup = workdir is None
    mapping = {}
    try:
        for row in rows:
            for name, code in taint.js_units(row["html"]):
                fname = "%s__%s" % (row["id"], name)
                with open(os.path.join(tmp, fname), "w", encoding="utf-8") as f:
                    f.write(code)
                mapping[fname] = row["id"]
        if not mapping:
            return {row["id"]: False for row in rows}
        cmd = [binary, "--config", config, "--json", "--quiet", "--no-git-ignore", tmp]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise BackendUnavailable(
                "未找到 Semgrep 可执行文件（%s）。安装：pip install semgrep，"
                "或用 SEMGREP_BIN 指定路径" % binary)
        except subprocess.TimeoutExpired:
            raise BackendUnavailable("Semgrep 运行超时（%ss）" % timeout)
        if proc.returncode not in (0, 1):
            raise BackendUnavailable("Semgrep 退出码 %d：%s"
                                     % (proc.returncode, (proc.stderr or proc.stdout or "")[:300]))
        try:
            data = json.loads(proc.stdout or "{}")
        except ValueError:
            raise BackendUnavailable("Semgrep 输出不是合法 JSON：%s" % (proc.stdout or "")[:200])
        hits = {row["id"]: 0 for row in rows}
        for res in data.get("results", []):
            rid = mapping.get(os.path.basename(str(res.get("path", ""))))
            if rid is not None:
                hits[rid] += 1
        return {rid: n > 0 for rid, n in hits.items()}
    finally:
        if cleanup:
            shutil.rmtree(tmp, ignore_errors=True)


# -------------------------------------------------------------------- 主流程
def load_dataset(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _cache_path(backend, dataset_path):
    stem = os.path.splitext(os.path.basename(dataset_path))[0]
    return os.path.join(EVAL_DIR, "cache", "%s__%s.json" % (backend, stem))


def evaluate_backend(backend, rows, dataset_path, use_cache=True):
    """单后端跑一遍语料，返回结果字典（含逐样本明细）。"""
    labels, preds, items, all_findings = [], [], [], []
    cache, dirty = {}, False
    cache_path = _cache_path(backend, dataset_path)
    if backend in ("deepseek", "llm_union") and use_cache and os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            cache = json.load(f)

    flags = None
    if backend == "semgrep":
        flags = semgrep_predictions(rows)

    started = time.time()
    for row in rows:
        sid, html = row["id"], row["html"]
        truth = bool(row["label"]["has_xss_risk"])

        if backend == "semgrep":
            findings = [{"vulnerability_type": "XSS", "location": "semgrep",
                         "risk_level": row["label"]["risk_level"], "reason": "semgrep",
                         "fix_suggestion": "见规则"}] if flags.get(sid) else []
        elif backend == "heuristic":
            findings = backend_heuristic(scanner_core.extract_features(html))
        elif backend == "taint":
            findings = backend_taint(html)
        elif backend == "hybrid":
            findings = backend_hybrid(html, scanner_core.extract_features(html))
        elif backend == "llm_union":
            static = backend_taint(html)
            if static:
                findings = static          # 静态已证实，不必花钱问模型
            elif sid in cache:
                findings = cache[sid]
            else:
                features = scanner_core.extract_features(html)
                prompt = scanner_core.build_prompt("eval:%s" % sid, features)
                try:
                    findings = normalize_findings(backend_deepseek(prompt))
                except Exception as exc:
                    findings = [{"error": "%s: %s" % (type(exc).__name__, exc)}]
                cache[sid] = findings
                dirty = True
        else:  # deepseek
            if sid in cache:
                findings = cache[sid]
            else:
                features = scanner_core.extract_features(html)
                prompt = scanner_core.build_prompt("eval:%s" % sid, features)
                try:
                    findings = normalize_findings(backend_deepseek(prompt))
                except Exception as exc:      # 网络或鉴权失败不中断整轮
                    findings = [{"error": "%s: %s" % (type(exc).__name__, exc)}]
                cache[sid] = findings
                dirty = True

        all_findings.append(findings)
        got = len(findings) > 0 and not (len(findings) == 1 and "error" in findings[0])
        labels.append(truth)
        preds.append(got)

        first = findings[0] if findings and isinstance(findings[0], dict) else {}
        items.append({
            "id": sid,
            "truth": truth,
            "pred": got,
            "note": row.get("note", ""),
            "findings": len([f for f in findings if isinstance(f, dict) and "error" not in f]),
            "level": first.get("risk_level", ""),
            "location": str(first.get("location", ""))[:160],
            "error": first.get("error", ""),
        })

    elapsed = round(time.time() - started, 3)

    if dirty:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=1)

    metrics = compute_binary_metrics(labels, preds)
    record = {
        "backend": backend,
        "dataset": os.path.basename(dataset_path),
        "samples": len(rows),
        "metrics": metrics,
        "ci": {
            "precision": bootstrap_ci(labels, preds, "precision"),
            "recall": bootstrap_ci(labels, preds, "recall"),
            "f1": bootstrap_ci(labels, preds, "f1"),
        },
        "elapsed_seconds": elapsed,
        "avg_seconds_per_sample": round(elapsed / len(rows), 4) if rows else 0.0,
        "items": items,
    }
    if backend in ("deepseek", "llm_union"):
        record["schema"] = compute_schema_completeness(all_findings)
    record["labels"], record["preds"] = labels, preds
    return record


def render_report(records, dataset_paths, skipped=None):
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "# 评测报告",
        "",
        "生成时间：%s　｜　复现命令：python eval.py" % stamp,
        "",
        "同一份语料、同一套指标、同一台机器上跑多个后端，才能回答"
        "「为什么需要污点分析」「为什么需要大模型」。",
        "",
    ]
    for path in dataset_paths:
        rows = load_dataset(path)
        pos = sum(1 for r in rows if r["label"]["has_xss_risk"])
        name = os.path.basename(path)
        lines += ["## %s（%d 条，%d 正 / %d 负）" % (name, len(rows), pos, len(rows) - pos), ""]
        lines += ["| 后端 | 精确率 P | 召回率 R | F1 | 误报率 FPR | TP / FP / TN / FN | 平均耗时 |",
                  "|---|---|---|---|---|---|---|"]
        rows_out = []
        for rec in records:
            if rec["dataset"] != name:
                continue
            m, ci = rec["metrics"], rec["ci"]
            lines.append("| %s | %.2f%% [%.2f, %.2f] | %.2f%% [%.2f, %.2f] | %.4f [%.2f, %.2f] | %.2f%% | %d / %d / %d / %d | %.3fs |"
                         % (rec["backend"],
                            m["precision"] * 100, ci["precision"][0] * 100, ci["precision"][1] * 100,
                            m["recall"] * 100, ci["recall"][0] * 100, ci["recall"][1] * 100,
                            m["f1"], ci["f1"][0], ci["f1"][1],
                            m["false_positive_rate"] * 100,
                            m["tp"], m["fp"], m["tn"], m["fn"],
                            rec["avg_seconds_per_sample"]))
            rows_out.append(rec)
        lines.append("")
        lines.append("方括号内是该指标在 2000 次 bootstrap 重采样下的 95% 置信区间。")
        lines.append("")

        for rec in rows_out:
            fp_ids = [i["id"] for i in rec["items"] if i["pred"] and not i["truth"]]
            fn_ids = [i["id"] for i in rec["items"] if i["truth"] and not i["pred"]]
            if not fp_ids and not fn_ids:
                continue
            lines.append("- **%s** 误报：%s" % (rec["backend"], ", ".join(fp_ids) or "无"))
            lines.append("  漏报：%s" % (", ".join(fn_ids) or "无"))
            lines.append("")

    pairs = []
    for i in range(len(records)):
        for j in range(i + 1, len(records)):
            a, b = records[i], records[j]
            if a["dataset"] != b["dataset"] or a["labels"] != b["labels"]:
                continue
            res = mcnemar_test(a["labels"], a["preds"], b["preds"])
            pairs.append((a["backend"], b["backend"], a["dataset"], res))
    if pairs:
        lines += ["## 显著性检验（McNemar 精确检验，双侧）", "",
                  "只有「一个后端判对而另一个判错」的样本参与检验；p 小于 0.05 才谈得上稳定差距。", "",
                  "| 对比 | 语料 | 前者独对 | 后者独对 | p 值 | 结论 |", "|---|---|---|---|---|---|"]
        for a, b, ds, res in pairs:
            verdict = "差距显著" if res["p_value"] < 0.05 else "样本量不足以判定"
            lines.append("| %s vs %s | %s | %d | %d | %.4f | %s |"
                         % (a, b, ds, res["a_only"], res["b_only"], res["p_value"], verdict))
        lines.append("")

    if skipped:
        lines += ["## 跳过的后端", ""]
        for name, reason in skipped.items():
            lines.append("- **%s**：%s" % (name, reason))
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="多后端对比评测")
    ap.add_argument("--backends", default=DEFAULT_BACKENDS,
                    help="逗号分隔：heuristic,taint,hybrid,deepseek,llm_union,semgrep")
    ap.add_argument("--backend", default=None, help="旧参数，等价于 --backends <名字>")
    ap.add_argument("--dataset", action="append", default=None, help="可重复；默认两套语料")
    ap.add_argument("--limit", type=int, default=0, help="每套语料只跑前 N 条")
    ap.add_argument("--no-cache", action="store_true", help="忽略大模型返回缓存")
    args = ap.parse_args(argv)

    if args.backend:
        args.backends = args.backend
    backends = [b.strip() for b in args.backends.split(",") if b.strip()]
    unknown = [b for b in backends if b not in ("heuristic", "taint", "hybrid", "deepseek", "llm_union", "semgrep")]
    if unknown:
        raise SystemExit("未知后端：%s" % ", ".join(unknown))

    datasets = args.dataset or DEFAULT_DATASETS
    records, skipped = [], {}
    for path in datasets:
        rows = load_dataset(path)
        if args.limit:
            rows = rows[: args.limit]
        for backend in backends:
            try:
                rec = evaluate_backend(backend, rows, path, use_cache=not args.no_cache)
            except BackendUnavailable as exc:
                skipped[backend] = str(exc)
                continue
            records.append(rec)
            m = rec["metrics"]
            print("%-10s %-22s P=%.3f R=%.3f F1=%.3f  (%d 条, %.2fs)"
                  % (backend, rec["dataset"], m["precision"], m["recall"], m["f1"],
                     rec["samples"], rec["elapsed_seconds"]))

    report = render_report(records, datasets, skipped)
    os.makedirs(EVAL_DIR, exist_ok=True)
    with open(os.path.join(EVAL_DIR, "report.md"), "w", encoding="utf-8") as f:
        f.write(report)
    with open(os.path.join(EVAL_DIR, "bench.json"), "w", encoding="utf-8") as f:
        json.dump({"records": records, "skipped": skipped}, f,
                  ensure_ascii=False, indent=1, default=str)
    print("\n已写入 eval/report.md 与 eval/bench.json")
    if skipped:
        for name, reason in skipped.items():
            print("跳过 %s：%s" % (name, reason))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
