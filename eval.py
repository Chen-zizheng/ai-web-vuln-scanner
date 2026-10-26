# -*- coding: utf-8 -*-
"""扫描器的离线评测脚本。

用法：
    python eval.py                      # 规则基线（离线，不发网络请求）
    python eval.py --backend deepseek   # 真实调用大模型（需 DEEPSEEK_API_KEY）
    python eval.py --backend deepseek --limit 10 --no-cache

产物：
    eval/results.json   本次运行的逐样本预测与汇总指标
    eval/report.md      可直接贴进 README 的评测报告

数据集：eval/dataset.jsonl，50 条人工标注样本（22 正 / 28 负），标注规则见 eval/README.md。
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))   # 仓库根目录
EVAL_DIR = os.path.join(HERE, "eval")                     # 数据集与产物目录
sys.path.insert(0, HERE)

import scanner_core  # noqa: E402


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


def compute_schema_completeness(findings):
    """findings: [[{...}, ...], ...]，返回字段完整率。"""
    REQUIRED = ["vulnerability_type", "risk_level", "location", "reason", "fix_suggestion"]
    total = 0
    complete = 0
    for item_list in findings:
        if not isinstance(item_list, list):
            continue
        for item in item_list:
            if not isinstance(item, dict):
                continue
            total += 1
            if all(str(item.get(k, "")).strip() for k in REQUIRED):
                complete += 1
    return {
        "findings_total": total,
        "findings_complete": complete,
        "schema_completeness": round(complete / total, 4) if total else 0.0,
    }


# --------------------------------------------------------------- 后端实现
def backend_heuristic(features):
    """规则基线：只要命中可疑 sink 就报 XSS。

    这是刻意保留的“笨基线”，用来证明关键词规则会大量误报，从而说明需要语义判断。
    输出结构与模型一致，便于同一套指标直接对比。
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
    }]


def backend_deepseek(prompt):
    return scanner_core.call_llm(prompt)


def load_dataset(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def normalize_findings(raw):
    """把模型返回统一成 list。模型要求返回数组，但可能返回对象或解析失败。"""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        if "raw_analysis" in raw:
            return [raw]
        if "vulnerability_type" in raw:
            return [raw]
        return [raw]
    return []


# --------------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["heuristic", "deepseek"], default="heuristic")
    ap.add_argument("--dataset", default=os.path.join(EVAL_DIR, "dataset.jsonl"))
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 条，0 表示全部")
    ap.add_argument("--no-cache", action="store_true")
    args = ap.parse_args()

    rows = load_dataset(args.dataset)
    if args.limit:
        rows = rows[: args.limit]

    cache_path = os.path.join(EVAL_DIR, "cache", "%s.json" % args.backend)
    cache = {}
    if os.path.exists(cache_path) and not args.no_cache:
        with open(cache_path, "r", encoding="utf-8") as f:
            cache = json.load(f)

    labels, preds, per_item = [], [], []
    all_findings = []
    started = time.time()

    for row in rows:
        sid = row["id"]
        html = row["html"]
        truth = bool(row["label"]["has_xss_risk"])

        features = scanner_core.extract_features(html)

        if args.backend == "heuristic":
            findings = backend_heuristic(features)
        else:
            if sid in cache:
                findings = cache[sid]
            else:
                prompt = scanner_core.build_prompt("eval:%s" % sid, features)
                try:
                    findings = normalize_findings(backend_deepseek(prompt))
                except Exception as exc:  # 网络/鉴权失败不应中断整轮评测
                    findings = [{"error": "%s: %s" % (type(exc).__name__, exc)}]
                cache[sid] = findings
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cache, f, ensure_ascii=False, indent=1)

        all_findings.append(findings)
        got = len(findings) > 0 and not (len(findings) == 1 and "error" in findings[0])
        labels.append(truth)
        preds.append(got)

        levels = [f.get("risk_level") for f in findings if isinstance(f, dict) and "risk_level" in f]
        per_item.append({
            "id": sid,
            "truth": truth,
            "pred": got,
            "note": row.get("note", ""),
            "pred_levels": levels,
            "truth_level": row["label"]["risk_level"],
        })

    elapsed = round(time.time() - started, 2)
    metrics = compute_binary_metrics(labels, preds)
    schema = compute_schema_completeness(all_findings)

    # 命中样本上的等级一致性
    level_hit = level_total = 0
    for item in per_item:
        if item["truth"] and item["pred"] and item["pred_levels"]:
            level_total += 1
            if item["truth_level"] in item["pred_levels"]:
                level_hit += 1

    result = {
        "backend": args.backend,
        "model": scanner_core.MODEL if args.backend == "deepseek" else "heuristic-baseline",
        "dataset": os.path.basename(args.dataset),
        "samples": len(rows),
        "elapsed_seconds": elapsed,
        "binary": metrics,
        "schema": schema,
        "level_agreement": {
            "checked": level_total,
            "matched": level_hit,
            "rate": round(level_hit / level_total, 4) if level_total else 0.0,
        },
        "items": per_item,
    }

    os.makedirs(os.path.join(HERE, "cache"), exist_ok=True)
    with open(os.path.join(EVAL_DIR, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    report = render_report(result)
    with open(os.path.join(EVAL_DIR, "report.md"), "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    return 0


def render_report(result):
    b = result["binary"]
    s = result["schema"]
    lv = result["level_agreement"]
    m = result["model"]
    backend = result["backend"]
    title = "规则基线" if backend == "heuristic" else "大模型（%s）" % m
    lines = [
        "# 评测报告 · %s" % title,
        "",
        "数据集：`%s`（%d 条，22 条正例 / 28 条负例），任务：判断页面是否存在 XSS 风险点。"
        % (result["dataset"], result["samples"]),
        "",
        "| 指标 | 值 |",
        "|---|---|",
        "| 准确率 Accuracy | %.2f%% |" % (b["accuracy"] * 100),
        "| 精确率 Precision | %.2f%% |" % (b["precision"] * 100),
        "| 召回率 Recall | %.2f%% |" % (b["recall"] * 100),
        "| F1 | %.4f |" % b["f1"],
        "| 误报率 FPR | %.2f%% |" % (b["false_positive_rate"] * 100),
        "| 混淆矩阵 | TP=%d / FP=%d / TN=%d / FN=%d |" % (b["tp"], b["fp"], b["tn"], b["fn"]),
        "| 输出字段完整率 | %.2f%%（%d/%d 条判定） |"
        % (s["schema_completeness"] * 100, s["findings_complete"], s["findings_total"]),
        "| 风险等级一致率 | %.2f%%（%d/%d） |" % (lv["rate"] * 100, lv["matched"], lv["checked"]),
        "| 耗时 | %.1fs |" % result["elapsed_seconds"],
        "",
    ]
    fp_ids = [i["id"] for i in result["items"] if i["pred"] and not i["truth"]]
    fn_ids = [i["id"] for i in result["items"] if i["truth"] and not i["pred"]]
    if fp_ids:
        lines.append("- 误报样本：%s" % ", ".join(fp_ids))
    if fn_ids:
        lines.append("- 漏报样本：%s" % ", ".join(fn_ids))
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
