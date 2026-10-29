# -*- coding: utf-8 -*-
"""评测脚本的单元测试：指标计算、数据集完整性、基线后端的行为约定。"""
import json
import os

import pytest

import eval as ev
import taint

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "eval", "dataset.jsonl")
HARD = os.path.join(HERE, "eval", "corpus-hard.jsonl")
HOLDOUT = os.path.join(HERE, "eval", "corpus-holdout.jsonl")
HOLDOUT2 = os.path.join(HERE, "eval", "corpus-holdout2.jsonl")
CORPORA = [(DATASET, 50, 22), (HARD, 25, 16), (HOLDOUT, 12, 5), (HOLDOUT2, 16, 10)]


# --------------------------------------------------------------- 指标计算
def test_binary_metrics_perfect():
    m = ev.compute_binary_metrics([True, False, True], [True, False, True])
    assert m["tp"] == 2 and m["tn"] == 1
    assert m["fp"] == 0 and m["fn"] == 0
    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0


def test_binary_metrics_all_wrong():
    m = ev.compute_binary_metrics([True, False], [False, True])
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (0, 1, 0, 1)
    assert m["accuracy"] == 0.0
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    assert m["f1"] == 0.0


def test_binary_metrics_all_negative_predictions_no_zero_division():
    m = ev.compute_binary_metrics([True, False], [False, False])
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    assert m["f1"] == 0.0
    assert m["specificity"] == 1.0


def test_binary_metrics_rejects_length_mismatch():
    with pytest.raises(ValueError):
        ev.compute_binary_metrics([True], [True, False])


def test_binary_metrics_known_values():
    # TP=2 FP=1 TN=1 FN=1 -> acc 0.6, prec 2/3, rec 2/3
    m = ev.compute_binary_metrics([True, True, True, False, False], [True, True, False, True, False])
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (2, 1, 1, 1)
    assert m["accuracy"] == 0.6
    assert m["precision"] == round(2 / 3, 4)
    assert m["recall"] == round(2 / 3, 4)


# --------------------------------------------------------------- 字段完整率
FULL = {"vulnerability_type": "XSS", "risk_level": "HIGH",
        "location": "inline script", "reason": "r", "fix_suggestion": "f"}


def test_schema_completeness_all_full():
    s = ev.compute_schema_completeness([[FULL], [FULL]])
    assert s["findings_total"] == 2
    assert s["schema_completeness"] == 1.0


def test_schema_completeness_counts_missing_field():
    broken = dict(FULL)
    broken["fix_suggestion"] = "   "          # 只有空白不算填了
    s = ev.compute_schema_completeness([[FULL], [broken]])
    assert s["findings_total"] == 2
    assert s["findings_complete"] == 1
    assert s["schema_completeness"] == 0.5


def test_schema_completeness_ignores_empty_and_garbage():
    s = ev.compute_schema_completeness([[], [{"error": "boom"}], "not-a-list"])
    assert s["findings_total"] == 1
    assert s["schema_completeness"] == 0.0


# --------------------------------------------------------------- 返回值归一化
def test_normalize_findings_keeps_list():
    data = [FULL]
    assert ev.normalize_findings(data) == data


def test_normalize_findings_wraps_single_object():
    assert ev.normalize_findings(FULL) == [FULL]


def test_normalize_findings_wraps_parse_failure():
    assert ev.normalize_findings({"raw_analysis": "not json"}) == [{"raw_analysis": "not json"}]


# --------------------------------------------------------------- 数据集完整性
def test_datasets_exist_and_are_balanced():
    # dataset / corpus-hard 是开发集，两套 holdout 是冻结代码后写的留出集
    for path, expected_total, expected_pos in CORPORA:
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        pos = sum(1 for r in rows if r["label"]["has_xss_risk"])
        assert len(rows) == expected_total, path
        assert pos == expected_pos, path
        assert len(rows) - pos == expected_total - expected_pos, path


def test_dataset_ids_unique_and_fields_present():
    for path, _total, _pos in CORPORA:
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        ids = [r["id"] for r in rows]
        assert len(ids) == len(set(ids)), path
        for r in rows:
            assert r["html"].strip(), r["id"]
            assert isinstance(r["label"]["has_xss_risk"], bool), r["id"]
            assert r["label"]["risk_level"] in ("LOW", "MEDIUM", "HIGH"), r["id"]


# --------------------------------------------------------------- 基线后端
def test_heuristic_flags_known_sink():
    findings = ev.backend_heuristic({"suspicious_patterns": ["innerHTML"], "forms": []})
    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "XSS"
    assert findings[0]["risk_level"] == "MEDIUM"      # 无表单 -> MEDIUM


def test_heuristic_silent_without_sink():
    assert ev.backend_heuristic({"suspicious_patterns": [], "forms": []}) == []


def test_heuristic_does_not_call_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("基线后端不应发起网络请求")
    monkeypatch.setattr("requests.post", boom)
    ev.backend_heuristic({"suspicious_patterns": ["eval("], "forms": [{}]})

# --------------------------------------------------------------- 统计工具
def test_bootstrap_ci_of_perfect_model_is_one():
    labels = [True, False] * 20
    ci = ev.bootstrap_ci(labels, labels, "f1", iters=200)
    assert ci == [1.0, 1.0]


def test_bootstrap_ci_brackets_point_estimate():
    labels = [True, True, True, False, False, False]
    preds = [True, False, True, True, False, False]
    m = ev.compute_binary_metrics(labels, preds)
    lo, hi = ev.bootstrap_ci(labels, preds, "f1", iters=500)
    assert lo <= m["f1"] <= hi


def test_bootstrap_ci_is_deterministic_with_seed():
    labels = [True, False, True, False, True]
    preds = [True, False, False, False, True]
    a = ev.bootstrap_ci(labels, preds, "recall", iters=300, seed=7)
    b = ev.bootstrap_ci(labels, preds, "recall", iters=300, seed=7)
    assert a == b


def test_mcnemar_identical_predictions_is_one():
    labels = [True, False, True]
    res = ev.mcnemar_test(labels, labels, labels)
    assert res["p_value"] == 1.0
    assert res["a_only"] == 0 and res["b_only"] == 0


def test_mcnemar_detects_one_sided_advantage():
    labels = [True] * 10
    good = [True] * 10
    bad = [False] * 10
    res = ev.mcnemar_test(labels, good, bad)
    assert res["a_only"] == 10
    assert res["b_only"] == 0
    assert res["p_value"] < 0.05


def test_mcnemar_small_disagreement_is_not_significant():
    labels = [True, True, True, False]
    a = [True, True, True, False]
    b = [True, False, True, False]
    res = ev.mcnemar_test(labels, a, b)
    assert res["p_value"] == 1.0      # 只有 1 个不一致样本，谈不上显著


# --------------------------------------------------------------- 新后端
def test_taint_backend_reports_line_number():
    html = "<script>document.write(location.hash);</script>"
    findings = ev.backend_taint(html)
    assert findings and findings[0]["confidence"] == "confirmed"
    assert findings[0]["evidence"]["line"] == 1


def test_hybrid_falls_back_to_heuristic():
    html = "<script>eval(userInput);</script>"
    findings = ev.backend_hybrid(html, {"suspicious_patterns": ["eval("], "forms": []})
    assert findings and findings[0]["confidence"] == "suspected"


def test_evaluate_backend_records_metrics_and_items():
    rows = [
        {"id": "p", "html": "<script>document.write(location.hash);</script>",
         "label": {"has_xss_risk": True}},
        {"id": "n", "html": "<p>静态页面</p>", "label": {"has_xss_risk": False}},
    ]
    rec = ev.evaluate_backend("taint", rows, DATASET)
    assert rec["backend"] == "taint"
    assert rec["metrics"]["tp"] == 1 and rec["metrics"]["tn"] == 1
    assert [i["id"] for i in rec["items"]] == ["p", "n"]


def _workdir():
    """沙箱里系统临时目录可能不可写，测试改用仓库内目录。"""
    path = os.path.join(HERE, "output", "semgrep-test")
    os.makedirs(path, exist_ok=True)
    return path


class _FakeProc:
    def __init__(self, stdout, returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, "", returncode


def test_semgrep_backend_maps_results_back_to_ids(monkeypatch):
    import json as _json
    unit_name = taint.js_units("<script>document.write(location.hash);</script>")[0][0]
    payload = {"results": [{"path": "p__%s" % unit_name}], "errors": []}

    def fake_run(cmd, **kwargs):
        assert "--json" in cmd
        return _FakeProc(_json.dumps(payload))

    monkeypatch.setattr(ev.subprocess, "run", fake_run)
    rows = [
        {"id": "p", "html": "<script>document.write(location.hash);</script>",
         "label": {"has_xss_risk": True, "risk_level": "HIGH"}},
        {"id": "n", "html": "<p>ok</p>", "label": {"has_xss_risk": False, "risk_level": "LOW"}},
    ]
    workdir = _workdir()
    try:
        flags = ev.semgrep_predictions(rows, workdir=workdir)
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
    assert flags["p"] is True
    assert flags["n"] is False


def test_semgrep_missing_binary_raises_backend_unavailable(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(ev.subprocess, "run", boom)
    rows = [{"id": "x", "html": "<script>document.write(location.hash);</script>",
             "label": {"has_xss_risk": True, "risk_level": "HIGH"}}]
    workdir = _workdir()
    try:
        with pytest.raises(ev.BackendUnavailable):
            ev.semgrep_predictions(rows, workdir=workdir)
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
