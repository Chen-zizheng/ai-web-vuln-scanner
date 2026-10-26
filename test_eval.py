# -*- coding: utf-8 -*-
"""评测脚本的单元测试：指标计算、数据集完整性、基线后端的行为约定。"""
import json
import os

import pytest

import eval as ev

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "eval", "dataset.jsonl")


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
def test_dataset_exists_and_is_balanced():
    rows = [json.loads(l) for l in open(DATASET, encoding="utf-8") if l.strip()]
    assert len(rows) == 50
    pos = sum(1 for r in rows if r["label"]["has_xss_risk"])
    assert pos == 22
    assert len(rows) - pos == 28


def test_dataset_ids_unique_and_fields_present():
    rows = [json.loads(l) for l in open(DATASET, encoding="utf-8") if l.strip()]
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids))
    for r in rows:
        assert r["html"].strip()
        assert isinstance(r["label"]["has_xss_risk"], bool)
        assert r["label"]["risk_level"] in ("LOW", "MEDIUM", "HIGH")


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
