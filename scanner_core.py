import json
import re
import os
import requests
from bs4 import BeautifulSoup

# 这里放你的API Key
API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-flash"


def extract_features(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")

    forms = []
    for form in soup.find_all("form"):
        forms.append({
            "action": form.get("action", ""),
            "method": (form.get("method") or "GET").upper(),
            "inputs": [
                {"name": i.get("name", ""), "type": i.get("type", "text")}
                for i in form.find_all("input")
            ],
        })

    script_blocks = [s.get_text() for s in soup.find_all("script") if s.get_text().strip()]
    inline_events = re.findall(r'on\w+\s*=\s*["\'][^"\']{0,200}["\']', html, re.IGNORECASE)
    suspicious_patterns = re.findall(
        r'(?:innerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|\.src\s*=)',
        html, re.IGNORECASE
    )

    return {
        "forms": forms,
        "script_blocks": script_blocks[:5],
        "inline_events": inline_events[:10],
        "suspicious_patterns": suspicious_patterns[:20],
    }


def build_prompt(source: str, features: dict) -> str:
    return f"""你是一个 Web 安全分析助手。请根据以下信息判断页面中可能存在的 XSS 和 SQL 注入风险点。

来源：{source}

页面特征：
{json.dumps(features, ensure_ascii=False, indent=2)}

请按以下要求输出 JSON 数组，每个元素包含：
- vulnerability_type：XSS / SQL_INJECTION / INPUT_REFLECTION / UNSAFE_SCRIPT / OTHER
- risk_level：LOW / MEDIUM / HIGH
- location：风险位置
- reason：判断依据
- fix_suggestion：修复建议

不要生成真实攻击载荷。如果没有风险，返回空数组。"""


def call_llm(prompt: str) -> dict:
    if not API_KEY:
        raise Exception("请先设置 DEEPSEEK_API_KEY 环境变量")
    resp = requests.post(
        API_URL,
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.3},
        timeout=60,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"].strip()
    for prefix in ["```json", "```"]:
        if content.startswith(prefix):
            content = content[len(prefix):].strip()
    if content.endswith("```"):
        content = content[:-3].strip()
    try:
        return json.loads(content)
    except Exception:
        return {"raw_analysis": content}
