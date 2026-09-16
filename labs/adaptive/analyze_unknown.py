"""미지 로그의 RAG+LLM 분석 (ch27 §27.4). ATT&CK whitelist·schema 검증 포함.

anthropic/chromadb 가 없거나 MOCK=1 이면, 공유 corpus 대신 내장 시드로 RAG 를 흉내내고
LLM 판정을 규칙 기반 mock 으로 대체한다. whitelist·schema 가드는 mock 에서도 동일 적용.
"""
from __future__ import annotations
import json
import os

_USE_MOCK = os.environ.get("MOCK", "1") == "1"

# ATT&CK 최신 버전에서 정의된 ID 만 허용(whitelist). LLM 이 만든 가짜 T-ID 를 걸러낸다.
ALLOWED_ATTACK_IDS = {
    "T1190", "T1078", "T1110", "T1059", "T1486",
    "T1566", "T1071", "T1053", "T1003", "T1499",
}

ANALYSIS_SCHEMA = {
    "required": ["category", "severity", "attack_id", "citation", "reasoning"],
    "category_enum": ["BENIGN", "SQLi", "XSS", "CMDi", "RCE", "SSRF", "Brute", "Other"],
}

_MOCK_CORPUS = {
    "CVE-2021-44228": ("T1190", "RCE", "jndi:ldap lookup 으로 원격 코드 실행"),
    "CVE-2017-5638":  ("T1190", "RCE", "Struts2 Content-Type OGNL 주입"),
    "sqli":           ("T1190", "SQLi", "' OR 1=1 / UNION SELECT 패턴"),
}


def _validate(result: dict) -> bool:
    if any(k not in result for k in ANALYSIS_SCHEMA["required"]):
        return False
    if result["category"] not in ANALYSIS_SCHEMA["category_enum"]:
        return False
    return isinstance(result["severity"], int) and 1 <= result["severity"] <= 5


def _mock_analyze(payload: str) -> dict:
    low = payload.lower()
    if "jndi" in low or "log4" in low:
        cid, cat = "CVE-2021-44228", "RCE"
    elif "ognl" in low or "struts" in low or "%{" in low:
        cid, cat = "CVE-2017-5638", "RCE"
    elif "union select" in low or "or 1=1" in low:
        cid, cat = "sqli", "SQLi"
    else:
        return {"category": "BENIGN", "severity": 1, "attack_id": None,
                "citation": [], "reasoning": "매칭 자료 없음"}
    aid, _, note = _MOCK_CORPUS[cid]
    return {"category": cat, "severity": 5, "attack_id": aid,
            "citation": [cid], "reasoning": f"[{cid}] {note} 와 동일 패턴"}


def analyze_unknown(log: dict, top_k: int = 5) -> dict:
    payload = log.get("payload", "")
    if _USE_MOCK:
        result = _mock_analyze(payload)
    else:
        import anthropic, chromadb  # noqa: F401
        col = chromadb.PersistentClient(path="/data/chroma").get_collection("security_kb")
        hits = col.query(query_texts=[payload], n_results=top_k)
        ctx = "\n".join(f"[{m.get('cve_id') or m.get('attack_id') or m['source']}] {d}"
                        for d, m in zip(hits["documents"][0], hits["metadatas"][0])) or "(참고 자료 없음)"
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model="claude-opus-5", max_tokens=600, thinking={"type": "disabled"},
            system="당신은 SOC senior analyst. 참고 자료 [ID] 가 있을 때만 attack_id 를 채우고, "
                   "없으면 null. citation 은 참고 자료 ID 목록.\n\n참고 자료:\n" + ctx,
            messages=[{"role": "user", "content": f"로그 분석:\n{json.dumps(log)}"}])
        try:
            result = json.loads("".join(b.text for b in resp.content if b.type == "text"))
        except json.JSONDecodeError as e:
            return {"category": "BENIGN", "severity": 1, "attack_id": None,
                    "citation": [], "reasoning": f"parse_error: {e}"}

    if not _validate(result):
        return {"category": "BENIGN", "severity": 1, "attack_id": None,
                "citation": [], "reasoning": "schema_violation"}
    # ATT&CK whitelist — LLM 이 만든 가짜 T-ID 거부
    if result.get("attack_id") and result["attack_id"] not in ALLOWED_ATTACK_IDS:
        result["attack_id"] = None
        result["reasoning"] += " [whitelist violation - attack_id stripped]"
    return result


if __name__ == "__main__":
    for p in ("${jndi:ldap://x}", "' OR 1=1--", "GET /index.html"):
        print(p[:20], "→", analyze_unknown({"payload": p}))
