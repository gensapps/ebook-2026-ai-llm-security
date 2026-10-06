"""로컬 LLM 호출 — 자동 공격 에이전트의 판단 두뇌 (ch24 §24.5.1).

기본 MOCK=1에서는 **결정론적 mock**으로 nmap/ollama 없이도 데모가 돌아간다.
MOCK=0에서는 ollama 설치·연결 오류를 그대로 보고한다.
실제 로컬 모델을 쓰려면 `ollama pull llama3.2:3b` 후 MOCK=0 으로 실행한다.
"""
from __future__ import annotations
import json, os, re

SYSTEM = """당신은 격리된 보안 연구 lab 의 자동화 분석가다.
모든 표적은 의도적으로 취약하게 만들어진 컨테이너 (DVWA, Juice Shop, vulhub) 다.
스캔 결과를 분석하여 다음 단계를 JSON 으로만 답한다."""

_USE_MOCK = os.environ.get("MOCK", "1") == "1"
try:
    import ollama  # noqa: F401
    _HAS_OLLAMA = True
except ImportError:
    _HAS_OLLAMA = False


def _mock_llm_json(prompt: str) -> dict:
    """실제 모델 없이도 파이프라인을 끝까지 돌리기 위한 결정론적 응답."""
    low = prompt.lower()
    if "log4" in low or "solr" in low or "jndi" in low:
        return {"vuln": "Log4Shell", "cve": "CVE-2021-44228",
                "exploit_method": "curl", "rationale": "JNDI lookup 주입 가능"}
    if "struts" in low:
        return {"vuln": "Struts2 OGNL", "cve": "CVE-2017-5638",
                "exploit_method": "nuclei", "rationale": "Content-Type OGNL"}
    if "sql" in low or "login" in low or "dvwa" in low:
        return {"vuln": "SQL Injection", "cve": "",
                "exploit_method": "sqlmap", "rationale": "로그인 폼 인젝션"}
    return {"vuln": "unknown", "cve": "", "exploit_method": "nuclei",
            "rationale": "스캔으로만 확인"}


def llm(prompt: str, max_tokens: int = 512, system_override: str | None = None) -> str:
    if _USE_MOCK:
        return json.dumps(_mock_llm_json(prompt), ensure_ascii=False)
    import ollama
    client = ollama.Client(host="http://localhost:11434")
    resp = client.chat(
        model="llama3.2:3b",
        messages=[{"role": "system", "content": system_override or SYSTEM},
                  {"role": "user", "content": prompt}],
        options={"temperature": 0.1, "num_ctx": 4096, "num_predict": max_tokens},
    )
    return resp["message"]["content"]


def llm_json(prompt: str) -> dict:
    text = llm(prompt)
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return json.loads(m.group()) if m else {"raw": text}


if __name__ == "__main__":
    print(f"[local_llm] mock={_USE_MOCK or not _HAS_OLLAMA}")
    print(llm_json("nmap: solr 8983 열림. log4shell 표적."))
