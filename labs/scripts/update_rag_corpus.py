"""RAG corpus 일일 갱신 (ch27 §27.3) — 전날 CVE 를 NVD 에서 받아 ChromaDB 에 upsert.

MOCK=1(기본) 또는 chromadb/네트워크가 없으면, 내장 시드 CVE 를 로컬 JSON corpus 에
적재하는 것으로 폴백해 파이프라인을 시연한다. cron 예: 0 3 * * *
"""
from __future__ import annotations
import json
import os
from datetime import date, timedelta
from pathlib import Path

_USE_MOCK = os.environ.get("MOCK", "1") == "1"
CORPUS_JSON = Path(os.environ.get("LAB_LOGS", "temp/lab_logs")) / "rag_corpus.json"

_SEED = [
    {"id": "CVE-2021-44228", "desc": "Apache Log4j2 JNDI RCE (Log4Shell)", "severity": 10.0},
    {"id": "CVE-2017-5638", "desc": "Apache Struts2 Content-Type OGNL RCE", "severity": 10.0},
]


def _upsert_local(rows: list) -> int:
    CORPUS_JSON.parent.mkdir(parents=True, exist_ok=True)
    cur = {}
    if CORPUS_JSON.exists():
        cur = {r["id"]: r for r in json.loads(CORPUS_JSON.read_text())}
    for r in rows:
        cur[r["id"]] = r
    CORPUS_JSON.write_text(json.dumps(list(cur.values()), ensure_ascii=False, indent=1))
    return len(rows)


def update_nvd(target_date: date) -> int:
    if _USE_MOCK:
        return _upsert_local([{**r, "source": "seed", "pub_date": str(target_date)} for r in _SEED])
    import requests, chromadb
    col = chromadb.PersistentClient(path="/data/chroma").get_or_create_collection("security_kb")
    data = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"pubStartDate": f"{target_date}T00:00:00.000",
                "pubEndDate": f"{target_date}T23:59:59.999", "resultsPerPage": 200},
        timeout=30).json()
    added = 0
    for v in data.get("vulnerabilities", []):
        cve = v["cve"]
        desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
        cvss = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        col.upsert(documents=[f'{cve["id"]}: {desc}'], ids=[cve["id"]],
                   metadatas=[{"cve_id": cve["id"], "severity": float(cvss.get("baseScore", 0)),
                               "source": "nvd", "pub_date": str(target_date)}])
        added += 1
    return added


if __name__ == "__main__":
    n = update_nvd(date.today() - timedelta(days=1))
    print(f"corpus 갱신: {n} 건 → {CORPUS_JSON}")
