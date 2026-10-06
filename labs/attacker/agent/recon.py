"""정찰 — nmap + nuclei (ch24 §24.5.2).

본문 스니펫은 nmap/nuclei 바이너리를 subprocess 로 부른다. 이 파일은 바이너리가
기본 MOCK=1에서는 **4개 모듈 데모 표적의 mock 스캔 결과**를 반환한다.
MOCK=0에서 바이너리가 없으면 실패하며 합성 결과로 바꾸지 않는다.
실제 스캔을 하려면 nmap·nuclei 를 설치하고 MOCK=0 으로 실행한다.
"""
from __future__ import annotations
import json, os, shutil, subprocess
import xml.etree.ElementTree as ET

_USE_MOCK = os.environ.get("MOCK", "1") == "1"

# 모듈 데모 표적 → 대표 서비스/취약점 (Docker 인프라와는 별도 예제)
_MOCK_SERVICES = {
    "tgt-dvwa":      [{"port": "80", "service": "http", "product": "Apache", "version": "2.4"}],
    "tgt-juice":     [{"port": "3000", "service": "http", "product": "Node", "version": "18"}],
    "tgt-log4shell": [{"port": "8983", "service": "http", "product": "Solr", "version": "8.11.0"}],
    "tgt-struts":    [{"port": "8080", "service": "http", "product": "Struts", "version": "2.5.10"}],
}
_MOCK_NUCLEI = {
    "tgt-log4shell": [{"template-id": "CVE-2021-44228", "info": {"severity": "critical"}}],
    "tgt-struts":    [{"template-id": "CVE-2017-5638", "info": {"severity": "critical"}}],
    "tgt-dvwa":      [{"template-id": "sqli-detect", "info": {"severity": "high"}}],
}


def parse_nmap_xml(xml: str) -> dict:
    root = ET.fromstring(xml)
    services = []
    for host in root.findall("host"):
        for port in host.iter("port"):
            svc = port.find("service")
            services.append({
                "port": port.get("portid"),
                "service": svc.get("name") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
    return {"services": services}


def nmap_scan(target: str) -> dict:
    if _USE_MOCK:
        return {"services": _MOCK_SERVICES.get(target, [])}
    out = subprocess.check_output(
        ["nmap", "-sV", "-sC", "--script=vuln", "-oX", "-", target],
        timeout=300, text=True)
    return parse_nmap_xml(out)


def nuclei_scan(target: str) -> list:
    """nuclei = 알려진 취약점 5000+ 자동 검증. 방어자 도구로도 사용."""
    if _USE_MOCK:
        return _MOCK_NUCLEI.get(target, [])
    out = subprocess.check_output(
        ["nuclei", "-u", f"http://{target}", "-jsonl", "-silent",
         "-tags", "cve,sqli,xss,rce", "-rl", "10"],
        timeout=600, text=True, stderr=subprocess.DEVNULL)
    return [json.loads(l) for l in out.splitlines() if l.strip()]


if __name__ == "__main__":
    for t in ("tgt-log4shell", "tgt-dvwa"):
        print(t, nmap_scan(t), nuclei_scan(t))
