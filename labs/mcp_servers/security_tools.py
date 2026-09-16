#!/usr/bin/env python3
"""보안 도구 계층 — red/blue Agent 가 호출하는 함수들.

실제 lab 에서는 이들이 MCP 서버(recon·exploit·defense)로 노출되고 권한이 분리된다(ch29).
여기서는 API·컨테이너 없이 돌도록 도구를 함수로 구현한다. 각 함수는 실제 도구가 하는 일을
모사하되, 부작용(실제 exploit·차단)은 격리를 위해 시뮬레이션으로 기록만 한다.

권한 등급(실제 MCP 서버에서 분리되는 경계):
  - recon_*   : read-only  (누구나)
  - exploit_* : write/위험  (sandbox 격리 네트워크 전용)
  - defense_* : write       (HITL 게이트 대상)
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from target import Service, Target  # noqa: E402


# ── recon (read-only) ─────────────────────────────────────────────
def recon_scan(target: Target) -> list[dict]:
    """nmap/nuclei 모사 — 서비스 배너에서 취약점 후보를 식별한다."""
    findings = []
    for s in target.services:
        findings.append({"service": s.name, "port": s.port,
                         "banner": s.banner, "cve_hint": s.cve_id})
    return findings


# ── exploit (위험·격리 전용) ──────────────────────────────────────
def _signature(cve: dict) -> str:
    """CVE 의 attack_pattern 에서 탐지 시그니처(정규화 토큰)를 만든다."""
    return " ".join(sorted(cve["attack_pattern"].lower().split()))


def obfuscate(signature: str) -> str:
    """페이로드 난독화 모사 — 시그니처를 변형해 단순 매칭을 우회한다."""
    h = hashlib.sha1(signature.encode()).hexdigest()[:6]
    return f"obf::{h}::" + signature.replace(" ", "_")


def generate_poc(cve: dict, mutate: bool = False) -> dict:
    """CVE 를 근거로 PoC(공격 페이로드)를 만든다. 실제로는 sqlmap/curl JNDI 등.

    mutate=True 면 난독화된 변형 페이로드를 만든다(탐지 회피).
    """
    sig = _signature(cve)
    payload_sig = obfuscate(sig) if mutate else sig
    return {"cve_id": cve["id"], "base_signature": sig,
            "payload_signature": payload_sig, "mutated": mutate}


def run_exploit(target: Target, service_name: str, poc: dict) -> dict:
    """격리 표적에 PoC 를 던진다(시뮬레이션). 실제 exploit 은 실행하지 않는다."""
    svc: Service | None = target.by_name(service_name)
    hit = bool(svc and svc.cve_id == poc["cve_id"])
    return {"service": service_name, "cve_id": poc["cve_id"],
            "payload_signature": poc["payload_signature"],
            "base_signature": poc["base_signature"],
            "mutated": poc["mutated"],
            "status": "simulated", "reached_vuln": hit}


# ── defense (HITL 대상) ───────────────────────────────────────────
def normalize_observed(payload_signature: str) -> str:
    """블루가 관측한 페이로드 시그니처를 정규화한다. 난독화 접두는 벗겨 본다."""
    if payload_signature.startswith("obf::"):
        # obf::<hash>::<tokens_with_underscore>
        parts = payload_signature.split("::", 2)
        if len(parts) == 3:
            return parts[2].replace("_", " ")
    return payload_signature


def block_ip(service: str, cve_id: str, rationale: str) -> dict:
    """차단 조치(시뮬레이션). 실제 lab 에서는 iptables/WAF 룰이며 HITL 게이트를 거친다."""
    return {"action": "block", "service": service, "cve_id": cve_id,
            "rationale": rationale, "status": "simulated"}
