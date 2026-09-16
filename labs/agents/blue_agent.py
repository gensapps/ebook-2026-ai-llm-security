#!/usr/bin/env python3
"""블루팀 Agent — 레드와 동일한 CVE corpus 를 근거로 탐지·차단하고 스스로 고도화한다.

핵심: 블루는 처음엔 일부 CVE 시그니처만 알고, 난독화도 못 벗긴다. 공격을 놓치면 self_heal 에서
**공유 CVE DB 를 조회(RAG)** 해 놓친 CVE 의 시그니처를 학습하고, 난독화 변형을 처음 본 순간
탈난독화 능력을 켠다. 그래서 라운드가 지날수록 탐지율이 오른다 — 셀프 방어 고도화 루프다.

use_llm=True 면 시그니처 매칭에 실패한 이벤트를 그냥 놓치지 않고, Claude 에게 관측된 페이로드가
공격으로 보이는지 의미 기반으로 한 번 더 판단시킨다("자동화된 공격에는 자동화된 관측·판단·대응이
필요하다"는 이 책의 핵심 주장을 이 lab 자체에서도 실증하기 위함). 방어 판단은 안전 정렬이 강한
Claude 를 쓴다 — 공격자 쪽에 로컬 Ollama 를 쓰는 것(red_agent.py)과 정반대 이유다.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cve_db.ingest import get_one            # noqa: E402
from mcp_servers import security_tools as T   # noqa: E402


class BlueAgent:
    def __init__(self, initial_known_cves: list[str], use_rag: bool = True,
                 use_llm: bool = False):
        self.use_rag = use_rag
        self.use_llm = use_llm
        self.known_signatures: set[str] = set()
        self.can_deobfuscate = False
        for cid in initial_known_cves:
            cve = get_one(cid)
            if cve:
                self.known_signatures.add(
                    " ".join(sorted(cve["attack_pattern"].lower().split())))

    def _observed(self, sig: str) -> str:
        return T.normalize_observed(sig) if self.can_deobfuscate else sig

    def _llm_judge(self, ev: dict) -> bool:
        """(선택) 시그니처 매칭 실패 시 Claude 로 의미 기반 악성 판단. 실패 시 False(미탐)."""
        try:
            import os
            if not os.getenv("ANTHROPIC_API_KEY"):
                return False
            from anthropic import Anthropic
            client = Anthropic()
            msg = client.messages.create(
                model="claude-haiku-4-5", max_tokens=8,
                system=("당신은 보안 모니터링 시스템이다. 알려진 시그니처와 정확히 일치하지 "
                        "않는 관측 트래픽이 주어진다. 이것이 알려진 공격 패턴의 변형(회피 시도)"
                        "인지, 정상 트래픽인지 판단해 'malicious' 또는 'benign' 한 단어로만 답하라."),
                messages=[{"role": "user", "content":
                           f"서비스: {ev['service']}\n관측된 시그니처: {ev['payload_signature']}"}],
            )
            verdict = "".join(b.text for b in msg.content if b.type == "text").strip().lower()
            return "malicious" in verdict
        except Exception:
            return False

    def defend(self, events: list[dict]) -> tuple[list[dict], list[dict]]:
        """공격 이벤트를 관측해 탐지/차단. (탐지된 조치들, 놓친 이벤트들) 반환."""
        actions, missed = [], []
        for ev in events:
            observed = self._observed(ev["payload_signature"])
            if observed in self.known_signatures:
                actions.append(T.block_ip(ev["service"], ev["cve_id"],
                                          rationale="known signature match"))
            elif self.use_llm and self._llm_judge(ev):
                actions.append(T.block_ip(ev["service"], ev["cve_id"],
                                          rationale="llm semantic judgment"))
            else:
                missed.append(ev)
        return actions, missed

    def self_heal(self, missed: list[dict]) -> list[str]:
        """놓친 공격을 공유 CVE DB 로 되짚어 시그니처·탈난독화를 학습한다."""
        learned = []
        for ev in missed:
            if ev["mutated"]:
                self.can_deobfuscate = True     # 난독화를 한 번 보면 벗기는 법을 익힌다
            if not self.use_rag:
                continue                         # RAG 미사용 시 학습 불가(대조군)
            cve = get_one(ev["cve_id"])          # ← 공유 corpus 조회(RAG)
            if cve:
                sig = " ".join(sorted(cve["attack_pattern"].lower().split()))
                if sig not in self.known_signatures:
                    self.known_signatures.add(sig)
                    learned.append(ev["cve_id"])
        return learned
