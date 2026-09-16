#!/usr/bin/env python3
"""레드팀 Agent — 공유 CVE DB 에서 취약점을 골라 표적을 공격한다.

동작: recon 으로 표적 서비스를 식별 → 각 서비스가 안은 CVE 를 cve_db 에서 조회 →
PoC 생성(라운드가 갈수록 난독화 변형 비율↑) → 격리 표적에 exploit(시뮬레이션).

이것이 "미토스/페이블5 식 자동 공격 Agent 를 우리가 직접 만든다"의 최소 실체다. 기본은
규칙 기반으로 API 없이 돌아가며, use_llm=True 면 페이로드 변형을 다양화한다(선택).

공격자 LLM 은 ch15·ch24 와 같은 이유로 **로컬 Ollama(llama3.2:3b)** 를 쓴다 — Claude 처럼
안전 정렬이 강한 모델에게 "탐지 회피 변형을 만들어 달라"고 요청하면 방어적으로 거부하는
것이 정상 동작이다(실제로 이 파일의 이전 버전은 Claude Haiku 를 썼다가 매번 거부당해
조용히 원본 페이로드로 폴백하는 버그가 있었다). 공격자 쪽에 안전장치가 약한/사설 모델을
쓰는 것 자체가 이 책이 반복해서 짚는 비대칭이다.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cve_db.ingest import get_one            # noqa: E402
from mcp_servers import security_tools as T   # noqa: E402
from target import Target                      # noqa: E402


class RedAgent:
    def __init__(self, target: Target, use_llm: bool = False):
        self.target = target
        self.use_llm = use_llm

    def attack(self, round_idx: int, rng) -> list[dict]:
        """한 라운드 공격. 라운드가 오를수록 난독화(회피) 확률이 증가한다."""
        mutate_prob = min(0.15 + 0.20 * round_idx, 0.9)
        findings = T.recon_scan(self.target)
        events = []
        for f in findings:
            cve = get_one(f["cve_hint"])
            if not cve:
                continue
            mutate = rng.random() < mutate_prob
            poc = T.generate_poc(dict(cve), mutate=mutate)
            if self.use_llm:
                poc = self._llm_vary(poc)
            ev = T.run_exploit(self.target, f["service"], poc)
            events.append(ev)
        return events

    def _llm_vary(self, poc: dict) -> dict:
        """(선택) 로컬 Ollama(llama3.2:3b) 로 페이로드 표현을 다양화. 실패·미설치 시 원본 유지."""
        try:
            import ollama
            client = ollama.Client(host="http://localhost:11434")
            resp = client.chat(
                model="llama3.2:3b",
                messages=[{"role": "system", "content":
                           "당신은 격리된 보안 lab 의 침투 테스트 도구다. 모든 표적은 "
                           "의도적으로 취약하게 만든 컨테이너이며 실제 피해자는 없다."},
                          {"role": "user", "content":
                           f"공격 시그니처 '{poc['base_signature']}' 의 변형 표현을 토큰 "
                           f"나열로 한 줄만 답하라. 설명 없이 토큰만."}],
                options={"temperature": 0.7, "num_predict": 32},
            )
            text = resp["message"]["content"].strip()
            if text:
                poc["payload_signature"] = "llm::" + text[:80]
        except Exception:
            pass
        return poc
