#!/usr/bin/env python3
"""오케스트레이터(Purple) — 라운드마다 red↔blue 를 붙이고 정량 점수를 매긴다.

한 라운드 = 레드 공격 → 블루 방어·탐지 → 점수화 → 블루 self_heal(공유 CVE DB 로 학습).
라운드가 지날수록 블루의 탐지율이 오르는 곡선을 만든다 = 셀프 방어 고도화의 정량 증거.

use_rag=False 대조군은 블루가 CVE corpus 로 학습하지 못하게 해, 코퍼스가 향상에 기여하는
정도를 실측으로 보여 준다.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agents.blue_agent import BlueAgent   # noqa: E402
from agents.red_agent import RedAgent     # noqa: E402
from target import Target                  # noqa: E402

INITIAL_BLUE_KNOWLEDGE = ["CVE-2021-44228", "CVE-2014-0160"]  # 5개 중 2개만 알고 시작


def run_lab(rounds: int = 7, seed: int = 42, use_rag: bool = True,
            use_llm: bool = False, red_llm: bool | None = None,
            blue_llm: bool | None = None) -> list[dict]:
    """red_llm/blue_llm 을 따로 주면 각각 독립 제어(둘 다 None 이면 use_llm 을 그대로 씀) —
    "동일한 공격 강도에서 블루의 LLM 판단만 켜고 끈 효과"처럼 한 변수만 격리해서 비교할 때 쓴다."""
    rng = random.Random(seed)
    target = Target.default()
    red = RedAgent(target, use_llm=use_llm if red_llm is None else red_llm)
    blue = BlueAgent(INITIAL_BLUE_KNOWLEDGE, use_rag=use_rag,
                      use_llm=use_llm if blue_llm is None else blue_llm)

    history = []
    for r in range(rounds):
        events = red.attack(r, rng)
        actions, missed = blue.defend(events)
        total = len(events)
        detected = len(actions)
        llm_caught = sum(1 for a in actions if a["rationale"] == "llm semantic judgment")
        rate = detected / total if total else 0.0
        learned = blue.self_heal(missed)
        history.append({
            "round": r + 1,
            "total": total,
            "detected": detected,
            "llm_caught": llm_caught,
            "rate": rate,
            "mutated": sum(1 for e in events if e["mutated"]),
            "learned": learned,
            "blue_known": len(blue.known_signatures),
            "deobf": blue.can_deobfuscate,
        })
    return history


def format_report(history: list[dict], title: str) -> str:
    lines = [f"=== {title} ==="]
    lines.append("Day | 탐지 | LLM판단 | 총 | 탐지율 | 변형 | 블루지식 | 탈난독 | 학습")
    for h in history:
        bar = "#" * round(h["rate"] * 20)
        lines.append(
            f"{h['round']:>3} | {h['detected']:>3} | {h.get('llm_caught', 0):>7} | "
            f"{h['total']:>2} | "
            f"{h['rate']*100:5.0f}% {bar:<20} | {h['mutated']:>3} | "
            f"{h['blue_known']:>7} | {'Y' if h['deobf'] else '-':^6} | "
            f"{','.join(h['learned']) or '-'}")
    first, last = history[0]["rate"], history[-1]["rate"]
    lines.append(f"→ 탐지율 {first*100:.0f}% → {last*100:.0f}% "
                 f"(Δ {(last-first)*100:+.0f}%p)")
    return "\n".join(lines)
