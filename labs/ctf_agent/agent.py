"""CTF 자동 풀이 에이전트 (ch25 §25.4.3) — 분류 → 전략 실행 → flag 추출 → 제출."""
from __future__ import annotations
import re
import time

try:
    from .classify import classify_challenge
    from .dispatch import DISPATCH
except ImportError:
    import sys as _sys, pathlib as _pl
    _sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
    from classify import classify_challenge
    from dispatch import DISPATCH

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)
MAX_ATTEMPTS = 5


def _extract_target(description: str) -> str:
    m = re.search(r"https?://[\w.\-:/]+", description)
    if m:
        return m.group().rstrip(".,;:")
    m2 = re.search(r"\.?/[\w.\-/]+\.\w+", description)   # 파일 경로(forensics)
    return m2.group() if m2 else "http://chall-web"


def solve_and_submit(client, challenge_summary: dict) -> dict:
    detail = client.get_challenge_detail(challenge_summary["id"])
    category = classify_challenge(detail["name"], detail["description"], detail.get("category", ""))
    strategy = DISPATCH.get(category)
    if strategy is None:
        return {"status": "skipped", "category": category,
                "reason": "no automated strategy (misc/pwn/rev)"}
    target = _extract_target(detail["description"])
    for attempt in range(1, MAX_ATTEMPTS + 1):
        result = strategy(target)
        evidence = result.get("evidence", "") + result.get("metadata", "")
        match = FLAG_PATTERN.search(evidence)
        if match:
            verdict = client.submit_flag(challenge_summary["id"], match.group())
            return {"status": verdict["status"], "flag": match.group(),
                    "attempts": attempt, "ctfd_message": verdict.get("message")}
        time.sleep(0.05)   # rate limit — ch26 §26.3.4 와 동일 원칙
    return {"status": "failed", "attempts": MAX_ATTEMPTS}


if __name__ == "__main__":
    from ctfd_client import get_client
    c = get_client()
    for ch in c.list_challenges():
        print(ch["name"], "→", solve_and_submit(c, ch))
