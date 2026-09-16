"""CTF 벤치마크 (ch25 §25.5) — 전체 챌린지에 에이전트를 돌려 카테고리별 해결률 집계."""
from __future__ import annotations
from collections import defaultdict

try:
    from .agent import solve_and_submit
    from .ctfd_client import get_client
except ImportError:
    import sys as _sys, pathlib as _pl
    _sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
    from agent import solve_and_submit
    from ctfd_client import get_client


def run_benchmark(client) -> dict:
    challenges = client.list_challenges()
    results = [solve_and_submit(client, c) for c in challenges]
    solved = sum(1 for r in results if r["status"] == "correct")
    by_cat = defaultdict(lambda: {"total": 0, "solved": 0})
    for c, r in zip(challenges, results):
        cat = c.get("category", "unknown")
        by_cat[cat]["total"] += 1
        if r["status"] == "correct":
            by_cat[cat]["solved"] += 1
    return {"total": len(challenges), "solved": solved,
            "solve_rate": solved / len(challenges) if challenges else 0,
            "by_category": dict(by_cat)}


if __name__ == "__main__":
    import json
    print(json.dumps(run_benchmark(get_client()), ensure_ascii=False, indent=1))
