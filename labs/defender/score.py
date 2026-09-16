"""Red vs Blue 점수 (ch24 §24.6.3) — 공격 감사와 방어 감사를 대조해 탐지율 산출."""
from __future__ import annotations
import json, os
from pathlib import Path

LOGS = Path(os.environ.get("LAB_LOGS", "./_lab_logs"))


def _load(name):
    p = LOGS / name
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def score():
    attack = _load("attack_audit.jsonl")
    defense = _load("defense_audit.jsonl")
    attacked = {a["target"] for a in attack if a.get("phase") == "exploit"}
    detected = {d["conn"]["dst"] for d in defense if d["verdict"]["route"] != "pass"}
    hits = attacked & detected
    total = len(attacked)
    print("\n=== Red vs Blue Score ===")
    print(f"공격 표적: {total}, 탐지: {len(hits)}  {sorted(hits)}")
    print(f"탐지율: {len(hits) / total:.0%}" if total else "N/A")
    return {"attacked": sorted(attacked), "detected": sorted(hits),
            "rate": (len(hits) / total) if total else None}


if __name__ == "__main__":
    score()
