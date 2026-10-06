"""Red vs Blue 점수 (ch24 §24.6.3) — 공격 감사와 방어 감사를 대조해 탐지율 산출."""
from __future__ import annotations
import json, os
from pathlib import Path

LOGS = Path(os.environ.get("LAB_LOGS", "./_lab_logs"))


def _load(name):
    p = LOGS / name
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def score(target_map: dict[str, str] | None = None):
    """target_map은 해당 실습에서 기록한 호스트명 → 목적지 IP 매핑입니다."""
    if target_map is None:
        mapping_path = os.environ.get("TARGET_MAP")
        target_map = json.loads(Path(mapping_path).read_text()) if mapping_path else {}
    attack = _load("attack_audit.jsonl")
    defense = _load("defense_audit.jsonl")
    attacked = {target_map.get(a["target"], a["target"]) for a in attack
                if a.get("phase") == "exploit" and a.get("result", {}).get("status") != "denied"}
    observed = {d["conn"]["dst"] for d in defense}
    detected = {d["conn"]["dst"] for d in defense if d["verdict"]["route"] != "pass"}
    from ipaddress import ip_address
    def is_ip(value):
        try:
            ip_address(value)
            return True
        except ValueError:
            return False
    if attacked and observed and any(not is_ip(t) for t in attacked) and any(is_ip(t) for t in observed):
        raise ValueError("호스트명과 IP를 비교하려면 TARGET_MAP 또는 target_map을 지정하세요")
    hits = attacked & detected
    total = len(attacked)
    print("\n=== Red vs Blue Score ===")
    print(f"공격 표적: {total}, 탐지: {len(hits)}  {sorted(hits)}")
    print(f"탐지율: {len(hits) / total:.0%}" if total else "N/A")
    return {"attacked": sorted(attacked), "detected": sorted(hits),
            "rate": (len(hits) / total) if total else None}


if __name__ == "__main__":
    score()
