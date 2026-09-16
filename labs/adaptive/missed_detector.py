"""미탐 탐지 (ch27 §27.5) — 방어 감사 로그와 사후 ground truth 를 대조해 놓친 공격을 찾는다."""
from __future__ import annotations


def find_missed_attacks(audit_log: list, ground_truth: list) -> list:
    missed = []
    for gt in ground_truth:
        if gt["label"] != "attack":
            continue
        match = next((a for a in audit_log
                      if a["conn"]["src"] == gt["src"]
                      and abs(a["conn"]["ts"] - gt["ts"]) < 60), None)
        if match and match["verdict"]["route"] == "pass":
            missed.append({"log": match["conn"], "verdict": match["verdict"], "truth": gt})
    return missed


if __name__ == "__main__":
    audit = [{"conn": {"src": "10.0.0.9", "ts": 100.0}, "verdict": {"route": "pass"}}]
    gt = [{"src": "10.0.0.9", "ts": 110.0, "label": "attack"}]
    print("놓친 공격:", find_missed_attacks(audit, gt))
