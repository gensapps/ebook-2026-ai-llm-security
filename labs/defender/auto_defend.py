"""자동 방어 — Zeek flow 를 SecurityAssistant 로 분석 (ch24 §24.6.2).

ch13 SecurityAssistant(lab 판) 를 재사용해 각 flow 를 판정하고 감사 로그를 남긴다.
"""
from __future__ import annotations
import json, os, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # labs/ 를 경로에
from security_assistant_lab import SecurityAssistant

try:
    from .parse_zeek import stream_conn_log
except ImportError:
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from parse_zeek import stream_conn_log

LOG = Path(os.environ.get("LAB_LOGS", "temp/lab_logs")) / "defense_audit.jsonl"
assistant = SecurityAssistant(dry_run=True)


def audit(event: dict):
    event["ts"] = time.time()
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def run_defender():
    print("[Defender] Zeek conn.log 분석 시작")
    detections = 0
    for conn in stream_conn_log():
        event = {
            "src": conn["src"], "dst": conn["dst"],
            "method": conn.get("service", ""),
            "url": f"{conn['service']}:{conn['dst_port']}",
            "ua": "", "status": 200,
            "duration": conn["duration"], "bytes": conn["orig_bytes"],
        }
        result = assistant.analyze(event)
        audit({"conn": conn, "verdict": result})
        if result["route"] != "pass":
            detections += 1
            print(f"  [DETECT] {conn['src']}→{conn['dst']} "
                  f"route={result['route']} ml={result.get('ml', 0):.2f}")
    print(f"[Defender] 탐지 {detections} 건")


if __name__ == "__main__":
    run_defender()
