"""긴급 정지 스위치 (ch26 §26.3). STOP 파일이 보이면 즉시 종료."""
from __future__ import annotations
import os
from pathlib import Path

KILL_FILE = Path(os.environ.get("KILL_FILE", "/tmp/STOP"))


def check_kill_switch():
    """매 단계마다 호출. STOP 파일이 있으면 즉시 종료."""
    if KILL_FILE.exists():
        print(f"[KILL] {KILL_FILE} 감지 — 즉시 중단")
        raise SystemExit(0)


if __name__ == "__main__":
    check_kill_switch()
    print("STOP 파일 없음 — 정상 진행")
