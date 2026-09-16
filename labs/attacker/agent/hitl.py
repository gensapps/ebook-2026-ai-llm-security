"""Human-in-the-Loop 승인 게이트 (ch26 §26.3). 위험 단계는 사람 승인."""
from __future__ import annotations
import sys

AUTO_MODE = "--auto" in sys.argv


def require_approval(action: str, details: dict) -> bool:
    """위험 단계는 stdin 으로 사람 승인. --auto 면 자동 승인."""
    if AUTO_MODE:
        return True
    print("\n=== HITL 승인 필요 ===")
    print(f"  action: {action}")
    print(f"  details: {details}")
    try:
        ans = input("승인? (yes/no): ").strip().lower()
    except EOFError:      # 비대화 실행(파이프) 시 안전하게 거부
        return False
    return ans == "yes"


if __name__ == "__main__":
    ok = require_approval("exploit", {"target": "tgt-dvwa", "method": "sqlmap"})
    print("승인됨" if ok else "거부/비대화")
