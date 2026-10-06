"""labs/ 전 챕터 데모를 mock 모드로 한 번에 실행해 각 모듈이 도는지 확인한다.

배포 모듈의 mock 실행 경로를 검사하는 스모크 러너. 실제 인프라 통합 검증과는 구분한다.
    python labs/run_all_demos.py
CI 나 릴리스 전 점검에 쓴다. 실제 인프라(nmap·ollama·CTFd·Zeek) 는 필요 없다.
"""
from __future__ import annotations
import os
import runpy
import sys
import traceback
from pathlib import Path

os.environ["MOCK"] = "1"  # 외부 환경의 MOCK=0을 상속해 실제 공격을 실행하지 않는다
os.environ["DRY_RUN"] = "1"
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

DEMOS = [
    ("ch13 SecurityAssistant CLI", "security_assistant_lab.py"),
    ("ch14 MCP gateway", "mcp_gateway/gateway.py"),
    ("ch14 SIEM MCP server", "mcp_gateway/siem_mcp_server.py"),
    ("ch24 local_llm", "attacker/agent/local_llm.py"),
    ("ch24 recon", "attacker/agent/recon.py"),
    ("ch24 auto_pentest", "attacker/agent/auto_pentest.py"),
    ("ch24 parse_zeek", "defender/parse_zeek.py"),
    ("ch24 auto_defend", "defender/auto_defend.py"),
    ("ch24 score", "defender/score.py"),
    ("ch25 ctf benchmark", "ctf_agent/benchmark.py"),
    ("ch25 setup_challenges", "ctf_platform/setup_challenges.py"),
    ("ch26 guardrails", "attacker/agent/guardrails.py"),
    ("ch26 rate_limit", "attacker/agent/rate_limit.py"),
    ("ch26 kill_switch", "attacker/agent/kill_switch.py"),
    ("ch26 tests", "tests/test_guardrails.py"),
    ("ch27 analyze_unknown", "adaptive/analyze_unknown.py"),
    ("ch27 drift_sentinel", "adaptive/drift_sentinel.py"),
    ("ch27 missed_detector", "adaptive/missed_detector.py"),
    ("ch27 incremental_train", "adaptive/incremental_train.py"),
    ("ch27 safe_block", "adaptive/safe_block.py"),
    ("ch27 update_rag_corpus", "scripts/update_rag_corpus.py"),
]


def main() -> int:
    ok = fail = 0
    from contextlib import redirect_stdout
    import io
    for label, rel in DEMOS:
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                runpy.run_path(str(ROOT / rel), run_name="__main__")
            print(f"  OK   {label:<28} ({rel})")
            ok += 1
        except SystemExit as exc:
            if exc.code in (None, 0):
                print(f"  OK   {label:<28} ({rel})")
                ok += 1
            else:
                print(f"  FAIL {label:<28} ({rel}) exit={exc.code}")
                fail += 1
        except Exception:
            print(f"  FAIL {label:<28} ({rel})")
            traceback.print_exc()
            fail += 1
    print(f"\n총 {ok+fail} / OK {ok} / FAIL {fail}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
