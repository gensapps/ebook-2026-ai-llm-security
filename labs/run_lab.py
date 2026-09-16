#!/usr/bin/env python3
"""labs end-to-end 러너 — CVE 기반 레드/블루 자기방어 데모. 서로 다른 변수 하나씩만
격리해서 보여주는 두 개의 독립된 비교 모드가 있다.

    python run_lab.py                # 모드 1: RAG on vs off (공유 CVE corpus 의 기여도)
    python run_lab.py --rounds 10
    python run_lab.py --llm          # 모드 2: 블루의 LLM 의미 판단 on vs off (레드 강도는 고정)

API 키·Ollama 없이도 기본 모드는 규칙 기반으로 완전히 실행된다. --llm 모드는 레드를 항상
로컬 Ollama(llama3.2:3b, 안전 정렬이 약한 공격자 쪽 모델)로 변형시켜 두 조건의 공격 강도를
동일하게 고정한 뒤, 블루가 시그니처 매칭에 실패한 이벤트를 Claude(안전 정렬이 강한 방어자
쪽 모델)로 의미 기반 재판단하는지 여부만 바꿔서 그 기여도를 격리 측정한다 — "자동화된
공격에는 자동화된 관측·판단·대응이 필요하다"는 이 책의 핵심 주장을 이 lab 자체에서 실증한다.

두 모드를 동시에 켜지 않는 이유: RAG(corpus 학습)와 LLM(의미 판단)을 한꺼번에 켜면 블루가
거의 모든 공격을 처음부터 잡아버려(포화) 두 메커니즘 중 무엇이 얼마나 기여했는지 알 수
없어진다. 그래서 각 모드는 정확히 하나의 변수만 켰다 껐다 하며 독립적으로 측정한다.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

try:
    from dotenv import load_dotenv
    load_dotenv(BASE.parent / ".env")   # 리포 루트 .env 의 ANTHROPIC_API_KEY 를 프로세스 환경에 로드
except ImportError:
    pass

from orchestrator import run_lab, format_report  # noqa: E402


def ensure_cve_db() -> None:
    db = BASE / "cve_db" / "cve.db"
    if not db.exists():
        print("[setup] CVE DB 없음 → 적재")
        subprocess.run([sys.executable, str(BASE / "cve_db" / "ingest.py")], check=True)


def main() -> int:
    p = argparse.ArgumentParser(description="CVE 기반 레드/블루 자기방어 lab")
    p.add_argument("--rounds", type=int, default=7)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--llm", action="store_true",
                    help="LLM 의미 판단 기여도 비교로 전환(레드=로컬 Ollama, 블루=Claude)")
    args = p.parse_args()

    ensure_cve_db()

    print("\n[레드/블루 자기방어 lab] 표적: 격리 5개 서비스 / 공유 CVE corpus\n")

    if args.llm:
        # 변수 하나만 격리: 레드의 공격 강도(Ollama 변형)는 두 조건에서 동일하게 고정하고,
        # 블루의 LLM 의미 판단만 켰다/껐다 하며 그 기여도만 따로 측정한다.
        base = run_lab(args.rounds, args.seed, use_rag=True, red_llm=True, blue_llm=False)
        print(format_report(base, "규칙 기반 단독 (레드는 Ollama 변형 사용, 블루는 시그니처 매칭만)"))

        aug = run_lab(args.rounds, args.seed, use_rag=True, red_llm=True, blue_llm=True)
        print("\n" + format_report(aug, "규칙 + LLM 의미 판단 (블루가 Claude 로 한 번 더 판단)"))

        gain = (aug[-1]["rate"] - base[-1]["rate"]) * 100
        print(f"\n[결론] 시그니처 매칭에 실패한 이벤트를 Claude 의미 판단으로 한 번 더 보게 하면 "
              f"탐지율이 {gain:+.0f}%p 더 오릅니다. 같은 공격 강도(Ollama 변형)에서 블루 쪽 "
              f"판단 방식만 바꾼 결과입니다 — '자동화된 공격을 자동화된 관측·판단이 따라잡는다'는 "
              f"이 책의 주장을 규칙 기반 corpus self-heal 과는 별개 축에서 보여 줍니다.")
    else:
        on = run_lab(args.rounds, args.seed, use_rag=True, use_llm=False)
        print(format_report(on, "RAG 사용 (공유 CVE corpus 로 self-heal)"))

        off = run_lab(args.rounds, args.seed, use_rag=False, use_llm=False)
        print("\n" + format_report(off, "대조군: RAG 미사용 (블루가 학습 불가)"))

        gain = (on[-1]["rate"] - off[-1]["rate"]) * 100
        print(f"\n[결론] 공유 CVE corpus 기반 self-heal 이 최종 탐지율을 "
              f"{gain:+.0f}%p 끌어올렸습니다. "
              f"코퍼스 없이는 블루가 미지 변형 공격을 학습하지 못합니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
