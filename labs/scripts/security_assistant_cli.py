"""SecurityAssistant CLI (ch13 §13.3). 로그 한 건을 받아 분석 결과 JSON 을 출력한다.

lab 판 security_assistant_lab.SecurityAssistant 를 쓰므로 API 키·pickle·ChromaDB 없이도
돌아간다(mock). --ml-model을 지정하면 RF 산출물을 실제로 읽는다.
RAG·LLM 연결은 ch13 노트북에서 별도로 실행한다. 외부 시스템 차단은 실행하지 않는다.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from security_assistant_lab import SecurityAssistant


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True, help="JSON 문자열 또는 .json 파일 경로")
    p.add_argument("--ml-model", default=None)
    p.add_argument("--chroma", default="/data/chroma")
    p.add_argument("--execute", action="store_false", dest="dry_run", default=True,
                   help="모의 실행 모드(외부 차단 어댑터 없음)")
    args = p.parse_args()

    log = json.load(open(args.log)) if args.log.endswith(".json") else json.loads(args.log)
    a = SecurityAssistant(args.ml_model, args.chroma,
                          os.environ.get("ANTHROPIC_API_KEY"), args.dry_run)
    print(json.dumps(a.analyze(log), indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
