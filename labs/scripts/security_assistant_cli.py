"""SecurityAssistant CLI (ch13 §13.3). 로그 한 건을 받아 분석 결과 JSON 을 출력한다.

lab 판 security_assistant_lab.SecurityAssistant 를 쓰므로 API 키·pickle·ChromaDB 없이도
돌아간다(mock). 실제 통합본을 쓰려면 ch13 노트북의 SecurityAssistant 를 임포트한다.
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
    p.add_argument("--ml-model", default="models/nsl_kdd_rf.pickle")
    p.add_argument("--chroma", default="/data/chroma")
    p.add_argument("--execute", action="store_false", dest="dry_run", default=True,
                   help="실제 차단 실행(기본은 dry-run)")
    args = p.parse_args()

    log = json.load(open(args.log)) if args.log.endswith(".json") else json.loads(args.log)
    a = SecurityAssistant(args.ml_model, args.chroma,
                          os.environ.get("ANTHROPIC_API_KEY"), args.dry_run)
    print(json.dumps(a.analyze(log), indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
