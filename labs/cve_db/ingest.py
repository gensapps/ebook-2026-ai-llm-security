#!/usr/bin/env python3
"""CVE DB 적재·검색 (labs 트랙 — red/blue 자기방어의 공통 지식베이스)

표준 라이브러리(sqlite3) 만으로 동작한다. 외부 API·패키지 없이 즉시 실행 가능하다.
레드팀 Agent 는 이 DB 에서 취약점을 골라 PoC 를 만들고, 블루팀 Agent 는 동일 DB 를 근거로
탐지·차단한다. 즉 이 파일이 "레드와 블루가 같은 CVE corpus 를 공유한다"는 폐루프의 뿌리다.

사용:
    python ingest.py                     # seed → SQLite 적재 (labs/cve_db/cve.db)
    python ingest.py --search log4j      # 키워드 검색
    python ingest.py --list              # 전체 목록
    python ingest.py --get CVE-2021-44228  # 단건 조회

향후: 영속 벡터스토어(Chroma) 연동은 mcp_servers/ 에서 이 DB 를 소스로 확장한다.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "cve.db"
SEED_PATH = BASE / "seed" / "cve_seed.json"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    id            TEXT PRIMARY KEY,
    name          TEXT,
    cvss          REAL,
    cwe           TEXT,
    product       TEXT,
    affected      TEXT,
    description   TEXT,
    attack_pattern TEXT,
    reference     TEXT
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ingest() -> int:
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    conn = connect()
    conn.executescript(SCHEMA)
    for row in seed:
        conn.execute(
            """INSERT OR REPLACE INTO cve
               (id, name, cvss, cwe, product, affected, description, attack_pattern, reference)
               VALUES (:id, :name, :cvss, :cwe, :product, :affected, :description,
                       :attack_pattern, :reference)""",
            row,
        )
    conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    conn.close()
    return n


def search(keyword: str) -> list[sqlite3.Row]:
    conn = connect()
    like = f"%{keyword.lower()}%"
    rows = conn.execute(
        """SELECT * FROM cve
           WHERE lower(id) LIKE ? OR lower(name) LIKE ? OR lower(product) LIKE ?
                 OR lower(description) LIKE ? OR lower(attack_pattern) LIKE ?
           ORDER BY cvss DESC""",
        (like, like, like, like, like),
    ).fetchall()
    conn.close()
    return rows


def get_one(cve_id: str) -> sqlite3.Row | None:
    conn = connect()
    row = conn.execute("SELECT * FROM cve WHERE id = ?", (cve_id.upper(),)).fetchone()
    conn.close()
    return row


def _print(row: sqlite3.Row) -> None:
    print(f"  [{row['id']}] {row['name']}  (CVSS {row['cvss']}, {row['cwe']})")
    print(f"     제품: {row['product']} / 영향: {row['affected']}")
    print(f"     설명: {row['description']}")
    print(f"     패턴: {row['attack_pattern']}")


def main() -> int:
    p = argparse.ArgumentParser(description="CVE DB 적재·검색")
    p.add_argument("--search", metavar="KW", help="키워드 검색")
    p.add_argument("--list", action="store_true", help="전체 목록")
    p.add_argument("--get", metavar="CVE", help="단건 조회")
    args = p.parse_args()

    if args.search:
        rows = search(args.search)
        print(f"검색 '{args.search}' → {len(rows)}건")
        for r in rows:
            _print(r)
        return 0
    if args.list:
        for r in search(""):
            _print(r)
        return 0
    if args.get:
        r = get_one(args.get)
        if r:
            _print(r)
        else:
            print(f"{args.get} 없음")
        return 0

    # 기본: 적재
    n = ingest()
    print(f"[OK] CVE {n}건 적재 → {DB_PATH.relative_to(BASE.parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
