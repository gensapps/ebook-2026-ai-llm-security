"""안전 차단 (ch27 §27.7) — 차단 + TTL 자동 해제 + rollback 로그.

**기본 DRY_RUN=1** 로 iptables 를 실제로 실행하지 않는다(공유 서버 보호). 실제 차단은
격리 VM 에서 root 로 DRY_RUN=0 실행할 때만 일어난다.
"""
from __future__ import annotations
import json
import os
import subprocess
import time
from pathlib import Path

ROLLBACK_LOG = Path(os.environ.get("LAB_LOGS", "./_lab_logs")) / "rollback.jsonl"
_DRY_RUN = os.environ.get("DRY_RUN", "1") == "1"


def safe_block(ip: str, reason: str, ttl_sec: int = 300) -> dict:
    entry = {"ts": time.time(), "ip": ip, "reason": reason,
             "ttl_sec": ttl_sec, "expires": time.time() + ttl_sec, "dry_run": _DRY_RUN}
    ROLLBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ROLLBACK_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    if _DRY_RUN:
        print(f"[dry-run] block {ip} ({reason}) TTL {ttl_sec}s — iptables 미실행")
        return entry
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    subprocess.run(["at", f"now + {ttl_sec // 60} minutes"],
                   input=f"iptables -D INPUT -s {ip} -j DROP".encode())
    return entry


def expire_old_blocks() -> int:
    if not ROLLBACK_LOG.exists():
        return 0
    now = time.time()
    keep, archived = [], 0
    for line in ROLLBACK_LOG.read_text().splitlines():
        e = json.loads(line)
        if now - e["ts"] > 30 * 86400:
            archived += 1
        else:
            keep.append(line)
    ROLLBACK_LOG.write_text("\n".join(keep) + ("\n" if keep else ""))
    return archived


if __name__ == "__main__":
    print(safe_block("203.0.113.9", "mock sqli", ttl_sec=300))
    print("만료 아카이브:", expire_old_blocks())
