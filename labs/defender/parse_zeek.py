"""Zeek conn.log 파서 (ch24 §24.6.1).

본문 스니펫은 실시간 tail 을 하지만, 이 파일은 conn.log 가 없으면 **mock flow 생성기**로
폴백해 데모가 돌게 한다. 실제 Zeek 로그를 쓰려면 ZEEK_LOG 를 지정하고 MOCK=0 으로 실행한다.
"""
from __future__ import annotations
import os, time
from pathlib import Path

ZEEK_LOG = Path(os.environ.get("ZEEK_LOG", "/zeek-logs/conn.log"))
_USE_MOCK = os.environ.get("MOCK", "1") == "1"

# 격리 표적으로 향하는 mock flow (공격 트래픽 + 정상 트래픽 섞임)
_MOCK_CONNS = [
    {"ts": 0.0, "uid": "C1", "src": "10.0.0.9", "src_port": 51000, "dst": "tgt-log4shell",
     "dst_port": 8983, "proto": "tcp", "service": "${jndi:ldap://x}", "duration": 0.2, "orig_bytes": 800},
    {"ts": 1.0, "uid": "C2", "src": "10.0.0.9", "src_port": 51001, "dst": "tgt-dvwa",
     "dst_port": 80, "proto": "tcp", "service": "' OR 1=1--", "duration": 0.1, "orig_bytes": 400},
    {"ts": 2.0, "uid": "C3", "src": "10.0.0.5", "src_port": 51002, "dst": "tgt-juice",
     "dst_port": 3000, "proto": "tcp", "service": "", "duration": 0.5, "orig_bytes": 1200},
    {"ts": 3.0, "uid": "C4", "src": "10.0.0.9", "src_port": 51003, "dst": "tgt-struts",
     "dst_port": 8080, "proto": "tcp", "service": "content-type: %{ognl}", "duration": 0.3, "orig_bytes": 600},
]


def parse_conn_line(line: str) -> dict:
    f = line.strip().split("\t")
    return {
        "ts": float(f[0]), "uid": f[1], "src": f[2], "src_port": int(f[3]),
        "dst": f[4], "dst_port": int(f[5]), "proto": f[6],
        "service": f[7] if f[7] != "-" else "",
        "duration": float(f[8]) if f[8] != "-" else 0,
        "orig_bytes": int(f[9]) if f[9] != "-" else 0,
    }


def stream_conn_log(follow: bool = False):
    """conn.log 를 읽어 각 flow 를 yield. mock 모드면 내장 샘플을 준다."""
    if _USE_MOCK or not ZEEK_LOG.exists():
        yield from _MOCK_CONNS
        return
    with ZEEK_LOG.open() as fp:
        if follow:
            fp.seek(0, 2)
        while True:
            line = fp.readline()
            if not line:
                if not follow:
                    break
                time.sleep(1); continue
            if line.startswith("#"):
                continue
            yield parse_conn_line(line)


if __name__ == "__main__":
    for c in stream_conn_log():
        print(c["src"], "→", c["dst"], repr(c["service"])[:40])
