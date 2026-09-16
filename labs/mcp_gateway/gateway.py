"""MCP 게이트웨이 — 호스트별 API 키 인증 + tool 권한 매트릭스 (ch14 §14.4).

본문은 authenticate() 조각만 싣는다(gateway.py 일부). 이 파일은 그 조각을 포함한
실행 가능한 최소 게이트웨이다 — 인메모리 호스트 DB 와 권한 검사, 감사 로그를 갖춘다.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field


@dataclass
class Host:
    name: str
    key: str
    tools: set[str] = field(default_factory=set)   # 이 호스트가 부를 수 있는 tool
    disabled: bool = False


class _HostDB:
    def __init__(self):
        self._by_key = {
            "key-soc": Host("soc-assistant", "key-soc", {"query_logs", "fetch_pcap"}),
            "key-fw": Host("fw-agent", "key-fw", {"query_logs", "block_ip"}),
        }

    async def get_host_by_key(self, key: str) -> Host | None:
        return self._by_key.get(key)


db = _HostDB()
AUDIT: list[dict] = []


async def authenticate(request) -> Host | None:
    key = request.headers.get("X-MCP-Key")
    if not key:
        return None
    host = await db.get_host_by_key(key)
    if host is None or host.disabled:
        return None
    return host


async def dispatch(request, tool: str, args: dict) -> dict:
    """인증 → 권한 검사 → 감사 로그. 권한 밖 tool 은 거부."""
    host = await authenticate(request)
    if host is None:
        return {"error": "unauthenticated"}
    allowed = tool in host.tools
    AUDIT.append({"ts": time.time(), "host": host.name, "tool": tool, "allowed": allowed})
    if not allowed:
        return {"error": f"'{host.name}' 은 '{tool}' 권한 없음"}
    return {"ok": True, "host": host.name, "tool": tool, "args": args}


if __name__ == "__main__":
    import asyncio

    class _Req:
        def __init__(self, key): self.headers = {"X-MCP-Key": key} if key else {}

    async def _demo():
        print(await dispatch(_Req("key-soc"), "query_logs", {"minutes": 5}))   # 허용
        print(await dispatch(_Req("key-soc"), "block_ip", {"ip": "1.2.3.4"}))  # 권한 없음
        print(await dispatch(_Req(None), "query_logs", {}))                    # 미인증
        print("감사:", AUDIT)

    asyncio.run(_demo())
