"""SIEM MCP 서버 — 격리 lab 용 최소 예시 (ch14 §14.3).

mcp SDK 가 있으면 실제 MCP 서버로 뜨고, 없으면 import 시 툴 목록/호출을 확인할 수 있는
경량 스텁으로 폴백한다. siem_client 는 lab 용 mock 로그 검색기다.
"""
from __future__ import annotations


class _MockSiemClient:
    """실제 SIEM 대신 lab 용 샘플 로그를 반환."""
    _ROWS = [
        "2026-06-15T03:14:22 src=10.0.0.9 GET /search?q=' OR 1=1-- 401",
        "2026-06-15T03:14:25 src=10.0.0.9 POST /solr/ hdr=${jndi:ldap://x} 500",
        "2026-06-15T03:15:01 src=10.0.0.5 GET /index.html 200",
    ]

    def search(self, filter_str: str = "", minutes: int = 5) -> list[str]:
        rows = self._ROWS
        return [r for r in rows if filter_str in r] if filter_str else rows


siem_client = _MockSiemClient()

try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent

    server = Server("siem")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [Tool(
            name="query_logs",
            description="SIEM 에서 최근 N분의 로그를 조회한다",
            inputSchema={"type": "object", "properties": {
                "minutes": {"type": "integer", "default": 5},
                "filter": {"type": "string", "default": ""}}, "required": []})]

    @server.call_tool()
    async def call_tool(name: str, args: dict) -> list[TextContent]:
        if name == "query_logs":
            rows = siem_client.search(args.get("filter", ""), minutes=args.get("minutes", 5))
            return [TextContent(type="text", text="\n".join(rows[:100]))]
        raise ValueError(f"unknown tool: {name}")

    _HAS_MCP = True
except ImportError:
    _HAS_MCP = False


if __name__ == "__main__":
    print(f"[siem_mcp_server] mcp_sdk={_HAS_MCP}")
    print("query_logs(filter='jndi'):")
    for row in siem_client.search("jndi"):
        print("  ", row)
