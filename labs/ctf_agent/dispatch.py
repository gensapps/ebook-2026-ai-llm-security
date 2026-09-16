"""카테고리별 풀이 전략 (ch25 §25.4.2). 자기 자산만 표적. mock 모드면 canned evidence."""
from __future__ import annotations
import os
import subprocess

_USE_MOCK = os.environ.get("MOCK", "1") == "1"
ALLOWED_TARGETS = {"127.0.0.1", "localhost", "chall-web"}   # 격리 lab 안의 자기 자산만

_MOCK_EVIDENCE = {
    "web": "sqlmap identified injectable param. dumped: flag{sql1_1nj3ct10n}",
    "forensics": "ExifTool: Comment = flag{ex1f_m3tadata}",
}


def run_web_strategy(target_url: str) -> dict:
    host = target_url.split("/")[2].split(":")[0] if "//" in target_url else target_url
    if host not in ALLOWED_TARGETS:
        return {"status": "blocked", "reason": "target not in allowed lab hosts"}
    if _USE_MOCK:
        return {"tool": "sqlmap(mock)", "evidence": _MOCK_EVIDENCE["web"]}
    out = subprocess.run(["sqlmap", "-u", target_url, "--batch", "--level=1",
                          "--risk=1", "--timeout=30"], capture_output=True, text=True, timeout=120)
    return {"tool": "sqlmap", "evidence": out.stdout[-2000:]}


def run_forensics_strategy(file_path: str) -> dict:
    if _USE_MOCK:
        return {"file_type": "JPEG image data", "metadata": _MOCK_EVIDENCE["forensics"]}
    ftype = subprocess.run(["file", file_path], capture_output=True, text=True).stdout
    exif = subprocess.run(["exiftool", file_path], capture_output=True, text=True).stdout
    return {"file_type": ftype.strip(), "metadata": exif[:2000]}


DISPATCH = {"web": run_web_strategy, "forensics": run_forensics_strategy}


if __name__ == "__main__":
    print(run_web_strategy("http://chall-web/login"))
    print(run_web_strategy("http://8.8.8.8/login"))   # 차단돼야
