"""CTFd REST 클라이언트 (ch25 §25.3). MockCTFdClient 로 서버 없이도 데모 가능."""
from __future__ import annotations
import os

_USE_MOCK = os.environ.get("MOCK", "1") == "1"


class CTFdClient:
    def __init__(self, base_url: str, token: str):
        import requests
        self._requests = requests
        self.base_url = base_url
        self.headers = {"Authorization": f"Token {token}", "Content-Type": "application/json"}

    def list_challenges(self) -> list[dict]:
        r = self._requests.get(f"{self.base_url}/api/v1/challenges", headers=self.headers)
        r.raise_for_status()
        return r.json()["data"]

    def get_challenge_detail(self, challenge_id: int) -> dict:
        r = self._requests.get(f"{self.base_url}/api/v1/challenges/{challenge_id}", headers=self.headers)
        r.raise_for_status()
        return r.json()["data"]

    def submit_flag(self, challenge_id: int, flag: str) -> dict:
        payload = {"challenge_id": challenge_id, "submission": flag}
        r = self._requests.post(f"{self.base_url}/api/v1/challenges/attempt",
                                json=payload, headers=self.headers)
        r.raise_for_status()
        return r.json()["data"]


class MockCTFdClient:
    """CTFd 서버 없이 도는 인메모리 대체 — 3 챌린지 + 정답 flag."""
    _CH = [
        {"id": 1, "name": "Login Bypass", "category": "web",
         "description": "Find the SQL injection at http://chall-web/login."},
        {"id": 2, "name": "Hidden Metadata", "category": "forensics",
         "description": "This image has a secret in its metadata: ./sample.jpg"},
        {"id": 3, "name": "Guess the Flag", "category": "misc",
         "description": "No obvious hints here."},
    ]
    _FLAGS = {1: "flag{sql1_1nj3ct10n}", 2: "flag{ex1f_m3tadata}", 3: "flag{misc_l4t3ral_th1nk1ng}"}

    def list_challenges(self):
        return [{"id": c["id"], "name": c["name"], "category": c["category"]} for c in self._CH]

    def get_challenge_detail(self, challenge_id: int):
        return next(c for c in self._CH if c["id"] == challenge_id)

    def submit_flag(self, challenge_id: int, flag: str):
        ok = self._FLAGS.get(challenge_id) == flag
        return {"status": "correct" if ok else "incorrect",
                "message": "정답" if ok else "오답"}


def get_client(base_url="http://127.0.0.1:8000", token="mock"):
    return MockCTFdClient() if _USE_MOCK else CTFdClient(base_url, token)


if __name__ == "__main__":
    c = get_client()
    print("챌린지:", c.list_challenges())
    print("제출:", c.submit_flag(1, "flag{sql1_1nj3ct10n}"))
