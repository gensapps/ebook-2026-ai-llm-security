"""CTFd 챌린지 등록 (ch25 §25.3). 실제 CTFd 에 REST 로 등록. MOCK/DRY 면 출력만.

실서버에 등록하려면 CTFd 를 띄우고 ADMIN_TOKEN 을 발급한 뒤 MOCK=0 으로 실행한다.
"""
from __future__ import annotations
import os

CTFD_URL = os.environ.get("CTFD_URL", "http://127.0.0.1:8000")
ADMIN_TOKEN = os.environ.get("CTFD_ADMIN_TOKEN", "ctfd_admin_token_here")
_USE_MOCK = os.environ.get("MOCK", "1") == "1"

CHALLENGES = [
    {"name": "Login Bypass", "category": "web",
     "description": "Find the SQL injection in the login form at chall-web.",
     "value": 100, "state": "visible", "type": "standard"},
    {"name": "Hidden Metadata", "category": "forensics",
     "description": "This image file has a secret hidden in its metadata.",
     "value": 100, "state": "visible", "type": "standard"},
    {"name": "Guess the Flag", "category": "misc",
     "description": "No obvious hints here — read carefully and explore.",
     "value": 50, "state": "visible", "type": "standard"},
]
FLAGS = {"Login Bypass": "flag{sql1_1nj3ct10n}",
         "Hidden Metadata": "flag{ex1f_m3tadata}",
         "Guess the Flag": "flag{misc_l4t3ral_th1nk1ng}"}


def _headers():
    return {"Authorization": f"Token {ADMIN_TOKEN}", "Content-Type": "application/json"}


def create_challenge(chal: dict) -> int:
    import requests
    r = requests.post(f"{CTFD_URL}/api/v1/challenges", json=chal, headers=_headers())
    r.raise_for_status()
    return r.json()["data"]["id"]


def add_flag(challenge_id: int, flag: str):
    import requests
    requests.post(f"{CTFD_URL}/api/v1/flags",
                  json={"challenge_id": challenge_id, "content": flag, "type": "static"},
                  headers=_headers()).raise_for_status()


if __name__ == "__main__":
    if _USE_MOCK:
        print("[mock] CTFd 미연결 — 등록할 챌린지:")
        for chal in CHALLENGES:
            print(f"  {chal['name']} ({chal['category']}) flag={FLAGS[chal['name']]}")
    else:
        for chal in CHALLENGES:
            cid = create_challenge(chal); add_flag(cid, FLAGS[chal["name"]])
            print(f"등록: {chal['name']} (id={cid})")
