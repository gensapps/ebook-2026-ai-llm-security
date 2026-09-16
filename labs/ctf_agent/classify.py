"""CTF 챌린지 카테고리 분류 (ch25 §25.4.1). CTFd category 필드를 설명 텍스트로 재검증."""
from __future__ import annotations

CATEGORY_HINTS = {
    "web":       ["http", "url", "login", "cookie", "sql", "xss"],
    "crypto":    ["cipher", "rsa", "xor", "encrypt", "modulus", "key"],
    "forensics": ["pcap", "image", "memory dump", "file", "metadata"],
    "misc":      [],  # 기본값
}


def classify_challenge(name: str, description: str, category_hint: str = "") -> str:
    if category_hint in CATEGORY_HINTS:
        return category_hint
    text = f"{name} {description}".lower()
    scores = {cat: sum(1 for kw in kws if kw in text) for cat, kws in CATEGORY_HINTS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "misc"


if __name__ == "__main__":
    print(classify_challenge("Login Bypass", "SQL injection in the login form"))
    print(classify_challenge("Hidden Metadata", "secret hidden in image metadata"))
