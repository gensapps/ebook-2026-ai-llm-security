"""토큰버킷형 rate limiter (ch26 §26.3). LLM·tool 호출 폭주 방지."""
from __future__ import annotations
import time
from collections import deque
from functools import wraps


class RateLimiter:
    def __init__(self, max_calls: int, window_sec: int):
        self.max_calls = max_calls
        self.window = window_sec
        self.calls: deque[float] = deque()

    def wait_if_needed(self):
        now = time.time()
        while self.calls and self.calls[0] < now - self.window:
            self.calls.popleft()
        if len(self.calls) >= self.max_calls:
            time.sleep(self.window - (now - self.calls[0]))
            return self.wait_if_needed()
        self.calls.append(now)


def rate_limited(rl: RateLimiter):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            rl.wait_if_needed()
            return fn(*a, **kw)
        return wrapper
    return deco


llm_rl = RateLimiter(max_calls=10, window_sec=60)    # LLM 분당 10회
tool_rl = RateLimiter(max_calls=30, window_sec=60)   # tool 분당 30회


if __name__ == "__main__":
    rl = RateLimiter(max_calls=3, window_sec=1)
    for i in range(3):
        rl.wait_if_needed(); print("call", i)
    print("3회 통과 — 4번째는 window 만료까지 대기했을 것")
