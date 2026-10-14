"""SecurityAssistant — lab 용 경량 구현 (ch13 캡스톤의 실행 가능한 축소판).

ch13 본문은 전작 14장 이진 RF + ChromaDB + Claude + 승인 게이트를 통합한다.
이 경량 lab은 기본 ML을 규칙으로 대체하며, 모델 경로를 지정하면 실제 RF를 읽는다.
RAG·LLM·외부 대응은 연결하지 않는다. RAG·LLM 연결은
ch13 노트북(notebooks/instructor/ch13_security_assistant_capstone.ipynb) 에 있다.

route 규칙은 ch13 §13.1 과 동일하다: ml<0.3 → pass, ml>0.9 → auto, 그 사이 → 검토.
"""
from __future__ import annotations
import re

_ATTACK_HINTS = (
    ("' or 1=1", 0.95), ("union select", 0.95), ("<script", 0.9),
    ("${jndi:", 0.97), ("/etc/passwd", 0.9), ("content-type: %{", 0.95),
    ("sqlmap", 0.85), ("../", 0.7),
)


class SecurityAssistant:
    def __init__(self, ml_model_path: str | None = None, chroma_path: str | None = None,
                 anthropic_api_key: str | None = None, dry_run: bool = True):
        # 명시한 모델 경로는 실제로 읽는다. RAG·LLM·대응은 이 경량 lab의 모의 경로다.
        self.scorer = None
        if ml_model_path is not None:
            try:
                from .artifact_model import BinaryArtifactScorer
            except ImportError:
                from artifact_model import BinaryArtifactScorer
            self.scorer = BinaryArtifactScorer(ml_model_path)
        self.ml_model_path = ml_model_path
        self.chroma_path = chroma_path
        self.dry_run = dry_run
        self.audit_log: list[dict] = []

    def _ml_score(self, event: dict) -> float:
        if self.scorer is not None:
            return self.scorer(event)
        blob = " ".join(str(v) for v in event.values()).lower()
        return max((s for h, s in _ATTACK_HINTS if h in blob), default=0.1)

    def analyze(self, event: dict) -> dict:
        s = self._ml_score(event)
        if s < 0.3:
            verdict = {"route": "pass", "ml": s, "verdict": "BENIGN"}
        elif s > 0.9:
            verdict = {"route": "auto", "ml": s, "verdict": "ATTACK",
                       "action": "simulated-block"}
        else:
            verdict = {"route": "review", "ml": s, "verdict": "SUSPECT"}
        self.audit_log.append({"event": event, "verdict": verdict})
        return verdict


if __name__ == "__main__":
    a = SecurityAssistant()
    for ev in ({"url": "/login?id=' OR 1=1--", "ua": "sqlmap"},
               {"url": "/index.html", "ua": "Mozilla"},
               {"url": "/solr/", "hdr": "${jndi:ldap://x}"}):
        print(a.analyze(ev)["route"], "\t", ev)
