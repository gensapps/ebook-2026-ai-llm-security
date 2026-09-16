"""LLM 결정 스키마 검증 가드 (ch26 §26.3). jsonschema 가 없으면 최소 검증기로 폴백."""
from __future__ import annotations

ALLOWED_METHODS = {"sqlmap", "curl", "nuclei"}     # metasploit·shell·reverse_shell X
ALLOWED_TARGETS = {"tgt-dvwa", "tgt-juice", "tgt-log4shell", "tgt-struts"}

DECISION_SCHEMA = {
    "type": "object",
    "required": ["target", "exploit_method"],
    "properties": {
        "target":         {"enum": list(ALLOWED_TARGETS)},
        "exploit_method": {"enum": list(ALLOWED_METHODS)},
        "cve":            {"type": "string", "pattern": r"^CVE-\d{4}-\d+$"},
        "rationale":      {"type": "string", "maxLength": 500},
    },
    "additionalProperties": False,
}

try:
    from jsonschema import validate, ValidationError
except ImportError:  # 최소 검증기 — enum·required 만 확인
    class ValidationError(Exception):
        def __init__(self, message): self.message = message

    def validate(inst, schema):  # noqa: ANN001
        for k in schema.get("required", []):
            if k not in inst:
                raise ValidationError(f"required '{k}' 누락")
        for k, spec in schema.get("properties", {}).items():
            if k in inst and "enum" in spec and inst[k] not in spec["enum"]:
                raise ValidationError(f"'{k}'={inst[k]!r} 은 허용 목록 밖")
        if not schema.get("additionalProperties", True):
            extra = set(inst) - set(schema.get("properties", {}))
            if extra:
                raise ValidationError(f"허용되지 않은 필드 {extra}")


def validate_llm_decision(decision: dict) -> dict:
    """LLM 응답을 schema 로 검증. 실패하면 안전한 기본값 반환."""
    try:
        validate(decision, DECISION_SCHEMA)
        return decision
    except ValidationError as e:
        return {"target": decision.get("target", ""),
                "exploit_method": "nuclei",   # 가장 안전한 default
                "rationale": f"LLM output rejected: {e.message}",
                "guardrail_blocked": True}


if __name__ == "__main__":
    print(validate_llm_decision({"target": "tgt-dvwa", "exploit_method": "sqlmap"}))
    print(validate_llm_decision({"target": "8.8.8.8", "exploit_method": "sqlmap"}))
