"""드리프트 감시 (ch27 §27.6) — 분포 변화 feature 를 KS 검정으로 식별.

scipy 가 없으면 평균차 기반 근사로 폴백한다. LLM 의미 라벨링은 mock 폴백.
"""
from __future__ import annotations
import json
import os

_USE_MOCK = os.environ.get("MOCK", "1") == "1"

try:
    from scipy.stats import ks_2samp
    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False


def _ks(a, b):
    if _HAS_SCIPY:
        s, p = ks_2samp(a, b)
        return float(s), float(p)
    # 근사: 정규화 평균차
    ma, mb = sum(a) / len(a), sum(b) / len(b)
    rng = (max(a + b) - min(a + b)) or 1.0
    return abs(ma - mb) / rng, 1.0


def detect_drift(reference: dict, current: dict, features: list,
                 threshold: float = 0.15) -> list:
    """reference/current 는 {feature: [values]}. KS>threshold 인 feature 반환."""
    drifted = []
    for f in features:
        ks_stat, p_value = _ks(reference[f], current[f])
        if ks_stat > threshold:
            drifted.append({
                "feature": f, "ks": ks_stat, "p": p_value,
                "ref_mean": sum(reference[f]) / len(reference[f]),
                "cur_mean": sum(current[f]) / len(current[f]),
            })
    return sorted(drifted, key=lambda x: x["ks"], reverse=True)


def label_drift_with_llm(drift_summary: list, recent_logs: list) -> dict:
    """drift 가 어떤 공격으로 보이는지 의미 라벨링. mock 폴백 포함."""
    if _USE_MOCK:
        top = drift_summary[0]["feature"] if drift_summary else None
        return {"suspected": "needs_review", "top_feature": top}
    import anthropic
    summary_text = "\n".join(
        f'- {d["feature"]}: mean {d["ref_mean"]:.2f} → {d["cur_mean"]:.2f} (KS={d["ks"]:.2f})'
        for d in drift_summary[:5])
    samples = "\n".join(json.dumps(l) for l in recent_logs[:10])
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-opus-5", max_tokens=400, thinking={"type": "disabled"},
        system="당신은 SOC drift analyst. 분포 변화 패턴을 보고 의심 공격 카테고리 1개 제안. "
               "확신 없으면 needs_review.",
        messages=[{"role": "user",
                   "content": f"drift summary:\n{summary_text}\n\n최근 샘플:\n{samples}\n\nJSON 출력."}])
    return json.loads("".join(b.text for b in resp.content if b.type == "text"))


if __name__ == "__main__":
    ref = {"bytes": [400, 420, 410, 430, 405]}
    cur = {"bytes": [1200, 1400, 1100, 1500, 1300]}
    d = detect_drift(ref, cur, ["bytes"])
    print("드리프트:", d)
    print("라벨:", label_drift_with_llm(d, []))
