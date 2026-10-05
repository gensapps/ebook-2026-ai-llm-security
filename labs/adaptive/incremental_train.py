"""증분 재학습 (ch27 §27.6) — 새 라벨 데이터로 1차 분류기를 업데이트.

sklearn/pickle 이 없거나 모델 파일이 없으면, 재학습 이력만 기록하는 mock 으로 폴백한다.
"""
from __future__ import annotations
import os
import pickle
from datetime import date
from pathlib import Path

_USE_MOCK = os.environ.get("MOCK", "1") == "1"


def _extract_features(log: dict) -> list:
    """데모용 최소 피처 — 페이로드 길이·특수문자 수·의심 토큰 유무."""
    p = str(log.get("payload", ""))
    susp = sum(t in p.lower() for t in ("select", "jndi", "script", "../", "or 1=1"))
    return [len(p), sum(not c.isalnum() for c in p), susp]


def incremental_retrain(model_path: str, new_samples: list) -> int:
    # 사람 검토를 마친 확정 라벨만 학습한다. 미확인 판정을 공격으로 바꾸지 않는다.
    allowed = {"BENIGN", "SQLi", "XSS", "CMDi", "RCE", "SSRF", "Brute", "Other"}
    if not new_samples or any(s.get("label", {}).get("category") not in allowed
                              or s["label"].get("requires_review") for s in new_samples):
        raise ValueError("재학습에는 검토가 끝난 확정 라벨이 필요합니다")
    # 새 클론에서 _lab_logs/ 가 없어도 동작하도록 상위 디렉터리를 먼저 만든다.
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    if _USE_MOCK or not Path(model_path).exists():
        # mock: 버전만 올리고 학습 데이터 수를 기록
        meta = Path(model_path + ".meta")
        ver = int(meta.read_text().strip()) + 1 if meta.exists() else 2
        meta.write_text(str(ver))
        print(f"[mock] {len(new_samples)} 샘플로 증분 학습 흉내 → v{ver}")
        return ver
    with open(model_path, "rb") as f:
        artifact = pickle.load(f)
    model = artifact["model"]
    X_new = artifact["preprocessor"].transform([_extract_features(s["log"]) for s in new_samples])
    y_new = [1 if s["label"]["category"] != "BENIGN" else 0 for s in new_samples]
    model.partial_fit(X_new, y_new, classes=[0, 1])
    artifact["model"] = model
    artifact["version"] = artifact.get("version", 1) + 1
    artifact["retrained_at"] = str(date.today())
    with open(model_path, "wb") as f:
        pickle.dump(artifact, f)
    return artifact["version"]


if __name__ == "__main__":
    samples = [{"log": {"payload": "' OR 1=1--"}, "label": {"category": "SQLi"}}]
    v = incremental_retrain("./_lab_logs/rf_model.pkl", samples)
    print("새 버전:", v)
