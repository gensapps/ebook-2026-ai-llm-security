# 출간 교정 후 실행 검증 (2026-10-06)

수정한 21장·27장만 다시 실행했다. 나머지 16개 노트북은 아래의 이전 기록이며,
현재 판본 전체를 새 환경에서 검증했다는 뜻은 아니다.

- 환경: Linux, Python 3.10.12, 임시 가상환경(시스템 패키지 포함).
- 패키지: numpy 2.2.4 · pandas 2.3.3 · sentence-transformers 5.5.1 · chromadb 1.5.9 · scikit-learn 1.7.2 · nbclient 0.11.0
- API 키 비움, 외부 API 호출 없음. 21장은 공개 임베딩 모델을 먼저 준비한 뒤 오프라인 실행;
  27장은 mock 모드. 실제 공격·방화벽 변경·Docker 표적 구동 없음.
- 설치 셀 1줄은 실행 환경을 유지하기 위해 생략하고 패키지 import를 확인했다.
- 학생 완성본에 실제 실행 결과를 반영했다. 다운로드·인터넷 연결·유료 모델 응답은 검증 범위가 아니다.

| 노트북 | 상태 | 코드 셀 | 실행 시간 | 모드 |
|---|---|---:|---:|---|
| ch21_federated_threat_intel.ipynb | OK | 13 | 5.1초 | 로컬 all-MiniLM-L6-v2, 고정 시드 교육 예제 |
| ch27_adaptive_defense_lab.ipynb | OK | 29 | 36.5초 | offline mock |

추가 검증: 판정·학습·차단 복구 회귀 테스트 7개 통과, 기존 가드 테스트 3개 통과,
mock/DRY_RUN 데모 21개 통과. 이는 실제 모델의 탐지 성능이나 운영망 안전성을 입증하지 않는다.

---

# 이전 전체 실행 기록 (2026-09-16)

- 실행 일시: 2026-09-16 03:15:27
- 실행 환경: Python 3.12.5 · anthropic 1.5.0 · mcp 1.30.0 · chromadb 1.5.9 · sentence-transformers 6.0.1 · scikit-learn 1.9.1
- 생성 도구: `tools/validate_notebooks.py`
- 대상: `notebooks/instructor/*.ipynb` 18개 (2026-08-29 재번호 이후 기준)
- 허용 인프라: ollama

`!pip install` 셀은 Colab 배포용이라 실행하지 않고, 대신 해당 패키지가 현재
환경에 있는지 import 로 확인했다. SKIP 은 통과가 아니라 **확인하지 않았다**는
뜻이다 — 실행하면 컨테이너를 띄우거나 모델을 내려받아 환경을 바꾸는 노트북이다.

| 노트북 | 상태 | 시간 | 비고 |
|---|---|---|---|
| `ch09_llm_log_interpretation.ipynb` | OK | 52.3s | 13 cells |
| `ch10_prompt_engineering_xai.ipynb` | OK | 398.3s | 14 cells |
| `ch11_rag_threat_intelligence.ipynb` | OK | 53.7s | 14 cells |
| `ch12_soar_llm_agent.ipynb` | OK | 64.1s | 12 cells |
| `ch13_security_assistant_capstone.ipynb` | OK | 59.1s | 16 cells |
| `ch14_mcp_security_tools.ipynb` | OK | 10.2s | 14 cells |
| `ch15_multi_agent_red_blue.ipynb` | OK | 294.7s | 21 cells |
| `ch16_llm_native_siem.ipynb` | OK | 1.2s | 8 cells |
| `ch17_ai_spm.ipynb` | OK | 14.4s | 9 cells |
| `ch18_continuous_adversarial_testing.ipynb` | OK | 1.3s | 10 cells · 선언 패키지 미설치: garak |
| `ch19_ai_supply_chain.ipynb` | OK | 1.4s | 12 cells |
| `ch20_llm_sandbox.ipynb` | OK | 1.2s | 6 cells |
| `ch21_federated_threat_intel.ipynb` | OK | 1.3s | 6 cells |
| `ch22_llm_red_team_tools.ipynb` | OK | 10.0s | 10 cells |
| `ch23_frontier_safety.ipynb` | OK | 1.5s | 6 cells |
| `ch24_mythos_auto_attack_defense_lab.ipynb` | OK | 96.9s | 17 cells · 선언 패키지 미설치: python-nmap |
| `ch25_ctf_agent_platform.ipynb` | OK | 1.0s | 16 cells |
| `ch27_adaptive_defense_lab.ipynb` | OK | 20.2s | 29 cells |

## 요약

- OK: 18
- FAIL: 0
- ERROR: 0
- SKIP: 0
- 총: 18
