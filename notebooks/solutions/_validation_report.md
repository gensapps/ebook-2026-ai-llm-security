# 노트북 실행 검증 결과

- 보고서 갱신 일시: 2026-10-16 02:35:31
- 실행 환경: Python 3.10.12 · anthropic 1.14.0 · mcp 1.30.0 · chromadb 1.5.9 · sentence-transformers 6.1.0 · scikit-learn 1.7.2
- 생성 도구: `tools/validate_notebooks.py`
- 대상: `notebooks/instructor/*.ipynb` 18개 (2026-08-29 재번호 이후 기준)
- 허용 인프라: ollama

`!pip install` 셀은 Colab 배포용이라 실행하지 않고, 대신 해당 패키지가 현재
환경에 있는지 import 로 확인했다. SKIP 은 통과가 아니라 **확인하지 않았다**는
뜻이다 — 실행하면 컨테이너를 띄우거나 모델을 내려받아 환경을 바꾸는 노트북이다.

| 노트북 | 상태 | 확인 일시 | 시간 | 비고 |
|---|---|---|---|---|
| `ch09_llm_log_interpretation.ipynb` | OK | 2026-10-16 02:22:50 | 46.0s | 19 cells |
| `ch10_prompt_engineering_xai.ipynb` | OK | 2026-10-16 02:23:36 | 172.6s | 18 cells |
| `ch11_rag_threat_intelligence.ipynb` | OK | 2026-10-16 02:26:28 | 62.6s | 20 cells |
| `ch12_soar_llm_agent.ipynb` | OK | 2026-10-16 02:27:31 | 272.0s | 16 cells |
| `ch13_security_assistant_capstone.ipynb` | OK | 2026-10-16 02:32:03 | 46.8s | 18 cells |
| `ch14_mcp_security_tools.ipynb` | OK | 2026-10-16 02:32:50 | 6.2s | 14 cells |
| `ch15_multi_agent_red_blue.ipynb` | OK | 2026-10-16 02:32:56 | 54.3s | 21 cells |
| `ch16_llm_native_siem.ipynb` | OK | 2026-10-16 02:33:50 | 18.0s | 14 cells |
| `ch17_ai_spm.ipynb` | OK | 2026-10-16 02:34:08 | 11.3s | 11 cells |
| `ch18_continuous_adversarial_testing.ipynb` | OK | 2026-10-16 02:34:20 | 1.0s | 9 cells · 선언 패키지 미설치: garak |
| `ch19_ai_supply_chain.ipynb` | OK | 2026-10-16 02:34:21 | 1.0s | 18 cells, pip 1줄 생략 |
| `ch20_llm_sandbox.ipynb` | OK | 2026-10-16 02:34:22 | 6.9s | 15 cells |
| `ch21_federated_threat_intel.ipynb` | OK | 2026-10-16 02:34:28 | 9.2s | 13 cells, pip 1줄 생략 |
| `ch22_llm_red_team_tools.ipynb` | OK | 2026-10-16 02:34:38 | 9.5s | 10 cells |
| `ch23_frontier_safety.ipynb` | OK | 2026-10-16 02:34:47 | 1.0s | 10 cells |
| `ch24_mythos_auto_attack_defense_lab.ipynb` | OK | 2026-10-16 02:34:48 | 6.7s | 17 cells · 선언 패키지 미설치: python-nmap |
| `ch25_ctf_agent_platform.ipynb` | OK | 2026-10-16 02:34:55 | 1.0s | 16 cells |
| `ch27_adaptive_defense_lab.ipynb` | OK | 2026-10-16 02:34:56 | 35.1s | 29 cells |

## 요약

- OK: 18
- FAIL: 0
- ERROR: 0
- SKIP: 0
- 총: 18
