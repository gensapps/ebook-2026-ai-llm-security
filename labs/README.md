# labs/ — 실습 코드 트랙 (레드/블루 자기방어 데모)

이 도서의 실습은 **두 트랙**이다.

1. **notebooks/** — 개념을 익히는 코드 스니펫 학습 트랙(강사/학생/실행본).
2. **labs/** (이 폴더) — 실행 가능한 시뮬레이션과 확장용 모듈 트랙. CVE DB 를 공유 지식베이스로 삼아,
   **레드팀 Agent 가 우리 서비스를 공격하고 블루팀 Agent 가 방어하며, 그 결과로 방어를 스스로
   고도화**하는 end-to-end 데모를 만든다.

> **주의(보안·법적):** 이 lab 의 공격 코드는 **격리된 VM/컨테이너**와 **본인 소유 표적**에서만
> 실행한다. 실제 운영 시스템·타인의 자산에 대한 스캔·exploit 은 정보통신망법 위반이다.

## 구성

```
labs/
├── cve_db/            # 공유 CVE 지식베이스 (레드·블루 공통 근거)
│   ├── seed/cve_seed.json   실재 CVE 시드(Log4Shell·Struts2·Heartbleed 등 6종)
│   ├── ingest.py            SQLite 적재·검색·조회 (stdlib 만)
│   └── cve.db               생성물(gitignore)
├── target.py          # 격리 표적 5개 서비스 모델 (docker-compose 와 1:1)
├── mcp_servers/
│   └── security_tools.py    recon·exploit·defense 도구 (권한 등급 분리)
├── agents/
│   ├── red_agent.py         CVE 선택→PoC→공격 (라운드마다 난독화↑, 선택적 로컬 Ollama)
│   └── blue_agent.py        탐지·차단 + self-heal(공유 corpus 로 학습) + 선택적 Claude 의미 판단
├── orchestrator.py    # Purple — 라운드 진행·점수·RAG on/off 및 LLM on/off 대조
├── run_lab.py         # end-to-end 러너 (한 명령으로 실행)
└── docker-compose.yml # 실제 취약 표적(vulhub/vulfocus) + 격리 네트워크
```

## 합성 표적 시뮬레이션 결과

`run_lab.py`는 `target.py`의 합성 서비스 모델을 사용합니다. Docker 표적에 실제로 접속하는
통합 공격·방어 검증이 아니며 `--live` 옵션도 없습니다. 아래 비율은 이 시뮬레이션의 결과로,
미지 공격이나 실제 SOC의 성능으로 일반화할 수 없습니다. 정상 트래픽 오탐률·미사용 평가
데이터·반복 실행을 별도로 평가해야 합니다.

이 lab 은 변수 하나만 격리하는 **독립된 두 비교 모드**를 갖는다 — 두 메커니즘(corpus 학습·
LLM 판단)을 한꺼번에 켜면 블루가 처음부터 거의 모든 공격을 탐지해(포화) 무엇이 얼마나
기여했는지 알 수 없어지기 때문이다.

### 모드 1 — RAG(corpus 학습) 기여도

```bash
python run_lab.py        # 규칙 기반, API 키·Ollama 불필요
```

블루는 5개 CVE 중 2개만 알고 시작한다. 레드가 라운드마다 난독화 변형을 늘려 공격하면,
블루는 놓친 공격을 **공유 CVE corpus 로 되짚어(self-heal) 학습**한다.

| 구분 | Day1 탐지율 | Day7 탐지율 |
|---|---|---|
| RAG 사용(공유 corpus) | 40% | **100%** |
| 대조군(RAG 미사용) | 40% | 40% (평탄) |

공유 CVE corpus 기반 self-heal 이 최종 탐지율을 **+60%p** 끌어올린다. 코퍼스가 없으면 블루는
미지 변형 공격을 학습하지 못한다 — 자기방어 고도화가 CVE corpus 에 의존함을 정량으로 보여 준다.

### 모드 2 — 블루의 LLM 의미 판단 기여도

```bash
python run_lab.py --llm  # 레드=로컬 Ollama(llama3.2:3b), 블루=Claude — 둘 다 API/모델 필요
```

RAG 는 두 조건 모두 켜 두고, 레드는 **매 라운드 로컬 Ollama 로 페이로드를 변형**해 공격
강도를 동일하게 고정한다. 이 상태에서 블루가 시그니처 매칭에 실패한 이벤트를 **Claude 로
의미 기반 재판단**하는지 여부만 바꿔서 그 기여도만 따로 측정한다.

| 구분 | Day1 탐지율 | Day7 탐지율 |
|---|---|---|
| 규칙 기반 단독 | **0%** | **0%** (평탄) |
| 규칙 + LLM 의미 판단(Claude) | 100% | 100%(80~100% 변동) |

레드가 매번 LLM 으로 변형하면 결정적 해시 기반 탈난독화 로직(`normalize_observed`)이 아예
통하지 않아 규칙 기반은 **완전히 무력화**된다(0%). 블루에 Claude 의미 판단을 추가하는 순간
탐지율이 즉시 80~100% 로 회복된다 — "자동화된 공격에는 자동화된 관측·판단·대응이 필요하다"
는 이 실습 조건에서 관찰한 결과다. 규칙 기반 corpus self-heal(모드 1)과 구분해 읽는다.

레드의 변형 생성은 Ollama에서 실행하는 로컬 모델이, 블루의 의미 판단은 Claude가 맡는다.
Ollama는 실행 도구이므로 그 자체로 모델의 안전 정렬 수준을 나타내지 않는다.
두 모델 모두 요청을 거부할 수 있으며, 거부는 우회하지 않고 결과에 기록한다.

## 빠른 시작 (CVE DB)

```bash
cd labs/cve_db
python ingest.py                    # CVE 적재 → cve.db
python ingest.py --search log4j     # 키워드 검색
python ingest.py --get CVE-2021-44228
python ingest.py --list             # 전체 목록
```

외부 패키지·API 키 없이 표준 라이브러리만으로 동작한다. 레드/블루 Agent 는 이 DB 를 **같은
근거 corpus** 로 공유한다 — 레드는 여기서 취약점을 골라 PoC 를 만들고, 블루는 같은 corpus 로
탐지·차단한다. 이 대칭이 "CVE 기반 자기방어 폐루프"의 출발점이다.

## 도서 챕터 연결

- CVE corpus 설계: ch11 (RAG 와 위협 인텔리전스)
- 레드/블루 Multi-Agent: ch15
- MCP 권한 분리: ch14
- 자동 공격·방어 lab: ch24
- 자기방어 고도화(Adaptive Defense): ch27


## 챕터별 실행 파일 (본문 코드 블록의 실제 출처)

본문(ch13·14·24·25·26·27)의 코드 블록은 아래 실행 파일의 **핵심 발췌**다. 전부 `MOCK=1`
(기본) 으로 nmap·ollama·CTFd·Zeek·root 없이 돌아간다. 한 번에 확인하려면:

```bash
python labs/run_all_demos.py     # 21개 모듈 mock 스모크 — OK 21 / FAIL 0
```

| 챕터 | 파일 | 무엇을 하는가 |
|---|---|---|
| ch13 | `security_assistant_lab.py`, `scripts/security_assistant_cli.py` | ML1차→RAG→LLM→Agent 라우팅 캡스톤(경량 실행판) + CLI |
| ch14 | `mcp_gateway/gateway.py`, `mcp_gateway/siem_mcp_server.py` | MCP 게이트웨이(키 인증·tool 권한 매트릭스) + SIEM MCP 서버 |
| ch24 | `attacker/agent/{local_llm,recon,auto_pentest}.py`, `defender/{parse_zeek,auto_defend,score}.py` | 자동 공격(정찰→LLM 선택→exploit) + 자동 방어(Zeek flow→판정) + Red vs Blue 점수 |
| ch25 | `ctf_agent/{ctfd_client,classify,dispatch,agent,benchmark}.py`, `ctf_platform/setup_challenges.py` | CTF 자동 풀이(분류→전략→flag 추출→제출) + 벤치마크 |
| ch26 | `attacker/agent/{guardrails,safe_llm,rate_limit,kill_switch,hitl}.py`, `tests/test_guardrails.py` | 11 가드 중 코드 가드(schema·injection shield·rate limit·kill switch·HITL) + 회귀 테스트 |
| ch27 | `adaptive/{analyze_unknown,drift_sentinel,missed_detector,incremental_train,safe_block}.py`, `scripts/update_rag_corpus.py` | Adaptive Defense — RAG 갱신·의미 추론·drift·Active Learning·안전 차단(기본 dry-run) |

> **두 트랙의 관계.** `run_lab.py`(위) 는 의존성 0 의 순수 시뮬레이션으로 레드·블루
> self-heal 루프를 정량 측정한다(ch27 이 인용하는 40%→100%). 위 챕터별 파일들은 실제
> 인프라(Ollama·nmap·Zeek·CTFd)를 쓰는 "인프라 트랙"으로, 인프라가 없으면 mock 으로
> 폴백해 같은 로직을 시연한다. 둘은 개념을 공유하되 실행 경로가 다르며, 어느 쪽이든
> 격리 네트워크·자기 자산에서만 돌린다.
