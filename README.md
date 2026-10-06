# 바이브 코딩의 시대, AI/ML·LLM 기반 보안 자동화 — 예제 코드 저장소

이 저장소는 도서 **「바이브 코딩의 시대, AI/ML·LLM 기반 보안 자동화 — 미토스(Mythos) 시대의 공격과 방어」**
(박수현 · GenAI Labs · 2026)의 **실행 가능한 실습 노트북 + 레드·블루 자기방어 lab**입니다.
AI/ML 탐지부터 LLM·RAG·Agent 자동 대응까지 직접 실행해 볼 수 있습니다.

- `notebooks/exercises/` — **실습본**: 빈칸(TODO)과 힌트가 들어 있어 직접 채우며 학습합니다.
- `notebooks/solutions/` — **완성본**: 정답 코드와 실행 결과가 들어 있습니다.
- `labs/` — **실습 코드**: 공유 CVE 지식베이스를 근거로 레드팀 Agent 와 블루팀 Agent 가
  공격·방어하는 데모입니다. `python labs/run_lab.py` 는 API 키 없이 바로 실행됩니다.

## 판본과 정오표

PDF와 같은 판본의 예제를 사용하세요. `RELEASE.json`에 판본과 파일 해시가 있습니다.
변경 사항과 오류 제보 방법은 [`ERRATA.md`](ERRATA.md)를 참고하세요.
ZIP으로 받은 경우에도 아래 명령은 압축을 푼 폴더에서 동일하게 실행합니다.

## 빠른 시작

전체 실행을 확인한 환경은 Linux · Python 3.10.12입니다. 같은 패키지 버전을 재현하려면
해당 Python으로 가상환경을 만들고 아래 잠금 파일을 사용하세요.
다른 OS·Python 버전의 실행은 별도 확인이 필요합니다.

```bash
# python --version으로 3.10.12인지 확인
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
python -m pip install -r requirements-lock.txt
pip install jupyterlab                # 로컬에서 노트북을 열 때만 (Colab 은 불필요)
cp .env.example .env                 # ch09 부터 LLM 실습에 키 사용; 없으면 자동 mock
jupyter lab
```

일반 설치에는 `requirements.txt`를 사용할 수 있지만, 최소 버전 조건이므로
검증 당시와 다른 패키지가 설치될 수 있습니다. 자세한 범위는 `notebooks/ENVIRONMENT.md`를 확인하세요.

### Google Colab

각 노트북 첫 셀의 `pip install` 주석을 한 번 해제해 실행합니다. GPU 는 필요하지 않습니다.
그래프의 한글이 깨지면 '한글 폰트 설정' 셀의 설치 주석을 한 번 실행한 뒤 런타임을 다시 시작합니다.

## LLM 실습 — API 키

ch09 부터 여러 노트북이 Anthropic Claude API 를 사용합니다. **키가 있으면 실제로 호출하고, 없으면
자동으로 mock** 으로 바꿔 끝까지 실행됩니다. 키는 환경변수 `ANTHROPIC_API_KEY` → 루트 `.env` →
Colab Secrets → 실행 중 입력(getpass) 순서로 찾습니다. `.env` 는 커밋하지 마세요.
ch15(Multi-Agent)·ch24(Mythos lab)는 로컬 LLM(Ollama llama3.2:3b)을 함께 쓰며, 설치되어 있지 않으면
역시 mock 으로 대체됩니다.

### 라이브러리 버전

`requirements.txt`는 최소 요구치입니다. 검증 이력·모드와 재실행 범위는
[`notebooks/ENVIRONMENT.md`](notebooks/ENVIRONMENT.md)를 확인하세요.
`RELEASE.json`에서 이 배포본의 파일 해시를 확인할 수 있습니다.

- **anthropic 1.x** — 1.0 부터 `temperature`·`top_p`·`top_k` 인자가 없어졌습니다. 이 저장소의 코드는
  이 인자를 쓰지 않고, 응답은 `type == 'text'` 인 블록만 모아 읽습니다(Opus 5·Sonnet 5 는 응답 앞에
  `thinking` 블록이 올 수 있습니다). 도서 ch09 §9.2.2 를 참고하세요.
- **mcp 1.x (`<2`)** — ch14 의 MCP 서버는 1.x API(`@server.list_tools()`)로 작성했습니다. 2.x 는 API 가
  달라 그대로 동작하지 않으므로 상한을 고정했습니다.
- 모델: `claude-opus-5` · `claude-sonnet-5` · `claude-haiku-4-5`, 로컬은 Ollama `llama3.2:3b` 입니다.

## labs/ 실행

```bash
python labs/run_lab.py          # 규칙 기반, API 키 불필요, 격리 표적 5개 서비스 시뮬레이션
python labs/run_lab.py --llm    # 레드=로컬 Ollama, 블루=Claude (둘 다 필요)
python labs/run_all_demos.py    # 챕터별 모듈 21개 mock 스모크 테스트
```

레드가 공유 CVE corpus 에서 취약점을 골라 공격하고, 블루가 같은 corpus 로 탐지·차단·self-heal
하는 합성 시뮬레이션을 라운드별 표로 출력합니다. `--live` 옵션은 없으며 Docker 표적과
자동 연결되지 않습니다. 별도 확장을 위한 취약 컨테이너는 `labs/docker-compose.yml`
(vulhub/vulfocus)로 실행하며, 반드시 인터넷이 차단된 격리 네트워크에서만 구동해야 합니다.

## 데이터

실습 데이터는 노트북 안에서 **합성 생성**됩니다. 임베딩 모델·Ollama 모델·컨테이너 이미지는
처음 실행할 때 별도로 내려받아야 합니다. 정상·공격 분포를
의도적으로 겹치게 만들어 비현실적인 100% 분리를 피했습니다.

## 주의 (법적·윤리)

모든 공격 실습은 **합성 데이터** 또는 사용자가 구성·확인한 **격리 환경**에서만
수행합니다. 실제 운영 네트워크를 대상으로 한 스캔·패킷 주입·공격은 금지됩니다.

## 라이선스

코드(노트북·labs/)는 **MIT** 입니다(`LICENSE` 참조). 도서 본문·삽화의 저작권은 저자에게 있으며
(삽화는 생성형 AI 로 제작), 외부 데이터셋으로 확장할 때는 상업 재사용 전에 각 데이터셋 약관을
확인하세요.

© 2026 박수현 (GenAI Labs)

---

> 이 저장소는 도서 **「바이브 코딩의 시대, AI/ML·LLM 기반 보안 자동화」**(GenAI Labs · 바이브 코딩 시리즈)의
> 실습 예제 코드입니다. 지은이 **박수현** · 펴낸곳 **GenAI Labs** · 2026.
