#!/usr/bin/env python3
"""격리 표적 환경 모델 — red/blue lab 이 공격·방어하는 대상.

실제 lab 에서는 docker-compose.yml 의 취약 컨테이너(vulhub/vulfocus) 가 이 역할을 한다.
이 파일은 API·컨테이너 없이도 데모가 돌도록 표적을 코드로 모사한다. 각 서비스는 실재 CVE 를
하나씩 안고 있으며, 그 CVE 는 labs/cve_db 의 공유 corpus 와 동일한 ID 를 쓴다.

즉 "레드가 공격하는 취약점"과 "블루가 근거로 삼는 CVE corpus"가 같은 출처를 공유한다 —
이것이 CVE 기반 자기방어 폐루프의 핵심 전제다.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Service:
    name: str          # 컨테이너/서비스 이름
    port: int
    cve_id: str        # 이 서비스가 안고 있는 취약점 (cve_db 와 동일 ID)
    banner: str        # recon 시 노출되는 버전 배너


@dataclass
class Target:
    """격리 네트워크 안의 표적 서비스 집합."""
    services: list[Service] = field(default_factory=list)

    @classmethod
    def default(cls) -> "Target":
        # docker-compose.yml 의 표적과 대응하는 기본 구성
        return cls(services=[
            Service("web-dvwa",   8080, "CVE-2021-44228", "Apache/2.4 + log4j 2.14"),
            Service("struts-app", 8081, "CVE-2017-5638",  "Struts 2.3.30"),
            Service("openssl-svc",8443, "CVE-2014-0160",  "OpenSSL 1.0.1f"),
            Service("spring-app", 8082, "CVE-2022-22965", "Spring 5.3.15 / JDK 17"),
            Service("drupal-cms", 8083, "CVE-2018-7600",  "Drupal 7.57"),
        ])

    def by_name(self, name: str) -> Service | None:
        return next((s for s in self.services if s.name == name), None)
