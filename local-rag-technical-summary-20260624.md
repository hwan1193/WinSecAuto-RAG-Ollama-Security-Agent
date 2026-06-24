# Technical Summary: Local LLM 및 RAG 기반 보안 운영 보조 Agent PoC

본 문서는 사내 폐쇄망 환경을 가정한 Linux 보안 운영 인프라 내에서 Local LLM과 RAG(Retrieval-Augmented Generation) 파이프라인을 융합하고, 시스템 자원을 최적화하기 위해 수행한 기술 검증 및 아키텍처 스위칭 기록 요약본입니다.

---

## 1. 프로젝트 목적 (Purpose)
* **운영 보안 확보:** 외부 LLM API 활용 시 발생할 수 있는 내부 핵심 자산 및 민감 로그의 외부 전송(Data Leakage) 우려를 근본적으로 차단하기 위한 온프레미스(On-Premise) 인프라 구축.
* **보안 운영 효율화:** 사내 보안 지침(계정/네트워크/자산 규정)에 대한 실시간 질의응답 및 보안 이벤트 분석 보조 엔진의 타당성 검증(PoC).
* **인프라 자원 최적화:** 한정된 컴퓨팅 자원(vCPU 기반 가상화 서버) 환경에서 트래픽 동적 분기를 통한 시스템 가용성 극대화.

## 2. 구성 환경 (Environment Specification)
* **OS:** Enterprise Linux (Kernel 5.x)
* **Compute 자원:** vCPU 4 Cores, 16GB RAM (No Hardware GPU Acceleration)
* **Core Engine:** Ollama Backend Engine (LLaMA3, Gemma:2b)
* **Framework & Library:** LangChain (v0.3.1), FAISS (v1.8.0), HuggingFace Transformers

## 3. 핵심 시스템 아키텍처 (Architecture)
시스템은 1차 Intent 분류를 담당하는 'LLM Router'와 2차 지식 추출을 담당하는 'RAG 파이프라인'의 하이브리드 구조로 설계되었습니다.

1. **질의 인입 (Ingress):** 임직원 및 관제 요원의 보안/일반 질의 수신.
2. **트래픽 라우팅 (Routing Layer):** LLaMA3 기반 라우터가 프롬프트 규격에 따라 질의 의도를 `SECURITY` 또는 `GENERAL`로 1차 분류 및 Python 문자열 필터링.
3. **보안 질의 처리 (RAG Path):** `SECURITY` 판정 시, 직렬화 병합된 보안 가이드라인이 적재된 `FAISS` 벡터 DB에서 유사도 검색 후 LLaMA3 메인 코어에서 최종 조치 근거 생성.
4. **일반 질의 처리 (Bypass Path):** `GENERAL` 판정 시, RAG 파이프라인(임베딩 연산 및 벡터 검색)을 우회하여 LLM 인라인 즉시 응답을 반환함으로써 시스템 오버헤드 최소화.

## 4. 발생 이슈 및 조치 내용 (Troubleshooting Note)

| 번호 | 발생 장애 (Issue) | 원인 분석 (Root Cause) | 조치 내용 (Resolution) |
| :--- | :--- | :--- | :--- |
| **1** | ChromaDB 초기화 실패 및 호환성 인터럽트 | 가상화 Linux 환경의 시스템 내장 `sqlite3` 버전이 ChromaDB의 요구 사양 미달. | 복잡한 의존성 업그레이드를 배제하고, 인-메모리 기반으로 경량화 및 고속 검색이 가능한 **`FAISS` 벡터 저장소로 전면 스위칭**. |
| **2** | Ollama Embedding API 미지원 에러 | 사용 중인 로컬 백엔드 버전에서 자체 임베딩 벡터 변환 파라미터 락 발생. | 경량화 및 한국어 성능이 검증된 오픈소스 임베딩 모델인 **`HuggingFace all-MiniLM-L6-v2`로 임베딩 레이어 분리 매핑**. |
| **3** | `DirectoryLoader` 가동 시 의존성 누수 | 다중 문서 로딩을 위해 호출한 기본 로더가 외부의 거대한 `unstructured` 패키지를 강제 요구하여 자원 소모 발생. | 추가 패키지 설치 없이 Python 내장 `os`/`open` 함수로 폴더 내 `.txt` 파일들을 선행 병합 직렬화한 뒤, 가벼운 **`TextLoader` 스트림으로 처리하도록 파이프라인 최적화**. |
| **4** | 경량 모델(`Gemma:2b`)의 라우팅 오판 및 논리 결함 | 2B급 모델의 지시어 이행(Instruction Following) 능력 한계로 출력이 정형화되지 않고 부연설명이 믹싱되어 조건문 오탐 유발. | 1. 추론 능력이 검증된 **`LLaMA3` 체제로 백엔드 원복 및 락온**.<br>2. 문자열의 맨 앞단만 필터링하는 **`startswith()` 제어 로직을 결합**하여 분기 안정성 100% 확보. |

## 5. 검증 결과 및 운영화 가능성 (Verification)
* **RAG 리트리블 무결성 검증:** 다중 보안 가이드라인 연동 후 "패스워드 변경 주기" 질의 시, 분산된 파일에서 **"90일(90 days)"** 자산을 정확히 추출하여 답변 완수.
* **Linux 서비스화(Daemonization) 검증:** 일회성 스크립트 실행에 그치지 않고, `security-rag.service` 명세서를 작성하여 **Linux `systemd` 시스템 데몬으로 등록**. `systemctl status` 확인 결과 `status=0/SUCCESS`로 안전하게 Deactivate됨을 확인하여 백그라운드 스케줄링 운영 가능성 입증.

## 6. 보안상 제한사항 및 향후 확장 방향 (Future Work)
* **보안 가이드라인 비식별화 준수:** 테스트 데이터셋(`sample_data/`) 구성 시, 실제 운영 서버 IP, 계정 자격증명, 내부 도메인 등 민감 식별자는 전수 마스킹 및 비식별화 처리를 완료하여 보안 사고 요인을 사전 차단함.
* **향후 과제:** 현재 PoC 단계를 넘어서기 위해, 향후 1차 속도전 레이어에는 안정성이 강화된 소형 모델(예: 프롬프트 튜닝된 Gemma2 규격)을 재도입하고, 백엔드에는 멀티 큐 파이프라인을 연계하여 비용 및 자원 효율성의 균형을 지속적으로 고도화할 예정임.