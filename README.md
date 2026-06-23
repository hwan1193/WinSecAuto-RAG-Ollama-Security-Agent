# WinSecAuto-RAG-Ollama-Security-Agent

WinSecAuto RAG Ollama Security Agent
1. 개요

WinSecAuto RAG Ollama Security Agent는 WinSecAuto V2.1 보안 운영 자동화 아키텍처의 확장 PoC입니다.

본 프로젝트는 Ollama 기반 Local LLM을 활용하여 보안 로그, 취약점 점검 결과, 서버 진단 결과를 로컬 환경에서 요약하고, 향후 RAG 기반 Security Knowledge Layer와 연계하여 내부 보안 정책, 점검 기준, MITRE ATT&CK, CVE, 과거 조치 이력을 근거로 분석하는 구조를 목표로 합니다.

본 PoC는 실제 공격, 침투, exploit 실행을 수행하지 않으며, 보안 운영자가 수집한 로그와 점검 결과를 기반으로 위험도 요약, 조치 권고, 리포트 초안 생성을 지원하는 보조 분석 도구입니다.

2. 설계 목적

기존 Multi-LLM 기반 보안 자동화 구조는 외부 LLM API 호출 비용, 민감 로그 외부 전송, 응답 지연 문제가 발생할 수 있습니다.

이를 보완하기 위해 본 PoC에서는 Ollama 기반 Local LLM을 도입하여 다음 역할을 수행합니다.

민감 로그 외부 전송 전 1차 요약
개인정보, 계정명, 호스트명 마스킹
보안 점검 결과 분류
취약점 리포트 초안 생성
RAG 연동 전 로컬 분석 테스트
외부 LLM 호출 비용 절감
3. 아키텍처 내 역할

본 프로젝트에서 Ollama는 전체 보안 운영 분석을 단독으로 수행하는 엔진이 아닙니다.

Ollama는 아래 역할을 담당합니다.

Local LLM 실행 환경
민감 로그 1차 분석
보안 점검 결과 요약
RAG 검색 결과 기반 초안 작성
외부 LLM 호출 전 사전 정리
오프라인 PoC 테스트

High, P1, P2 또는 판단이 불확실한 항목은 외부 LLM 또는 Multi-LLM 교차 검증 대상으로 분리할 수 있습니다.

4. 테스트 환경
OS: Linux
LLM Runtime: Ollama
Tested Models:
llama3
gemma3
Use Case:
보안 로그 요약
취약점 점검 결과 요약
조치 권고 초안 생성
RAG 기반 보안 지식 검색 연계 준비
5. 설치 방법
Ollama 설치

공식 설치 방식에 따라 Ollama를 설치합니다.

curl -fsSL https://ollama.com/install.sh | sh
모델 다운로드
ollama pull llama3
ollama pull gemma3
설치 확인
ollama list
모델 실행
ollama run llama3
ollama run gemma3
6. 샘플 실행
cd scripts
bash check_ollama.sh
bash run_local_llm_test.sh

또는 Python 기반 샘플 분석기를 실행합니다.

python3 sample_log_analyzer.py
7. 보안 유의사항

본 프로젝트에는 실제 운영 로그, 실제 서버 IP, 계정명, 내부 도메인, 개인정보, API Key를 포함하지 않습니다.

GitHub에 업로드하는 모든 샘플 데이터는 비식별화된 테스트 데이터만 사용합니다.

금지 항목:

실제 회사 로그 업로드 금지
실제 취약점 진단 결과 원본 업로드 금지
실제 서버 IP 및 내부 도메인 업로드 금지
API Key 업로드 금지
Ollama 모델 파일 업로드 금지
개인정보 또는 계정정보 업로드 금지
8. 향후 확장 계획
RAG 기반 Security Knowledge Layer 연동
Chroma 또는 FAISS 기반 벡터 검색 PoC
내부 보안 정책 및 점검 기준 임베딩
MITRE ATT&CK 후보 매핑 자동화
CVE/NVD/KEV 기반 취약점 근거 검색
WinSecAuto 점검 결과 자동 요약
HTML/PDF 보안 리포트 자동 생성
외부 LLM API와 선택적 교차 검증 구조 연계
9. 프로젝트 상태

현재 상태: Local LLM 실행 환경 구축 및 보안 로그 요약 PoC 단계

본 프로젝트는 WinSecAuto V2.1의 RAG 및 Local LLM 확장 검증을 위한 PoC입니다.

<img width="1672" height="941" alt="WinSecAuto V2 1 멀티 LLM 보안 운영 아키텍처_20260623" src="https://github.com/user-attachments/assets/d553f874-d064-4652-b99a-00d477ebd16a" />

