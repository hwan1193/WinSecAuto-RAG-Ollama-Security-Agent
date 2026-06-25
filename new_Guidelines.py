import os
import re
import sys
from langchain_ollama import OllamaLLM
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.chains import RetrievalQA

# ==========================================
# 1. 인프라 환경 변수 및 자산 방화벽 정의
# ==========================================
DATA_DIR = "/root/WinSecAuto-RAG-Ollama-Security-Agent/sample_data"
MERGED_FILE = os.path.join(DATA_DIR, "merged_guidelines.tmp")
HTML_REPORT = os.path.join(DATA_DIR, "staging_scan_report.html")

try:
    # 사내 보안 지침 병합 인프라 가동
    with open(MERGED_FILE, "w", encoding="utf-8") as outfile:
        for filename in os.listdir(DATA_DIR):
            if filename.startswith("Guidelines_") and filename.endswith(".txt"):
                file_path = os.path.join(DATA_DIR, filename)
                with open(file_path, "r", encoding="utf-8") as infile:
                    outfile.write(f"\n{infile.read()}\n")

    # 최신 규격 OllamaLLM 및 임베딩 바인딩
    main_llm = OllamaLLM(model="llama3")
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    loader = TextLoader(MERGED_FILE, encoding="utf-8")
    documents = loader.load()
    vector_store = FAISS.from_documents(documents, embeddings)

    if os.path.exists(MERGED_FILE):
        os.remove(MERGED_FILE)

    qa_chain = RetrievalQA.from_chain_type(
        llm=main_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever()
    )
except Exception as init_err:
    print(f"[❌ FATAL_INIT_ERROR] 인프라 초기화 실패: {str(init_err)}")
    sys.exit(1)

# ==========================================
# 2. [뇌, 손, 발 + 방어막] 실전형 자동화 오케스트레이터
# ==========================================
def execute_brain_hand_foot_pipeline():
    if not os.path.exists(HTML_REPORT):
        print(f"[❌ INVALID_FILE_PATH] 점검 리포트가 존재하지 않습니다: {HTML_REPORT}")
        return

    # [손 - Hand]: 리포트 로드 및 데이터 정밀 추출
    with open(HTML_REPORT, "r", encoding="utf-8") as f:
        report_content = f.read()

    cve_targets = re.findall(r'(CVE-\d+-\d+)', report_content)
    cve_targets = list(set(cve_targets))

    print("\n" + "="*80)
    print("🤖 [트랙스로지스코리아 인프라 자산 인식형 SecOps 자동화 보고서 - 엔터프라이즈 에디션]")
    print("="*80)
    print(f"▶ [손 (Hand)] 점검 리포트 파싱 완료: {len(cve_targets)}건의 긴급 취약점 자산 탐지.")

    # [뇌 - Brain]: 탐지된 CVE에 대해 사내 지침과 대조하여 위험도 판정
    for idx, cve in enumerate(cve_targets, 1):
        print(f"\n🚨 [위험 요인 {idx}] 자산 관련 위협 인텔리전스 탐지: {cve}")

        # ======================================================================
        # 🔥 [정밀 타격 패치] 고강도 통제형 프롬프트 레이어 결합 (한국어 고정 및 사족 차단)
        # ======================================================================
        query = (
            f"당신은 사내 정보보호 아키텍트입니다. 제공된 사내 보안 지침 규정(Context)만을 근거로 삼아, "
            f"스테이징 서버 리포트에서 발견된 취약점 '{cve}'의 위험성을 정밀 분석하십시오.\n\n"
            f"[⚠️ 엄격한 출력 통제 규칙]\n"
            f"1. 반드시 처음부터 끝까지 완전한 '한국어'로만 작성하십시오. 영어를 혼용하지 마십시오.\n"
            f"2. 답변은 오직 위반한 구체적인 지침 명칭, 위반 원인 분석, 조치 근거만 팩트 기반으로 핵심만 요약하십시오.\n"
            f"3. 본문 뒤에 '(Note: ...)', 'Please note', 'Based on the guidelines...' 같은 LLM 특유의 설명, 부연설명, 주의사항, 사족을 적는 행위를 절대 엄금합니다.\n"
            f"4. 만약 제공된 사내 지침 규정 내용에 '{cve}'나 해당 자산과 관련된 맥락이 전혀 없다면, 다른 규정을 억지로 엮지 말고 반드시 '제공된 사내 보안 지침에 해당 취약점(또는 자산)과 매핑되는 규정이 존재하지 않아 판단을 보류합니다.' 라고만 명확히 단답형으로 답변하십시오."
        )

        # [방어막 패치 완료] 내부 연산 에러 코드 제어
        try:
            raw_response = qa_chain.invoke({"query": query})
            brain_decision = raw_response.get("result", str(raw_response))
        except Exception as chain_err:
            print(f"├─ [❌ CHAIN_EXECUTION_ERROR] LangChain 연산 중 인터럽트 발생.")
            brain_decision = f"ERROR_CODE: INVALID_PROMPT_OR_MODEL_TIMEOUT / 원인: {str(chain_err)}"

        print("├─ [뇌 (Brain)] 사내 보안 지침 매핑 및 위험도 추론:")
        print(f"  {brain_decision}")

        # [발 - Foot]: 판정 결과를 기반으로 즉각적인 리눅스 인프라 대응 가이드 덤프
        print("└─ [발 (Foot)] 인프라 방어 통제령 발령 (Action Item):")
        if "CVE-2021-26855" in cve:
            print("   ⚠️ [즉시 조치] autodiscover 외부 노출 차단: DMZ 인바운드 방화벽 정책 즉시 적용.")
        elif "CVE-2021-22205" in cve or "CVE-2024-23897" in cve:
            print("   ⚠️ [즉시 조치] CI/CD 및 형상관리 자산 격리: 내부망(Private) 접근 제어(VPN/MFA) 강화.")
        elif "CVE-2022-0543" in cve:
            print("   ⚠️ [즉시 조치] Redis 인-메모리 DB 바인딩 수정: 0.0.0.0 리스닝 포트를 127.0.0.1로 즉시 변경.")
        else:
            print("   ⚠️ [상시 조치] 소프트웨어 최신 패치 배포 및 SAST/SBOM 정기 점검 큐 가동.")
        print("-" * 80)

if __name__ == "__main__":
    execute_brain_hand_foot_pipeline()
