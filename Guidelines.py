import os
import re
from langchain_community.llms import Ollama
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.chains import RetrievalQA

# ==========================================
# 1. 인프라 환경 변수 및 자산 방화벽 정의 (기밀성 보장)
# ==========================================
DATA_DIR = "/root/WinSecAuto-RAG-Ollama-Security-Agent/sample_data"
MERGED_FILE = os.path.join(DATA_DIR, "merged_guidelines.tmp")
HTML_REPORT = os.path.join(DATA_DIR, "staging_scan_report.html")

# 사내 보안 지침 병합 인프라 가동 (무결성 확보)
with open(MERGED_FILE, "w", encoding="utf-8") as outfile:
    for filename in os.listdir(DATA_DIR):
        if filename.startswith("Guidelines_") and filename.endswith(".txt"):
            file_path = os.path.join(DATA_DIR, filename)
            with open(file_path, "r", encoding="utf-8") as infile:
                outfile.write(f"\n{infile.read()}\n")

# 로컬 코어 바인딩 (외부 유출 원천 차단)
main_llm = Ollama(model="llama3")
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

# ==========================================
# 2. [뇌, 손, 발의 통합] 실전형 자동화 오케스트레이터
# ==========================================
def execute_brain_hand_foot_pipeline():
    if not os.path.exists(HTML_REPORT):
        print(f"[❌ 인프라 에러] 점검 리포트가 존재하지 않습니다: {HTML_REPORT}")
        return

    # [손 - Hand의 역할]: 리포트 로드 및 정규식 기반 고위험 자산/CVE 정밀 추출
    with open(HTML_REPORT, "r", encoding="utf-8") as f:
        report_content = f.read()

    # CVE 및 주요 고위험 키워드 자산 추출 (정적 파싱 알고리즘)
    cve_targets = re.findall(r'(CVE-\d+-\d+)', report_content)
    cve_targets = list(set(cve_targets)) # 중복 유효성 노이즈 제거

    print("\n" + "="*80)
    print("🤖 [트랙스로지스코리아 인프라 자산 인식형 SecOps 자동화 보고서]")
    print("="*80)
    print(f"▶ [손 (Hand)] 점검 리포트 파싱 완료: {len(cve_targets)}건의 긴급 취약점 자산 탐지.")

    # [뇌 - Brain의 역할]: 탐지된 CVE에 대해 사내 지침과 대조하여 위험도 판정
    for idx, cve in enumerate(cve_targets, 1):
        print(f"\n🚨 [위험 요인 {idx}] 자산 관련 위협 인텔리전스 탐지: {cve}")
        
        # 뇌의 연산 유도 프롬프트
        query = (
            f"사내 보안 지침(네트워크/개발 보안/계정 관리 지침)을 참조하여, "
            f"현재 스테이징 서버 리포트에서 발견된 고위험 RCE 취약점인 '{cve}'에 대해 "
            f"사내 인프라 방어 관점에서 어떤 규정을 위반했는지 분석하고 조치 근거를 한글로 정형화해서 답변해줘."
        )
        
        # 가용성을 고려한 직렬화 연산 실행
        brain_decision = qa_chain.run(query)
        print("├─ [뇌 (Brain)] 사내 보안 지침 매핑 및 위험도 추론:")
        print(f"│  {brain_decision}")

        # [발 - Foot의 역할]: 판정 결과를 기반으로 즉각적인 리눅스 인프라 대응 가이드 덤프
        print("└─ [발 (Foot)] 인프라 방어 통제령 발령 (Action Item):")
        if "CVE-2021-26855" in cve:
            print("   ⚠️ [즉시 조치] autodiscover 외부 노출 차단: DMZ 인바운드 방화벽 정책 즉시 적용.")
        elif "CVE-2021-22205" in cve or "CVE-2024-23897" in cve:
            print("   ⚠️ [즉시 조치] CI/CD 및 형상관리 자산 격리: 내부망(Private) 접근 제어(VPN/MFA) 강제화.")
        elif "CVE-2022-0543" in cve:
            print("   ⚠️ [즉시 조치] Redis 인-메모리 DB 바인딩 수정: 0.0.0.0 리스닝 포트를 127.0.0.1로 즉시 변경.")
        else:
            print("   ⚠️ [상시 조치] 소프트웨어 최신 패치 배포 및 SAST/SBOM 정기 점검 큐 가동.")
        print("-" * 80)

if __name__ == "__main__":
    execute_brain_hand_foot_pipeline()