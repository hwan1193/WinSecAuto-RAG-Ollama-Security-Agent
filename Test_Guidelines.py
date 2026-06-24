import os
from langchain_community.llms import Ollama
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.chains import RetrievalQA
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

# ==========================================
# 1. 파일 강제 병합 및 무결성 검증
# ==========================================
DATA_DIR = "/root/WinSecAuto-RAG-Ollama-Security-Agent/sample_data"
MERGED_FILE = "/root/WinSecAuto-RAG-Ollama-Security-Agent/sample_data/merged_guidelines.tmp"

with open(MERGED_FILE, "w", encoding="utf-8") as outfile:
    for filename in os.listdir(DATA_DIR):
        # 기존 샘플 파일 및 신규 추가된 파일 전수 직렬화
        if filename.endswith(".txt") and filename != "merged_guidelines.tmp":
            file_path = os.path.join(DATA_DIR, filename)
            with open(file_path, "r", encoding="utf-8") as infile:
                outfile.write(f"\n{infile.read()}\n")

# ==========================================
# 2. 성능 및 추론 무결성이 검증된 LLaMA3 백엔드 배치
# ==========================================
main_llm = Ollama(model="llama3")
router_llm = Ollama(model="llama3")

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
# 3. LLaMA3 전용 구조화 출력 통제 프롬프트
# ==========================================
router_prompt = PromptTemplate.from_template(
    "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
    "You are a strict routing machine. Respond with EXACTLY one word: 'SECURITY' or 'GENERAL'.\n"
    "Do not provide any explanation, thoughts, or punctuation. Just output the single word.\n"
    "If the question is about security, guidelines, password, policy -> SECURITY\n"
    "If the question is greetings, weather, or general conversation -> GENERAL\n"
    "<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
    "Question: {question}\n"
    "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
)
router_chain = router_prompt | router_llm | StrOutputParser()

# ==========================================
# 4. 정밀 분기 및 연산 컨트롤러
# ==========================================
def route_and_execute(user_question):
    raw_decision = router_chain.invoke({"question": user_question}).strip().upper()

    # gemma의 오동작 패턴(부연설명 문자열 포함)을 완벽 차단하기 위한 정밀 스트링 파싱
    # 첫 단어가 GENERAL로 시작하면 조건 없이 GENERAL로 고정
    if raw_decision.startswith("GENERAL"):
        decision = "GENERAL"
    elif raw_decision.startswith("SECURITY"):
        decision = "SECURITY"
    else:
        decision = "SECURITY" if "SECURITY" in raw_decision else "GENERAL"

    print(f"\n[⚙️ 인프라 라우터 로깅] 분류 결과: {decision} (원문: {raw_decision})")

    if decision == "SECURITY":
        print("[🔒 보안 관제 라인] 중요 보안 지침 탐지 - LLaMA3 메인 RAG 파이프라인 가동.")
        return qa_chain.run(user_question)
    else:
        print("[💬 일반 통신 라인] 단순 질의 탐지 - LLaMA3 인라인 즉시 응답.")
        return router_llm.invoke(user_question)

if __name__ == "__main__":
    q1 = "우리 회사 보안 규정 중 패스워드 변경 주기는 어떻게 돼?"
    res1 = route_and_execute(q1)
    print(f"결과 리포트 1:\n{res1}\n")
    print("-" * 50)

    q2 = "안녕 반가워! 오늘 날씨가 참 좋네."
    res2 = route_and_execute(q2)
    print(f"결과 리포트 2:\n{res2}\n")