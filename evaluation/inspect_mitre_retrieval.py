from rag.embeddings import EmbeddingModel
from rag.index.vector_store import VectorStore
from rag.retriever.retriever import KnowledgeRetriever


QUESTIONS = [
    (
        "SAM credential dumping",
        "An attacker dumps credentials from the Windows Security Account Manager.",
    ),
    (
        "Archive collected data",
        "An attacker compresses collected files into an archive before sending them out.",
    ),
    (
        "Remote Desktop Protocol",
        "An attacker uses Remote Desktop Protocol to remotely access a compromised Windows machine.",
    ),
    (
        "Phishing attachment",
        "An attacker uses phishing with a malicious attachment to deliver malware.",
    ),
]


def main():
    print("=" * 70)
    print("MITRE ATT&CK RETRIEVAL FAILURE ANALYSIS")
    print("=" * 70)

    embedding_model = EmbeddingModel()

    vector_store = VectorStore(
        path="rag/index/qdrant",
        collection_name="mitre_attack",
        vector_size=384,
    )

    retriever = KnowledgeRetriever(
        vector_store=vector_store,
        embedding_model=embedding_model,
    )

    for name, question in QUESTIONS:

        print("\n" + "=" * 70)
        print(name)
        print("=" * 70)

        print(f"\nQuestion:\n{question}\n")

        results = retriever.retrieve(
            query=question,
            top_k=10,
        )

        seen = set()
        rank = 0

        for result in results:

            payload = result["payload"]

            chunk_id = payload["chunk_id"]
            technique_id = chunk_id.split("-chunk-")[0]

            if technique_id in seen:
                continue

            seen.add(technique_id)
            rank += 1

            print(
                f"Rank {rank:2d} | "
                f"Score: {result['score']:.4f} | "
                f"Technique: {technique_id}"
            )

            print(
                f"          Title: {payload['title']}"
            )

            print(
                f"          Content: "
                f"{payload['content'][:300].replace(chr(10), ' ')}"
            )

            print()


if __name__ == "__main__":
    main()