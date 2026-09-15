import json
from pathlib import Path

from rag.embeddings import EmbeddingModel
from rag.index.vector_store import VectorStore
from rag.retriever.retriever import KnowledgeRetriever


QUESTIONS_FILE = Path(
    "evaluation/mitre_retrieval_questions.json"
)

QDRANT_PATH = "rag/index/qdrant"
COLLECTION_NAME = "mitre_attack"

K_VALUES = [1, 3, 5, 10]


def load_questions() -> list[dict]:
    if not QUESTIONS_FILE.exists():
        raise FileNotFoundError(
            f"Evaluation file not found: {QUESTIONS_FILE}"
        )

    with QUESTIONS_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        questions = json.load(file)

    if not questions:
        raise ValueError(
            "Evaluation dataset is empty."
        )

    return questions


def extract_technique_id(chunk_id: str) -> str:
    """
    Convert a chunk ID such as:

        T1053.005-chunk-0001

    into:

        T1053.005
    """

    return chunk_id.split("-chunk-")[0]


def deduplicate_techniques(
    results: list[dict],
) -> list[str]:
    """
    Preserve retrieval ranking while removing
    duplicate chunks belonging to the same technique.
    """

    technique_ids = []
    seen = set()

    for result in results:
        chunk_id = result["payload"]["chunk_id"]

        technique_id = extract_technique_id(
            chunk_id
        )

        if technique_id not in seen:
            seen.add(technique_id)
            technique_ids.append(technique_id)

    return technique_ids


def reciprocal_rank(
    retrieved_ids: list[str],
    expected_ids: set[str],
) -> float:

    for rank, technique_id in enumerate(
        retrieved_ids,
        start=1,
    ):
        if technique_id in expected_ids:
            return 1.0 / rank

    return 0.0


def main():

    print("=" * 70)
    print("MITRE ATT&CK RETRIEVAL EVALUATION")
    print("=" * 70)

    # ------------------------------------------------------------
    # 1. Load questions
    # ------------------------------------------------------------

    print("\n[1/4] Loading evaluation questions...")

    questions = load_questions()

    print(
        f"Questions loaded: {len(questions)}"
    )

    # ------------------------------------------------------------
    # 2. Load embedding model
    # ------------------------------------------------------------

    print("\n[2/4] Loading embedding model...")

    embedding_model = EmbeddingModel()

    print(
        f"Embedding model: "
        f"{embedding_model.model_name}"
    )

    # ------------------------------------------------------------
    # 3. Connect to Qdrant
    # ------------------------------------------------------------

    print("\n[3/4] Connecting to Qdrant...")

    vector_store = VectorStore(
        path=QDRANT_PATH,
        collection_name=COLLECTION_NAME,
        vector_size=384,
    )

    retriever = KnowledgeRetriever(
        vector_store=vector_store,
        embedding_model=embedding_model,
    )

    print(
        f"Collection: {COLLECTION_NAME}"
    )

    print(
        f"Vectors: {vector_store.count():,}"
    )

    # ------------------------------------------------------------
    # 4. Evaluate
    # ------------------------------------------------------------

    print("\n[4/4] Evaluating retrieval...\n")

    hits = {
        k: 0
        for k in K_VALUES
    }

    reciprocal_ranks = []

    for index, item in enumerate(
        questions,
        start=1,
    ):

        question = item["question"]

        expected_ids = set(
            item["expected_techniques"]
        )

        # Retrieve enough chunks so that
        # deduplication still gives us up to 10
        # unique techniques.
        results = retriever.retrieve(
            query=question,
            top_k=30,
        )

        retrieved_ids = deduplicate_techniques(
            results
        )

        # --------------------------------------------------------
        # Recall@K
        # --------------------------------------------------------

        for k in K_VALUES:

            top_k_ids = retrieved_ids[:k]

            if expected_ids.intersection(
                top_k_ids
            ):
                hits[k] += 1

        # --------------------------------------------------------
        # MRR
        # --------------------------------------------------------

        rr = reciprocal_rank(
            retrieved_ids,
            expected_ids,
        )

        reciprocal_ranks.append(rr)

        print(
            f"[{index:02d}] {question}"
        )

        print(
            f"     Expected : "
            f"{', '.join(sorted(expected_ids))}"
        )

        print(
            f"     Retrieved: "
            f"{', '.join(retrieved_ids[:10])}"
        )

        print(
            f"     RR       : {rr:.4f}"
        )

        print()

    # ------------------------------------------------------------
    # Final metrics
    # ------------------------------------------------------------

    total = len(questions)

    print("=" * 70)
    print("RESULTS")
    print("=" * 70)

    for k in K_VALUES:

        recall = hits[k] / total

        print(
            f"Recall@{k:<2}: "
            f"{recall:.4f} "
            f"({recall * 100:.2f}%)"
        )

    mrr = (
        sum(reciprocal_ranks)
        / total
    )

    print(
        f"MRR      : "
        f"{mrr:.4f}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()