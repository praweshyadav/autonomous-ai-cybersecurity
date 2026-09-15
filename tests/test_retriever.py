import numpy as np

from rag.documents.chunker import DocumentChunk
from rag.index.vector_store import VectorStore
from rag.retriever.retriever import KnowledgeRetriever


class FakeEmbeddingModel:
    """
    Deterministic embedding model for testing retrieval logic.
    """

    def encode_one(self, text: str):
        if "brute force" in text.lower():
            return np.array(
                [1.0, 0.0, 0.0],
                dtype=np.float32,
            )

        return np.array(
            [0.0, 1.0, 0.0],
            dtype=np.float32,
        )


def test_retriever_returns_relevant_chunks(tmp_path):
    store = VectorStore(
        path=str(tmp_path / "qdrant"),
        collection_name="retriever_test",
        vector_size=3,
    )

    chunks = [
        DocumentChunk(
            chunk_id="brute-001",
            document_id="brute",
            title="Brute Force",
            source="brute.md",
            content="Brute force attacks repeatedly attempt authentication.",
        ),
        DocumentChunk(
            chunk_id="dos-001",
            document_id="dos",
            title="DoS",
            source="dos.md",
            content="Denial of service attacks overwhelm a target.",
        ),
    ]

    embeddings = np.array(
        [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
        ],
        dtype=np.float32,
    )

    store.add_chunks(
        chunks,
        embeddings,
    )

    retriever = KnowledgeRetriever(
        vector_store=store,
        embedding_model=FakeEmbeddingModel(),
    )

    results = retriever.retrieve(
        "How does a brute force attack work?",
        top_k=1,
    )

    assert len(results) == 1

    assert (
        results[0]["payload"]["chunk_id"]
        == "brute-001"
    )


def test_retriever_rejects_empty_query(tmp_path):
    store = VectorStore(
        path=str(tmp_path / "qdrant"),
        collection_name="retriever_test",
        vector_size=3,
    )

    retriever = KnowledgeRetriever(
        vector_store=store,
        embedding_model=FakeEmbeddingModel(),
    )

    try:
        retriever.retrieve("")
        assert False
    except ValueError:
        pass