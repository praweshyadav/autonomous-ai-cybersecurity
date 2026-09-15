from dataclasses import dataclass
from typing import Any

from rag.embeddings import EmbeddingModel
from rag.index.vector_store import VectorStore
from rag.retriever.retriever import KnowledgeRetriever


@dataclass
class RAGResult:
    """
    One retrieved knowledge result.
    """

    chunk_id: str
    document_id: str
    title: str
    source: str
    content: str
    score: float


class RAGQueryEngine:
    """
    High-level interface for querying the cybersecurity
    knowledge base.

    Flow:

        Query
          ↓
        Embedding Model
          ↓
        Knowledge Retriever
          ↓
        Qdrant Vector Store
          ↓
        RAG Results
    """

    def __init__(
        self,
        collection_name: str = "mitre_attack",
        qdrant_path: str = "rag/index/qdrant",
        embedding_model_name: str = (
            "sentence-transformers/all-MiniLM-L6-v2"
        ),
        vector_size: int = 384,
    ):
        self.embedding_model = EmbeddingModel(
            model_name=embedding_model_name
        )

        self.vector_store = VectorStore(
            path=qdrant_path,
            collection_name=collection_name,
            vector_size=vector_size,
        )

        self.retriever = KnowledgeRetriever(
            vector_store=self.vector_store,
            embedding_model=self.embedding_model,
        )

        self._closed = False

    def query(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[RAGResult]:
        """
        Retrieve the most relevant knowledge for a query.
        """

        if self._closed:
            raise RuntimeError(
                "RAGQueryEngine is already closed."
            )

        if not isinstance(query, str):
            raise TypeError(
                "query must be a string"
            )

        query = query.strip()

        if not query:
            raise ValueError(
                "query cannot be empty"
            )

        if top_k <= 0:
            raise ValueError(
                "top_k must be greater than 0"
            )

        results = self.retriever.retrieve(
            query=query,
            top_k=top_k,
        )

        rag_results = []

        for result in results:
            payload = result["payload"]

            rag_results.append(
                RAGResult(
                    chunk_id=payload["chunk_id"],
                    document_id=payload["document_id"],
                    title=payload["title"],
                    source=payload["source"],
                    content=payload["content"],
                    score=float(result["score"]),
                )
            )

        return rag_results

    def query_dict(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Return retrieval results as dictionaries.
        """

        return [
            {
                "chunk_id": result.chunk_id,
                "document_id": result.document_id,
                "title": result.title,
                "source": result.source,
                "content": result.content,
                "score": result.score,
            }
            for result in self.query(
                query=query,
                top_k=top_k,
            )
        ]

    def close(self) -> None:
        """
        Close the underlying VectorStore and release
        the local Qdrant filesystem lock.

        Calling close() multiple times is safe.
        """

        if self._closed:
            return

        self.vector_store.close()
        self._closed = True

    def __enter__(self):
        """
        Support usage with a context manager.
        """

        if self._closed:
            raise RuntimeError(
                "RAGQueryEngine is already closed."
            )

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        """
        Automatically close the Qdrant client when leaving
        a context manager.
        """

        self.close()

    def __del__(self) -> None:
        """
        Best-effort cleanup if the object is garbage collected.
        """

        try:
            self.close()
        except Exception:
            pass