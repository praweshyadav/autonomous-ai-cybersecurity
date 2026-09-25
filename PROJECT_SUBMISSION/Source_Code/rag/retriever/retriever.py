from typing import Any

from rag.embeddings import EmbeddingModel
from rag.index.vector_store import VectorStore


class KnowledgeRetriever:
    """
    Performs semantic retrieval over the cybersecurity knowledge base.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        embedding_model: EmbeddingModel,
    ):
        self.vector_store = vector_store
        self.embedding_model = embedding_model

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Retrieve the most relevant knowledge chunks for a query.
        """

        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        if top_k <= 0:
            raise ValueError("top_k must be greater than 0.")

        query_vector = self.embedding_model.encode_one(
            query.strip()
        )

        return self.vector_store.search(
            query_vector=query_vector,
            limit=top_k,
        )